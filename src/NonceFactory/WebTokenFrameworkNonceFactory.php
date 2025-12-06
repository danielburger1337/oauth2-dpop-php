<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\NonceFactory;

use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPJwkException;
use Jose\Component\Checker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Psr\Clock\ClockInterface;

class WebTokenFrameworkNonceFactory implements NonceFactoryInterface
{
    final public const string TYPE_PARAMETER = 'dpop+nonce';

    private readonly AlgorithmManager $algorithmManager;
    private readonly JWKSet $jwkSet;

    private readonly JWSBuilder $jwsBuilder;
    private readonly JWSSerializerManager $serializer;

    /**
     * @param Algorithm|AlgorithmManager                                                    $algorithm        JWA that is used to sign the DPoP-Nonce token.
     * @param JWK|JWKSet                                                                    $jwk              JWK that is used to sign the DPoP-Nonce token.
     * @param ClockInterface                                                                $clock            PSR20 clock to use.
     * @param \DateInterval                                                                 $ttl              [optional] How long a DPoP-Nonce token is valid.
     * @param int                                                                           $allowedTimeDrift [optional] Allowed time skew offset in seconds.
     * @param \Closure(array<string, int>, string, WebTokenFrameworkNonceFactory):void|null $closure          [optional] Callable that will be invoked when a valid DPoP-Nonce token was loaded.
     *                                                                                                        This callable may be used to send the client a new DPoP-Nonce.
     */
    public function __construct(
        AlgorithmManager|Algorithm $algorithm,
        JWK|JWKSet $jwk,
        private readonly ClockInterface $clock,
        private readonly \DateInterval $ttl = new \DateInterval('PT15M'),
        private readonly int $allowedTimeDrift = 5,
        private readonly ?\Closure $closure = null,
    ) {
        if ($algorithm instanceof Algorithm) {
            $algorithm = new AlgorithmManager([$algorithm]);
        }
        $this->algorithmManager = $algorithm;

        if ($jwk instanceof JWK) {
            $jwk = new JWKSet([$jwk]);
        }
        $this->jwkSet = $jwk;

        $this->serializer = new JWSSerializerManager([new CompactSerializer()]);
        $this->jwsBuilder = new JWSBuilder($this->algorithmManager);
    }

    public function createNewNonce(string $thumbprint): string
    {
        $now = $this->clock->now();

        $payload = [
            'iat' => $now->getTimestamp(),
            'exp' => $now->add($this->ttl)->getTimestamp(),
            // Some signatures are deterministic (always produce the same signature for the same input)
            // Add a little bit of randomness to prevent multiple nonces to be equal when they were created
            // at the same time.
            'jti' => \bin2hex(\random_bytes(4)),
            'jkt' => $thumbprint,
        ];

        $jwk = null;
        $algorithm = null;
        foreach ($this->algorithmManager->all() as $algorithm) {
            if (null !== ($jwk = $this->jwkSet->selectKey('sig', $algorithm))) {
                break;
            }
        }

        if (null === $jwk || null === $algorithm) {
            throw new MissingDPoPJwkException('Failed to find a suitable JWK/JWA to sign a DPoP-Nonce token.');
        }

        $protectedHeader = [
            'typ' => self::TYPE_PARAMETER,
            'alg' => $algorithm->name(),
        ];

        if ($jwk->has('kid')) {
            $protectedHeader['kid'] = $jwk->get('kid');
        }
        if ($jwk->has('crv')) {
            $protectedHeader['crv'] = $jwk->get('crv');
        }

        $builder = $this->jwsBuilder->create()
            ->withPayload(JsonConverter::encode($payload))
            ->addSignature($jwk, $protectedHeader)
        ;

        return $this->serializer->serialize(CompactSerializer::NAME, $builder->build());
    }

    public function createNewNonceIfInvalid(string $thumbprint, string $nonce): ?string
    {
        $headerCheckerManager = new Checker\HeaderCheckerManager([
            new Checker\IsEqualChecker('typ', self::TYPE_PARAMETER),
            new Checker\AlgorithmChecker($this->algorithmManager->list(), true),
        ], [
            new JWSTokenSupport(),
        ]);

        $jwsLoader = new JWSLoader($this->serializer, new JWSVerifier($this->algorithmManager), $headerCheckerManager);

        try {
            $jws = $jwsLoader->loadAndVerifyWithKeySet($nonce, $this->jwkSet, $signatureIndex);

            if (!\is_int($signatureIndex) || !$jws->getSignature($signatureIndex)->hasProtectedHeaderParameter('typ')) {
                throw new \Exception();
            }

            $claimCheckerManager = new ClaimCheckerManager([
                new Checker\ExpirationTimeChecker($this->allowedTimeDrift, false, $this->clock),
                new Checker\IssuedAtChecker($this->allowedTimeDrift, false, $this->clock),
                new Checker\IsEqualChecker('jkt', $thumbprint),
            ]);

            $payload = JsonConverter::decode($jws->getPayload() ?? '');
            if (!\is_array($payload)) {
                throw new \Exception();
            }

            $verifiedClaims = $claimCheckerManager->check($payload, ['iat', 'exp']);
        } catch (\Exception) {
            return $this->createNewNonce($thumbprint);
        }

        if (null !== $this->closure) {
            // @see https://datatracker.ietf.org/doc/html/rfc9449#section-8.2
            \call_user_func($this->closure, $verifiedClaims, $thumbprint, $this);
        }

        return null;
    }
}
