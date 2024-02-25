<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

use danielburger1337\OAuth2DPoP\Exception\MissingDPoPJwkException;
use Jose\Component\Checker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Psr\Clock\ClockInterface;

class WebTokenFrameworkNonceStorage implements NonceStorageInterface
{
    final public const TYPE_PARAMETER = 'dpop+nonce';

    private readonly AlgorithmManager $algorithmManager;
    private readonly JWSBuilder $jwsBuilder;
    private readonly JWSSerializerManager $serializer;
    private readonly \DateInterval $ttl;

    public function __construct(
        private readonly Algorithm $algorithm,
        private readonly JWKSet $jwkSet,
        private readonly ClockInterface $clock,
        \DateInterval|string $ttl = new \DateInterval('PT15M'),
        private readonly int $allowedTimeDrift = 5,
        private readonly \Closure|null $closure = null
    ) {
        if ($this->algorithm instanceof None) {
            throw new \InvalidArgumentException('This DPoP nonce storage does not allow the "none" JWA.');
        }

        if (\is_string($ttl)) {
            $this->ttl = new \DateInterval($ttl);
        } else {
            $this->ttl = $ttl;
        }

        $this->algorithmManager = new AlgorithmManager([$this->algorithm]);
        $this->serializer = new JWSSerializerManager([new CompactSerializer()]);
        $this->jwsBuilder = new JWSBuilder($this->algorithmManager);
    }

    public function isNonceValid(string $key, string $nonce): bool
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
        } catch (\Throwable) {
            return false;
        }

        if (!\is_int($signatureIndex) || !$jws->getSignature($signatureIndex)->hasProtectedHeaderParameter('typ')) {
            return false;
        }

        $claimCheckerManager = new ClaimCheckerManager([
            new Checker\ExpirationTimeChecker($this->allowedTimeDrift, false, $this->clock),
            new Checker\IssuedAtChecker($this->allowedTimeDrift, false, $this->clock),
        ]);

        $payload = $jws->getPayload();
        if (null === $payload) {
            return false;
        }

        $payload = JsonConverter::decode($payload);
        if (!\is_array($payload)) {
            return false;
        }

        try {
            $verifiedClaims = $claimCheckerManager->check($payload, ['iat', 'exp']);
        } catch (\Throwable) {
            return false;
        }

        if (null !== $this->closure) {
            \call_user_func($this->closure, $verifiedClaims, $key, $this);
        }

        return true;
    }

    public function createNewNonce(string $key): string
    {
        $now = $this->clock->now();

        $payload = [
            'iat' => $now->getTimestamp(),
            'exp' => $now->add($this->ttl)->getTimestamp(),
            'jti' => \bin2hex(\random_bytes(4)),
        ];

        $protectedHeader = [
            'typ' => self::TYPE_PARAMETER,
            'alg' => $this->algorithm->name(),
        ];

        $jwk = $this->jwkSet->selectKey('sig', $this->algorithm);
        if (null === $jwk) {
            throw new MissingDPoPJwkException();
        }

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

    public function storeNextNonce(string $key, string $nonce): void
    {
        // noop
    }

    public function getCurrentNonce(string $key): ?string
    {
        return $this->createNewNonce($key);
    }
}
