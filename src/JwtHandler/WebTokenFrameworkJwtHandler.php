<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\JwtHandler;

use danielburger1337\OAuth2DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2DPoP\Model\ParsedDPoPProofModel;
use Jose\Component\Checker;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Psr\Clock\ClockInterface;

class WebTokenFrameworkJwtHandler implements JwtHandlerInterface
{
    private readonly JWSBuilder $jwsBuilder;
    private readonly JWSSerializerManager $serializer;

    public function __construct(
        private readonly JWKSet $jwkSet,
        private readonly ClockInterface $clock,
        private readonly AlgorithmManager $algorithmManager,
        private readonly int $allowedTimeDrift = 5
    ) {
        $this->jwsBuilder = new JWSBuilder($this->algorithmManager);
        $this->serializer = new JWSSerializerManager([new CompactSerializer()]);
    }

    public function parseProof(string $proof): ParsedDPoPProofModel
    {
        try {
            $jws = $this->serializer->unserialize($proof);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidDPoPProofException('Failed to parse DPoP proof.', previous: $e);
        }

        try {
            // @phpstan-ignore-next-line
            $jwk = new JWK($jws->getSignature(0)->getProtectedHeaderParameter('jwk'));
        } catch (\Throwable $e) {
            throw new InvalidDPoPProofException('Failed to get "jwk" from DPoP proof header.', previous: $e);
        }

        if ($jwk->toPublic()->jsonSerialize() !== $jwk->jsonSerialize()) {
            throw new InvalidDPoPProofException('DPoP-Proof may not contain a private key in the "jwk" header parameter.');
        }

        $headerCheckerManager = new Checker\HeaderCheckerManager([
            new Checker\IsEqualChecker('typ', self::TYPE_HEADER_PARAMETER),
            new Checker\AlgorithmChecker($this->algorithmManager->list(), true),
        ], [
            new JWSTokenSupport(),
        ]);

        $jwsLoader = new JWSLoader($this->serializer, new JWSVerifier($this->algorithmManager), $headerCheckerManager);

        try {
            $jws = $jwsLoader->loadAndVerifyWithKey($proof, $jwk, $signatureIndex);
            if (null === $signatureIndex) {
                throw new \Exception('');
            }

            $signature = $jws->getSignature($signatureIndex);

            if (!$signature->hasProtectedHeaderParameter('typ')) {
                throw new MissingMandatoryHeaderParameterException('The "typ" header parameter is missing.', ['typ']);
            }

            $algorithmName = $signature->getProtectedHeaderParameter('alg');
            if (!\is_string($algorithmName) || !$this->algorithmManager->has($algorithmName)) {
                throw new InvalidHeaderException('Invalid algorithm', 'alg', $algorithmName);
            }

            $algorithm = $this->algorithmManager->get($algorithmName);
            // @see https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-16.html#section-4.2
            if ($algorithm instanceof MacAlgorithm || $algorithm instanceof None) {
                throw new InvalidHeaderException('MUST NOT be none or an identifier for a symmetric algorithm (MAC)', 'alg', $algorithmName);
            }
        } catch (\Exception $e) {
            if ($e instanceof InvalidHeaderException) {
                $header = \htmlspecialchars($e->getHeader());

                throw new InvalidDPoPProofException("The DPoP proof \"{$header}\" header parameter is invalid.", previous: $e);
            }

            if ($e instanceof MissingMandatoryHeaderParameterException) {
                $list = \array_map(static fn (string $param): string => \htmlspecialchars($param), $e->getParameters());

                throw new InvalidDPoPProofException('The DPoP proof is missing the following mandatory header parameters: '.\implode(', ', $list), previous: $e);
            }

            throw new InvalidDPoPProofException('The DPoP proof has an invalid signature.', previous: $e);
        }

        try {
            $unverifiedClaims = JsonConverter::decode($jws->getPayload() ?? '');
            if (!\is_array($unverifiedClaims)) {
                throw new \Exception();
            }
        } catch (\Exception $e) {
            throw new InvalidDPoPProofException('The DPoP proof has an invalid payload.');
        }

        return new ParsedDPoPProofModel($jwk->thumbprint('sha256'), $unverifiedClaims);
    }

    public function selectJWK(?array $serverSupportedSignatureAlgorithms = null): JwkInterface
    {
        $serverSupportedSignatureAlgorithms ??= $this->algorithmManager->list();

        foreach ($serverSupportedSignatureAlgorithms as $algorithmName) {
            if (!$this->algorithmManager->has($algorithmName)) {
                continue;
            }

            $algorithm = $this->algorithmManager->get($algorithmName);

            if (null !== ($jwk = $this->jwkSet->selectKey('sig', $algorithm))) {
                return new WebTokenFrameworkJwk($jwk, $algorithm);
            }
        }

        throw new MissingDPoPJwkException();
    }

    public function createProof(JwkInterface $jwk, array $payload, array $protectedHeader): string
    {
        if (!$jwk instanceof WebTokenFrameworkJwk) {
            throw new \InvalidArgumentException(\sprintf('$jwk must be an instance of "%s", "%s" given.', WebTokenFrameworkJwk::class, \get_debug_type($jwk)));
        }

        $protectedHeader['alg'] = $jwk->algorithm->name();

        if ($jwk->jwk->has('kid')) {
            $protectedHeader['kid'] = $jwk->jwk->get('kid');
        }
        if ($jwk->jwk->has('crv')) {
            $protectedHeader['crv'] = $jwk->jwk->get('crv');
        }

        $builder = $this->jwsBuilder->create()
            ->withPayload(JsonConverter::encode($payload))
            ->addSignature($jwk->jwk, $protectedHeader)
        ;

        return $this->serializer->serialize(CompactSerializer::NAME, $builder->build());
    }
}
