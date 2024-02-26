<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Loader;

use danielburger1337\OAuth2DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2DPoP\Model\DecodedDPoPProof;
use Jose\Component\Checker;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class WebTokenFrameworkTokenLoader implements DPoPTokenLoaderInterface
{
    private readonly JWSSerializerManager $serializer;

    /**
     * @param AlgorithmManager $algorithmManager An algorithm manager that contains all the JWA algorithms that are supported.
     */
    public function __construct(
        private readonly AlgorithmManager $algorithmManager
    ) {
        $this->serializer = new JWSSerializerManager([new CompactSerializer()]);
    }

    public function loadProof(string $proof): DecodedDPoPProof
    {
        try {
            $jws = $this->serializer->unserialize($proof);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidDPoPProofException('The presented DPoP proof is not in a supported JWT format.', previous: $e);
        }

        try {
            // @phpstan-ignore-next-line
            $jwk = new JWK($jws->getSignature(0)->getProtectedHeaderParameter('jwk'));
        } catch (\Throwable $e) {
            throw new InvalidDPoPProofException('Failed to get "jwk" from DPoP proof header.', previous: $e);
        }

        if ($jwk->toPublic()->jsonSerialize() !== $jwk->jsonSerialize()) {
            throw new InvalidDPoPProofException('DPoP proof must not contain a private key in the "jwk" header parameter.');
        }

        $headerCheckerManager = new Checker\HeaderCheckerManager([
            new Checker\AlgorithmChecker($this->algorithmManager->list(), true),
        ], [
            new JWSTokenSupport(),
        ]);

        $jwsLoader = new JWSLoader($this->serializer, new JWSVerifier($this->algorithmManager), $headerCheckerManager);

        try {
            $jws = $jwsLoader->loadAndVerifyWithKey($proof, $jwk, $signatureIndex);
            if (null === $signatureIndex) {
                throw new \Exception('Failed to get signature index from DPoP proof.');
            }

            $signature = $jws->getSignature($signatureIndex);

            $algorithmName = $signature->getProtectedHeaderParameter('alg');
            if (!\is_string($algorithmName)) {
                throw new InvalidHeaderException('Invalid algorithm', 'alg', $algorithmName);
            }

            $algorithm = $this->algorithmManager->get($algorithmName);
        } catch (\Exception $e) {
            if ($e instanceof InvalidHeaderException && $e->getHeader()) {
                throw new InvalidDPoPProofException("The DPoP proof \"{$e->getHeader()}\" header parameter is invalid.", previous: $e);
            }

            if ($e instanceof MissingMandatoryHeaderParameterException) {
                throw new InvalidDPoPProofException('The DPoP proof is missing the following mandatory header parameters: '.\implode(', ', $e->getParameters()), previous: $e);
            }

            throw new InvalidDPoPProofException('The DPoP proof either has an invalid signature or uses an unsupported algorithm.', previous: $e);
        }

        // @see https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-16.html#section-4.2
        if ($algorithm instanceof MacAlgorithm) {
            throw new InvalidDPoPProofException('The DPoP proof must not use a symmetric signature algorithm (MAC).');
        }
        if ($algorithm instanceof None) {
            throw new InvalidDPoPProofException('The DPoP proof must not use the "none" signature algorithm.');
        }

        try {
            $unverifiedClaims = JsonConverter::decode($jws->getPayload() ?? '');
            if (!\is_array($unverifiedClaims)) {
                throw new \Exception('DPoP proof payload could not be decoded to an array.');
            }
        } catch (\Exception $e) {
            throw new InvalidDPoPProofException('The DPoP proof has an invalid payload.', previous: $e);
        }

        return new DecodedDPoPProof($jwk->thumbprint('sha256'), $unverifiedClaims, $signature->getProtectedHeader());
    }

    public function getSupportedAlgorithms(): array
    {
        return $this->algorithmManager->list();
    }
}
