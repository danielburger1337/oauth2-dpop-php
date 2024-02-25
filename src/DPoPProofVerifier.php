<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP;

use Base64Url\Base64Url;
use danielburger1337\OAuth2DPoP\Exception\DPoPReplayAttackException;
use danielburger1337\OAuth2DPoP\Exception\InvalidDPoPNonceException;
use danielburger1337\OAuth2DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2DPoP\JwtHandler\JwtHandlerInterface;
use danielburger1337\OAuth2DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2DPoP\Model\ParsedDPoPProofModel;
use danielburger1337\OAuth2DPoP\NonceStorage\NonceStorageInterface;
use danielburger1337\OAuth2DPoP\ReplayAttack\ReplayAttackDetectorInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Request;

class DPoPProofVerifier
{
    /**
     * @param JwtHandlerInterface                $jwtHandler           The JSON Web Token handler.
     * @param NonceStorageInterface|null         $nonceStorage         [optional] The "nonce" claim storage.
     *                                                                 Pass `null` will disable the nonce requirement.
     * @param ReplayAttackDetectorInterface|null $replayAttackDetector [optional] A service that can detect whether the DPoP proof was already used.
     *                                                                 Pass `null` will disables replay attack detection.
     */
    public function __construct(
        private readonly ClockInterface $clock,
        private readonly JwtHandlerInterface $jwtHandler,
        private readonly NonceStorageInterface|null $nonceStorage = null,
        private readonly ReplayAttackDetectorInterface|null $replayAttackDetector = null,
        private readonly int $allowedTimeDrift = 5
    ) {
    }

    public function verifyFromRequest(ServerRequestInterface|Request $request, AccessTokenModel|null $accessToken = null): ParsedDPoPProofModel
    {
        if ($request instanceof Request) {
            /** @var string[] */
            $headers = $request->headers->all('dpop');
            $htu = $request->getSchemeAndHttpHost().$request->getBaseUrl().$request->getPathInfo();
        } else {
            $headers = $request->getHeaders()['dpop'] ?? [];
            $htu = $request->getUri()->withQuery('')->withFragment('')->__toString();
        }

        if (\count($headers) !== 1) {
            throw new InvalidDPoPProofException('The request must contain exactly one "DPoP" header.');
        }

        return $this->verifyFromRequestParts($headers[\array_key_first($headers)], $request->getMethod(), $htu, $accessToken);
    }

    /**
     * Verify a DPoP proof.
     *
     * @param string $dpopProof The "DPoP" header value.
     * @param string $htm       The expected "htm" claim.
     * @param string $htu       The expected "htu" claim.
     *
     * @throws InvalidDPoPProofException If the DPoP proof is invalid.
     * @throws InvalidDPoPNonceException If the DPoP nonce is invalid.
     * @throws \InvalidArgumentException If access token is not of type "DPoP"
     */
    public function verifyFromRequestParts(string $dpopProof, string $htm, string $htu, AccessTokenModel|null $accessToken = null): ParsedDPoPProofModel
    {
        $dpopProof = \trim($dpopProof);
        if ('' === $dpopProof) {
            throw new InvalidDPoPProofException('The DPoP proof must be a non empty string.');
        }

        $proof = $this->jwtHandler->parseProof($dpopProof);

        if (
            !\array_key_exists('typ', $proof->protectedHeader)
            || !\is_string($proof->protectedHeader['typ'])
            || $proof->protectedHeader['typ'] !== JwtHandlerInterface::TYPE_HEADER_PARAMETER
        ) {
            throw new InvalidDPoPProofException('The DPoP proof "typ" header parameter is invalid.');
        }

        $now = $this->clock->now()->getTimestamp();

        if (!\array_key_exists('iat', $proof->payload) || !\is_int($proof->payload['iat'])) {
            throw new InvalidDPoPProofException('The DPoP proof "iat" claim is invalid.');
        }
        if ($now < $proof->payload['iat'] - $this->allowedTimeDrift) {
            throw new InvalidDPoPProofException('The DPoP proof was issued in the future.');
        }

        if (\array_key_exists('exp', $proof->payload)) {
            if (!\is_int($proof->payload['exp'])) {
                throw new InvalidDPoPProofException('The DPoP proof "exp" claim is invalid.');
            }

            if ($now > $proof->payload['exp'] + $this->allowedTimeDrift) {
                throw new InvalidDPoPProofException('The DPoP proof has expired.');
            }
        }

        if (\array_key_exists('nbf', $proof->payload)) {
            if (!\is_int($proof->payload['nbf'])) {
                throw new InvalidDPoPProofException('The DPoP proof "nbf" claim is invalid.');
            }

            if ($now < $proof->payload['nbf'] - $this->allowedTimeDrift) {
                throw new InvalidDPoPProofException('The DPoP proof is not valid valid.');
            }
        }

        if (null !== $accessToken) {
            if ($proof->jwkThumbprint !== $accessToken->jkt) {
                throw new InvalidDPoPProofException('The DPoP proof was signed by a different JWK than was used to issue the access token.');
            }

            if (!\array_key_exists('ath', $proof->payload) || !\is_string($proof->payload['ath'])) {
                throw new InvalidDPoPProofException('The DPoP proof is missing the required "ath" claim.');
            }

            // TODO Base64Url::encode(hash(...))
            if (!\hash_equals(\hash('sha256', (string) $accessToken->accessToken), $proof->payload['ath'])) {
                throw new InvalidDPoPProofException('The DPoP proof "ath" claim is invalid.');
            }
        }

        if (!\array_key_exists('htu', $proof->payload) || !\is_string($proof->payload['htu'])) {
            throw new InvalidDPoPProofException('The DPoP proof is missing the required "htu" claim.');
        }
        if (!\hash_equals(\strtolower($htu), \strtolower($proof->payload['htu']))) {
            throw new InvalidDPoPProofException('The DPoP proof "htu" claim is invalid.');
        }

        if (!\array_key_exists('htm', $proof->payload) || !\is_string($proof->payload['htm'])) {
            throw new InvalidDPoPProofException('The DPoP proof is missing the required "htm" claim.');
        }
        if (!\hash_equals(\strtolower($htm), \strtolower($proof->payload['htm']))) {
            throw new InvalidDPoPProofException('The DPoP proof "htm" claim is invalid.');
        }

        if (null !== $this->nonceStorage) {
            if (!\array_key_exists('nonce', $proof->payload)) {
                $nonce = $this->nonceStorage->getCurrentNonce($proof->jwkThumbprint);
                $nonce ??= $this->nonceStorage->createNewNonce($proof->jwkThumbprint);

                throw new InvalidDPoPNonceException($nonce, 'The DPoP proof is missing the required "nonce" claim.');
            }

            if (!\is_string($proof->payload['nonce']) || !$this->nonceStorage->isNonceValid($proof->jwkThumbprint, $proof->payload['nonce'])) {
                $nonce = $this->nonceStorage->createNewNonce($proof->jwkThumbprint);

                throw new InvalidDPoPNonceException($nonce, 'The DPoP proof "nonce" claim is invalid.');
            }
        }

        if (!\array_key_exists('jti', $proof->payload) || !\is_string($proof->payload['jti'])) {
            throw new InvalidDPoPProofException('The DPoP proof is missing the required "jti" claim.');
        }
        $jtiLen = \strlen($proof->payload['jti']);
        if ($jtiLen < 16 || $jtiLen > 4096) {
            throw new InvalidDPoPProofException('The DPoP proof is "jti" claim does not match the required format.');
        }

        if (null !== $this->replayAttackDetector) {
            $key = \hash('xxh128', $proof->jwkThumbprint.$proof->payload['jti']);

            if ($this->replayAttackDetector->isReplay($key)) {
                throw new DPoPReplayAttackException();
            }

            $this->replayAttackDetector->storeUsage($key);
        }

        return $proof;
    }

    /**
     * Create the WWW-Authenticate header that include the resource servers supported DPoP JWAs.
     */
    public function createWwwAuthenticateChallengeLine(): string
    {
        return \sprintf('DPoP algs="%s"', \implode(' ', $this->jwtHandler->getSupportedAlgorithms()));
    }
}
