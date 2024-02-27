<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP;

use danielburger1337\OAuth2DPoP\Exception\DPoPReplayAttackException;
use danielburger1337\OAuth2DPoP\Exception\InvalidDPoPNonceException;
use danielburger1337\OAuth2DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2DPoP\JwtHandler\JwtHandlerInterface;
use danielburger1337\OAuth2DPoP\Loader\DPoPTokenLoaderInterface;
use danielburger1337\OAuth2DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2DPoP\Model\DecodedDPoPProof;
use danielburger1337\OAuth2DPoP\NonceStorage\NonceVerificationStorageInterface;
use danielburger1337\OAuth2DPoP\ReplayAttack\ReplayAttackDetectorInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Symfony\Component\HttpFoundation\Request;

class DPoPProofVerifier
{
    /**
     * @param ClockInterface                         $clock                The PSR-20 clock to use.
     * @param DPoPTokenLoaderInterface               $tokenLoader          The DPoP token loader to use.
     * @param NonceVerificationStorageInterface|null $nonceStorage         [optional] The "nonce" claim storage.
     *                                                                     `null` will disable the nonce requirement.
     * @param ReplayAttackDetectorInterface|null     $replayAttackDetector [optional] A service that can detect whether the DPoP proof was already used.
     *                                                                     `null` will disable replay attack detection.
     * @param int                                    $allowedTimeDrift     [optional] Allowed time drift in seconds.
     */
    public function __construct(
        private readonly ClockInterface $clock,
        private readonly DPoPTokenLoaderInterface $tokenLoader,
        private readonly NonceVerificationStorageInterface|null $nonceStorage = null,
        private readonly ReplayAttackDetectorInterface|null $replayAttackDetector = null,
        private readonly int $allowedTimeDrift = 5
    ) {
    }

    /**
     * Verify a DPoP proof from a request.
     *
     * @param ServerRequestInterface|Request $request     The PSR-7/Http-Foundation request to verify.
     * @param AccessTokenModel|null          $accessToken [optional] The access token the DPoP proof must be bound to.
     *
     * @throws InvalidDPoPProofException If the DPoP proof is invalid.
     * @throws InvalidDPoPNonceException If the DPoP nonce is invalid.
     * @throws DPoPReplayAttackException If the DPoP proof has already been used.
     */
    public function verifyFromRequest(ServerRequestInterface|Request $request, AccessTokenModel|null $accessToken = null): DecodedDPoPProof
    {
        if ($request instanceof Request) {
            /** @var string[] */
            $headers = $request->headers->all('dpop');
        } else {
            $headers = $request->getHeader('dpop');
        }

        if (\count($headers) !== 1) {
            throw new InvalidDPoPProofException('The request must contain exactly one "DPoP" header.');
        }

        return $this->verifyFromRequestParts($headers[\array_key_first($headers)], $request->getMethod(), $request->getUri(), $accessToken);
    }

    /**
     * Verify a DPoP proof.
     *
     * @param string                $dpopProof   The "DPoP" header value.
     * @param string                $htm         The expected http method of the request.
     * @param UriInterface|string   $htu         The expected http URI of the request.
     * @param AccessTokenModel|null $accessToken [optional] The access token the DPoP proof must be bound to.
     *
     * @throws InvalidDPoPProofException If the DPoP proof is invalid.
     * @throws InvalidDPoPNonceException If the DPoP nonce is invalid.
     * @throws DPoPReplayAttackException If the DPoP proof has already been used.
     */
    public function verifyFromRequestParts(string $dpopProof, string $htm, UriInterface|string $htu, AccessTokenModel|null $accessToken = null): DecodedDPoPProof
    {
        $dpopProof = \trim($dpopProof);
        if ('' === $dpopProof) {
            throw new InvalidDPoPProofException('The DPoP proof must be a non empty string.');
        }

        $proof = $this->tokenLoader->loadProof($dpopProof);

        if (!\array_key_exists('htm', $proof->payload) || !\is_string($proof->payload['htm'])) {
            throw new InvalidDPoPProofException('The DPoP proof is missing the required "htm" claim.');
        }
        if (!\hash_equals(\strtolower($htm), \strtolower($proof->payload['htm']))) {
            throw new InvalidDPoPProofException('The DPoP proof "htm" claim is invalid.');
        }

        if (!\array_key_exists('htu', $proof->payload) || !\is_string($proof->payload['htu'])) {
            throw new InvalidDPoPProofException('The DPoP proof is missing the required "htu" claim.');
        }
        if (!\hash_equals(\strtolower(Util::createHtu($htu)), \strtolower($proof->payload['htu']))) {
            throw new InvalidDPoPProofException('The DPoP proof "htu" claim is invalid.');
        }

        if (
            !\array_key_exists('typ', $proof->protectedHeader)
            || $proof->protectedHeader['typ'] !== JwtHandlerInterface::TYPE_HEADER_PARAMETER
        ) {
            throw new InvalidDPoPProofException('The DPoP proof "typ" header parameter is invalid.');
        }

        if (!\array_key_exists('jti', $proof->payload) || !\is_string($proof->payload['jti'])) {
            throw new InvalidDPoPProofException('The DPoP proof is missing the required "jti" claim.');
        }
        $jtiLen = \strlen($proof->payload['jti']);
        if ($jtiLen < 16 || $jtiLen > 4096) {
            throw new InvalidDPoPProofException('The DPoP proof is "jti" claim does not match the required format.');
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
                throw new InvalidDPoPProofException('The DPoP proof is not yet valid.');
            }
        }

        if (
            !\is_array($proof->protectedHeader['jwk'] ?? null) // this SHOULD be impossible
            || 0 !== \count(\array_intersect_key($proof->protectedHeader['jwk'], \array_flip(['p', 'd', 'q', 'dp', 'dq', 'qi'])))
        ) {
            throw new InvalidDPoPProofException('DPoP proof must not contain a private key in the "jwk" header parameter.');
        }

        if (null !== $accessToken) {
            if (!\array_key_exists('ath', $proof->payload) || !\is_string($proof->payload['ath'])) {
                throw new InvalidDPoPProofException('The DPoP proof is missing the required "ath" claim.');
            }

            if ($proof->jwk->thumbprint() !== $accessToken->jkt) {
                throw new InvalidDPoPProofException('The DPoP proof was signed by a different JWK than was used to issue the access token.');
            }

            if (!\hash_equals(Util::createAccessTokenHash($accessToken), $proof->payload['ath'])) {
                throw new InvalidDPoPProofException('The DPoP proof "ath" claim is invalid.');
            }
        }

        if (null !== $this->nonceStorage) {
            $thumbprint = $proof->jwk->thumbprint();

            if (!\array_key_exists('nonce', $proof->payload) || !\is_string($proof->payload['nonce'])) {
                $nonce = $this->nonceStorage->getCurrentOrCreateNewNonce($thumbprint);

                throw new InvalidDPoPNonceException($nonce, 'The DPoP proof is missing the required "nonce" claim.');
            }

            $nonce = $this->nonceStorage->createNewNonceIfInvalid($thumbprint, $proof->payload['nonce']);
            if (null !== $nonce) {
                throw new InvalidDPoPNonceException($nonce, 'The DPoP proof "nonce" claim is invalid.');
            }
        }

        if (false === $this->replayAttackDetector?->consumeProof($proof)) {
            throw new DPoPReplayAttackException($proof);
        }

        return $proof;
    }

    /**
     * Create the WWW-Authenticate header that include the resource servers supported DPoP JWAs.
     */
    public function createWwwAuthenticateChallengeLine(): string
    {
        return \sprintf('DPoP algs="%s"', \implode(' ', $this->tokenLoader->getSupportedAlgorithms()));
    }
}
