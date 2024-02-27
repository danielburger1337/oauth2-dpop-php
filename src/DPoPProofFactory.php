<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP;

use danielburger1337\OAuth2DPoP\Encoder\DPoPTokenEncoderInterface;
use danielburger1337\OAuth2DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2DPoP\Model\DPoPProof;
use danielburger1337\OAuth2DPoP\Model\JwkInterface;
use danielburger1337\OAuth2DPoP\NonceStorage\NonceStorageInterface;
use danielburger1337\OAuth2DPoP\NonceStorage\NonceStorageKeyFactoryInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class DPoPProofFactory
{
    /**
     * @param ClockInterface                  $clock                  The PSR-20 clock to use.
     * @param DPoPTokenEncoderInterface       $encoder                The JWT encoder to use.
     * @param NonceStorageInterface           $nonceStorage           Service that stores the upstream servers "DPoP-Nonce" header.
     *                                                                `NullNonceStorage` can be used if it is known that the upstream server does not use the "DPoP-Nonce" header.
     * @param NonceStorageKeyFactoryInterface $nonceStorageKeyFactory Server that creates the nonce storage key.
     * @param int<1, max>                     $jtiByteLength          [optional] The byte length of the generated "jti" claim.
     */
    public function __construct(
        private readonly ClockInterface $clock,
        private readonly DPoPTokenEncoderInterface $encoder,
        private readonly NonceStorageInterface $nonceStorage,
        private readonly NonceStorageKeyFactoryInterface $nonceStorageKeyFactory,
        private readonly int $jtiByteLength = 32
    ) {
    }

    /**
     * Get the JWK that the authorization code should be bound to.
     *
     * @param string[] $serverSupportedSignatureAlgorithms The DPoP signature algorithms that the upstream server reported as supported.
     *
     * @throws MissingDPoPJwkException If no suitable JWK is registered.
     */
    public function getJwkToBind(array $serverSupportedSignatureAlgorithms): JwkInterface
    {
        return $this->encoder->selectJWK($serverSupportedSignatureAlgorithms);
    }

    /**
     * Create a DPoP proof token.
     *
     * @param string                       $htm                                The http method of the request.
     * @param UriInterface|string          $htu                                The http URI of the request.
     * @param string[]                     $serverSupportedSignatureAlgorithms The DPoP signature algorithms that the upstream server reported as supported.
     * @param AccessTokenModel|string|null $bindTo                             [optional] The access token the DPoP proof must be bound to.
     *                                                                         If the argument is of type `string`, it is assumed that a JKT
     *                                                                         is given and the DPoP proof will be signed with a JWK that matches that JKT.
     *
     * @throws MissingDPoPJwkException If no suitable JWK is registered.
     */
    public function createProof(string $htm, UriInterface|string $htu, array $serverSupportedSignatureAlgorithms, AccessTokenModel|string|null $bindTo = null): DPoPProof
    {
        $jkt = $bindTo instanceof AccessTokenModel ? $bindTo->jkt : $bindTo;

        $jwk = $this->encoder->selectJWK($serverSupportedSignatureAlgorithms, $jkt);

        $protectedHeader = [
            'typ' => DPoPTokenEncoderInterface::TYPE_HEADER_PARAMETER,
            'jwk' => $jwk->toPublic(),
        ];

        $htu = Util::createHtu($htu);

        $payload = [
            'htm' => $htm,
            'htu' => $htu,
            'iat' => $this->clock->now()->getTimestamp(),
            'jti' => \bin2hex(\random_bytes($this->jtiByteLength)),
        ];

        if ($bindTo instanceof AccessTokenModel) {
            $payload['ath'] = Util::createAccessTokenHash($bindTo);
        }

        $key = $this->nonceStorageKeyFactory->createKey($jwk, $htu);
        if (null !== ($nonce = $this->nonceStorage->getCurrentNonce($key))) {
            $payload['nonce'] = $nonce;
        }

        return new DPoPProof($jwk, $this->encoder->createProof($jwk, $payload, $protectedHeader));
    }

    /**
     * Create a DPoP proof token.
     *
     * @param RequestInterface             $request                            The request to create the DPoP proof from.
     * @param string[]                     $serverSupportedSignatureAlgorithms The DPoP signature algorithms that the upstream server reported as supported.
     * @param AccessTokenModel|string|null $bindTo                             [optional] The access token the DPoP proof must be bound to.
     *                                                                         If the argument is of type `string`, it is assumed that a JKT
     *                                                                         is given and the DPoP proof will be signed with a JWK that matches that JKT.
     *
     * @throws MissingDPoPJwkException If no suitable JWK is registered.
     */
    public function createProofFromRequest(RequestInterface $request, array $serverSupportedSignatureAlgorithms, AccessTokenModel|string|null $bindTo = null): DPoPProof
    {
        return $this->createProof($request->getMethod(), $request->getUri(), $serverSupportedSignatureAlgorithms, $bindTo);
    }

    /**
     * Store the "DPoP-Nonce" received by the upstream server.
     *
     * @param string              $nonce The "DPoP-Nonce" header value.
     * @param JwkInterface        $jwk   The JWK that was used in the request that received the "DPoP-Nonce" in the response.
     * @param UriInterface|string $htu   The http URI of the request that responded with the "DPoP-Nonce" header.
     */
    public function storeNextNonce(string $nonce, JwkInterface $jwk, UriInterface|string $htu): void
    {
        $key = $this->nonceStorageKeyFactory->createKey($jwk, Util::createHtu($htu));
        $this->nonceStorage->storeNextNonce($key, $nonce);
    }

    /**
     * Store the "DPoP-Nonce" header (if it exists) from a PSR-7 response.
     *
     * @param ResponseInterface $response The PSR-7 response.
     * @param RequestInterface  $request  The PSR-7 request.
     * @param JwkInterface      $jwk      The JWK that that received the "DPoP-Nonce" in the response.
     *
     * @throws \InvalidArgumentException If the response contains multiple "DPoP-Nonce" headers.
     */
    public function storeNextNonceFromResponse(ResponseInterface $response, RequestInterface $request, JwkInterface $jwk): void
    {
        $nonce = $response->getHeader('dpop-nonce');

        $count = \count($nonce);
        if (0 === $count) {
            return;
        }

        if (1 !== $count) {
            throw new \InvalidArgumentException('The PSR-7 response contains multiple "DPoP-Nonce" headers.');
        }

        $this->storeNextNonce($nonce[\array_key_first($nonce)], $jwk, $request->getUri());
    }
}
