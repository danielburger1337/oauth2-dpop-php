<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP;

use danielburger1337\OAuth2DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2DPoP\JwtHandler\JwkInterface;
use danielburger1337\OAuth2DPoP\JwtHandler\JwtHandlerInterface;
use danielburger1337\OAuth2DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2DPoP\Model\DPoPProof;
use danielburger1337\OAuth2DPoP\NonceStorage\NonceStorageInterface;
use danielburger1337\OAuth2DPoP\NonceStorage\NonceStorageKeyFactoryInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class DPoPProofFactory
{
    public function __construct(
        private readonly NonceStorageKeyFactoryInterface $nonceStorageKeyFactory,
        private readonly ClockInterface $clock,
        private readonly JwtHandlerInterface $jwtHandler,
        private readonly NonceStorageInterface $nonceStorage
    ) {
    }

    /**
     * Get the JWK that the authorization code should be bound to.
     *
     * @throws MissingDPoPJwkException If no suitable JWK is registered.
     */
    public function getJwkToBind(): JwkInterface
    {
        return $this->jwtHandler->selectJWK(null, null);
    }

    /**
     * @param string[]|null $serverSupportedSignatureAlgorithms [optional] The DPoP signature algorithms that the server reported as supported.
     */
    public function createProof(string $htm, UriInterface|string $htu, AccessTokenModel|string|null $bindTo = null, ?array $serverSupportedSignatureAlgorithms = null): DPoPProof
    {
        $jkt = $bindTo instanceof AccessTokenModel ? $bindTo->jkt : $bindTo;

        $jwk = $this->jwtHandler->selectJWK($jkt, $serverSupportedSignatureAlgorithms);

        $protectedHeader = [
            'typ' => JwtHandlerInterface::TYPE_HEADER_PARAMETER,
            'jwk' => $jwk->toPublic(),
        ];

        $htu = Util::createHtu($htu);

        $payload = [
            'htm' => $htm,
            'htu' => $htu,
            'iat' => $this->clock->now()->getTimestamp(),
            'jti' => \bin2hex(\random_bytes(32)),
        ];

        if ($bindTo instanceof AccessTokenModel) {
            $payload['ath'] = Util::createAccessTokenHash($bindTo);
        }

        $key = $this->nonceStorageKeyFactory->createKey($htu);
        if (null !== ($nonce = $this->nonceStorage->getCurrentNonce($key))) {
            $payload['nonce'] = $nonce;
        }

        return new DPoPProof($jwk, $this->jwtHandler->createProof($jwk, $payload, $protectedHeader));
    }

    /**
     * @param string[]|null $serverSupportedSignatureAlgorithms [optional] The DPoP signature algorithms that the server reported as supported.
     */
    public function createProofForRequest(RequestInterface $request, AccessTokenModel|null $accessToken = null, ?array $serverSupportedSignatureAlgorithms = null): RequestInterface
    {
        $proof = $this->createProof($request->getMethod(), $request->getUri(), $accessToken, $serverSupportedSignatureAlgorithms);

        return $request->withHeader('DPoP', $proof->proof);
    }

    public function storeNextNonce(string $nonce, string $htm, UriInterface|string $htu): void
    {
        $key = $this->nonceStorageKeyFactory->createKey(Util::createHtu($htu));
        $this->nonceStorage->storeNextNonce($key, $nonce);
    }

    public function storeNextNonceFromResponse(ResponseInterface $response, RequestInterface $request): void
    {
        if (!$response->hasHeader('dpop-nonce')) {
            return;
        }

        $key = $this->nonceStorageKeyFactory->createKey(Util::createHtu($request->getUri()));
        $this->nonceStorage->storeNextNonce($key, $response->getHeaderLine('dpop-nonce'));
    }
}
