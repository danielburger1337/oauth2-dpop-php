<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP;

use Base64Url\Base64Url;
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
    public function createProof(string $htm, UriInterface|string $htu, AccessTokenModel|null $accessToken = null, ?array $serverSupportedSignatureAlgorithms = null): DPoPProof
    {
        $jwk = $this->jwtHandler->selectJWK($accessToken?->jkt, $serverSupportedSignatureAlgorithms);

        $protectedHeader = [
            'typ' => JwtHandlerInterface::TYPE_HEADER_PARAMETER,
            'jwk' => $jwk->toPublic(),
        ];

        $htu = self::createHtu($htu);

        $payload = [
            'htm' => $htm,
            'htu' => $htu,
            'iat' => $this->clock->now()->getTimestamp(),
            'jti' => \bin2hex(\random_bytes(32)),
        ];

        if (null !== $accessToken) {
            $payload['ath'] = Base64Url::encode(\hash('sha256', $accessToken->accessToken, true));
        }

        $key = $this->nonceStorageKeyFactory->createKey($htm, $htu);
        if (null !== ($nonce = $this->nonceStorage->getCurrentNonce($key))) {
            $payload['nonce'] = $nonce;
        }

        return new DPoPProof($jwk, $this->jwtHandler->createProof($jwk, $payload, $protectedHeader));
    }

    public function createProofForRequest(RequestInterface $request, AccessTokenModel|null $accessToken = null, ?array $serverSupportedSignatureAlgorithms = null): RequestInterface
    {
        $proof = $this->createProof($request->getMethod(), $request->getUri(), $accessToken, $serverSupportedSignatureAlgorithms);

        return $request->withHeader('DPoP', $proof->proof);
    }

    public function storeNextNonce(string $nonce, string $htm, UriInterface|string $htu): void
    {
        $key = $this->nonceStorageKeyFactory->createKey($htm, self::createHtu($htu));
        $this->nonceStorage->storeNextNonce($key, $nonce);
    }

    public function storeNextNonceFromResponse(ResponseInterface $response, RequestInterface $request): void
    {
        if (!$response->hasHeader('dpop-nonce')) {
            return;
        }

        $key = $this->nonceStorageKeyFactory->createKey($request->getMethod(), self::createHtu($request->getUri()));
        $this->nonceStorage->storeNextNonce($key, $response->getHeaderLine('dpop-nonce'));
    }

    public static function createHtu(UriInterface|string $htu): string
    {
        if ($htu instanceof UriInterface) {
            $htu = (string) $htu;
        }

        $pos = \strpos($htu, '?');
        if ($pos !== false) {
            $htu = \substr($htu, 0, $pos);
        } else {
            $pos = \strpos($htu, '#');
            if ($pos !== false) {
                $htu = \substr($htu, 0, $pos);
            }
        }

        return $htu;
    }

    /**
     * @param string $header The WWW-Authenticate header to parse.
     *
     * @return string[]|null
     */
    public static function parseSupportedAlgorithmsFromHeader(string $header): ?array
    {
        $pos = \strpos(\strtolower($header), 'dpop algs="');
        if (false === $pos) {
            return null;
        }

        // 11 => strlen('dpop algs="')
        $header = \substr($header, $pos + 11);

        $endPos = \strpos($header, '"');
        if (false === $endPos) {
            return null;
        }

        $header = \substr($header, 0, $endPos);

        return \explode(' ', $header);
    }
}
