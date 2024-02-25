<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP;

use danielburger1337\OAuth2DPoP\JwtHandler\JwtHandlerInterface;
use danielburger1337\OAuth2DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2DPoP\NonceStorage\NonceStorageInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\RequestInterface;

class DPoPProofFactory
{
    public function __construct(
        private readonly string $key,
        private readonly ClockInterface $clock,
        private readonly JwtHandlerInterface $jwtHandler,
        private readonly NonceStorageInterface|null $nonceStorage = null
    ) {
    }

    /**
     * @param string[]|null $serverSupportedSignatureAlgorithms [optional] The DPoP signature algorithms that the server reported as supported.
     */
    public function createProof(string $htm, string $htu, ?AccessTokenModel $accessToken = null, ?array $serverSupportedSignatureAlgorithms = null): string
    {
        $jwk = $this->jwtHandler->selectJWK($accessToken?->jkt, $serverSupportedSignatureAlgorithms);

        $protectedHeader = [
            'typ' => JwtHandlerInterface::TYPE_HEADER_PARAMETER,
            'jwk' => $jwk->toPublic(),
        ];

        return $this->jwtHandler->createProof($jwk, $this->createPayload($htm, $htu), $protectedHeader);
    }

    public function createProofForRequest(RequestInterface $request): RequestInterface
    {
        $proof = $this->createProof($request->getMethod(), $request->getUri()->__toString());

        return $request->withHeader('DPoP', $proof);
    }

    /**
     * @return array<string, string|int>
     */
    protected function createPayload(string $htm, string $htu): array
    {
        $pos = \strpos($htu, '?');
        if ($pos !== false) {
            $htu = \substr($htu, 0, $pos);
        } else {
            $pos = \strpos($htu, '#');
            if ($pos !== false) {
                $htu = \substr($htu, 0, $pos);
            }
        }

        $payload = [
            'htm' => $htm,
            'htu' => $htu,
            'iat' => $this->clock->now()->getTimestamp(),
            'jti' => \bin2hex(\random_bytes(32)),
        ];

        if (null !== ($nonce = $this->nonceStorage?->getCurrentNonce($this->key))) {
            $payload['nonce'] = $nonce;
        }

        return $payload;
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
