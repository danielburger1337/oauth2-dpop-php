<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP;

use Base64Url\Base64Url;
use danielburger1337\OAuth2DPoP\Model\AccessTokenModel;
use Psr\Http\Message\UriInterface;

final class Util
{
    /**
     * Parse the server supported DPoP algorithms from a "WWW-Authenticate" header.
     *
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

    /**
     * Create an "htu" claim.
     *
     * @param UriInterface|string $htu The URI to create the "htu" from.
     */
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
     * Create an "ath" hash.
     *
     * @param AccessTokenModel|\Stringable|string $accessToken The access token to hash.
     */
    public static function createAccessTokenHash(AccessTokenModel|\Stringable|string $accessToken): string
    {
        if ($accessToken instanceof AccessTokenModel) {
            $accessToken = $accessToken->accessToken;
        }

        return Base64Url::encode(\hash('sha256', (string) $accessToken, true));
    }
}
