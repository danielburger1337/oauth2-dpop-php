<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP;

use Base64Url\Base64Url;
use danielburger1337\OAuth2\DPoP\Model\AccessTokenModel;
use Psr\Http\Message\UriInterface;
use Uri\InvalidUriException;
use Uri\Rfc3986\Uri;

/**
 * @internal
 */
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
     * @param UriInterface|Uri|string $htu The URI to create the "htu" from.
     *
     * @throws \InvalidArgumentException If the htu is not a valid URI.
     */
    public static function createHtu(UriInterface|Uri|string $htu): string
    {
        if (\PHP_VERSION_ID >= 80500) {
            try {
                $uri = $htu instanceof Uri ? $htu : new Uri((string) $htu);
            } catch (InvalidUriException $e) {
                throw new \InvalidArgumentException('The provided "htu" is not a valid URI.', previous: $e);
            }

            return $uri
                ->withQuery(null)
                ->withFragment(null)
                ->toString();
        } else {
            if ($htu instanceof UriInterface) {
                return $htu
                    ->withQuery('')
                    ->withFragment('')
                    ->__toString();
            }

            // This parser is really bad and error prone.
            // TODO: Remove when min PHP version is 8.5
            $pos = \strpos($htu, '?');
            if ($pos !== false) {
                $htu = \substr($htu, 0, $pos);
            } else {
                $pos = \strpos($htu, '#');
                if ($pos !== false) {
                    $htu = \substr($htu, 0, $pos);
                }
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
