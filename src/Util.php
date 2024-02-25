<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP;

use Base64Url\Base64Url;
use danielburger1337\OAuth2DPoP\Model\AccessTokenModel;

final class Util
{
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
