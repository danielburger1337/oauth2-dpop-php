<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Model;

final class AccessTokenModel
{
    /**
     * @codeCoverageIgnore
     */
    public function __construct(
        public readonly string|\Stringable $accessToken,
        public readonly string $jkt
    ) {
    }
}
