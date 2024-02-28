<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Model;

final class AccessTokenModel
{
    /**
     * @param \Stringable|string $accessToken The access token that must be bound to a JKT.
     * @param string             $jkt         The JKT the access token must be bound to.
     *
     * @codeCoverageIgnore
     */
    public function __construct(
        public readonly \Stringable|string $accessToken,
        public readonly string $jkt
    ) {
    }
}
