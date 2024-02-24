<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\JwtHandler;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\JWK;

class WebTokenFrameworkJwk implements JwkInterface
{
    public function __construct(
        public readonly JWK $jwk,
        public readonly Algorithm $algorithm
    ) {
    }

    public function toPublic(): array
    {
        return $this->jwk->toPublic()->jsonSerialize();
    }
}
