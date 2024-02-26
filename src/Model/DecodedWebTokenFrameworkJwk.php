<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Model;

use Jose\Component\Core\JWK;

final class DecodedWebTokenFrameworkJwk implements JwkInterface
{
    public function __construct(
        public readonly JWK $jwk,
        public readonly string $thumbprint,
    ) {
    }

    public function toPublic(): array
    {
        return $this->jwk->toPublic()->jsonSerialize();
    }

    public function thumbprint(): string
    {
        return $this->thumbprint;
    }
}
