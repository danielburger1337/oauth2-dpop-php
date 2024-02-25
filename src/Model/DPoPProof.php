<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Model;

use danielburger1337\OAuth2DPoP\JwtHandler\JwkInterface;

final class DPoPProof implements \Stringable
{
    public function __construct(
        public readonly JwkInterface $jwk,
        public readonly string $proof
    ) {
    }

    public function __toString(): string
    {
        return $this->proof;
    }
}
