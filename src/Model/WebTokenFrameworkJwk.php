<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Model;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\JWK;

/**
 * @internal
 */
final class WebTokenFrameworkJwk implements JwkInterface
{
    public function __construct(
        public readonly JWK $jwk,
        public readonly string $jkt,
        public readonly Algorithm $algorithm,
    ) {
    }

    public function toPublic(): array
    {
        return $this->jwk->toPublic()->jsonSerialize();
    }

    public function thumbprint(): string
    {
        return $this->jkt;
    }

    public function algorithm(): string
    {
        return $this->algorithm->name();
    }
}
