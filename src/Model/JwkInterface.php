<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Model;

interface JwkInterface
{
    /**
     * The JWK public key.
     *
     * @return array<string, mixed>
     */
    public function toPublic(): array;

    /**
     * The JWK thumbprint (JKT).
     */
    public function thumbprint(): string;
}
