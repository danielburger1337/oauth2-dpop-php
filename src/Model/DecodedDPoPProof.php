<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Model;

final class DecodedDPoPProof
{
    /**
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $protectedHeader
     */
    public function __construct(
        public readonly string $jwkThumbprint,
        public readonly array $payload,
        public readonly array $protectedHeader
    ) {
    }
}
