<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Model;

final class ParsedDPoPProofModel
{
    /**
     * @param array<string, mixed> $payload
     */
    public function __construct(
        public readonly string $jwkThumbprint,
        public readonly array $payload
    ) {
    }
}
