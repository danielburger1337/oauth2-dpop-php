<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Model;

final class DecodedDPoPProof
{
    /**
     * @param JwkInterface         $jwk             The JWK that was used to sign the DPoP proof.
     * @param array<string, mixed> $payload         The decoded payload of the DPoP proof token.
     * @param array<string, mixed> $protectedHeader The decoded protected header of the DPoP proof token.
     *
     * @codeCoverageIgnore
     */
    public function __construct(
        public readonly JwkInterface $jwk,
        public readonly array $payload,
        public readonly array $protectedHeader
    ) {
    }
}
