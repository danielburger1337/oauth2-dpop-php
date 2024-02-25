<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\JwtHandler;

use danielburger1337\OAuth2DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2DPoP\Model\ParsedDPoPProofModel;

interface JwtHandlerInterface
{
    final public const TYPE_HEADER_PARAMETER = 'dpop+jwt';

    /**
     * Select the JWK used to sign DPoP proof.
     *
     * @param string[]|null $serverSupportedSignatureAlgorithms
     *
     * @throws MissingDPoPJwkException If no suitable JWK was found.
     */
    public function selectJWK(?string $jkt, ?array $serverSupportedSignatureAlgorithms = null): JwkInterface;

    /**
     * Create a DPoP proof.
     *
     * @param JwkInterface         $jwk             The JWK that must be used to sign the DPoP proof.
     * @param array<string, mixed> $payload         The DPoP payload to encode.
     * @param array<string, mixed> $protectedHeader The DPoP protected header to encode.
     */
    public function createProof(JwkInterface $jwk, array $payload, array $protectedHeader): string;

    /**
     * Parse a DPoP proof.
     *
     * @param string $proof The DPoP proof to parse.
     *
     * @throws InvalidDPoPProofException If the DPoP proof is invalid.
     */
    public function parseProof(string $proof): ParsedDPoPProofModel;
}
