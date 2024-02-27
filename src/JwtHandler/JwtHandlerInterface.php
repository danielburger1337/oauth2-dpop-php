<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\JwtHandler;

use danielburger1337\OAuth2DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2DPoP\Model\JwkInterface;

interface JwtHandlerInterface
{
    final public const TYPE_HEADER_PARAMETER = 'dpop+jwt';

    /**
     * Select the JWK used to sign DPoP proof.
     *
     * @param string[]    $serverSupportedSignatureAlgorithms The DPoP signature algorithms that the upstream server reported as supported.
     * @param string|null $jkt                                [optional] The JKT of the JWK that must be returned.
     *
     * @throws MissingDPoPJwkException If no suitable JWK was found.
     */
    public function selectJWK(array $serverSupportedSignatureAlgorithms, string|null $jkt = null): JwkInterface;

    /**
     * Create a DPoP proof.
     *
     * @param JwkInterface         $jwk             The JWK that must be used to sign the DPoP proof.
     * @param array<string, mixed> $payload         The DPoP payload to encode.
     * @param array<string, mixed> $protectedHeader The DPoP protected header to encode.
     */
    public function createProof(JwkInterface $jwk, array $payload, array $protectedHeader): string;
}
