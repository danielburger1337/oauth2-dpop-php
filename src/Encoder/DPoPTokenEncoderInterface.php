<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Encoder;

use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2\DPoP\Model\JwkInterface;

interface DPoPTokenEncoderInterface
{
    final public const string TYPE_HEADER_PARAMETER = 'dpop+jwt';

    /**
     * Select the JWK used to sign a DPoP proof.
     *
     * @param string[]    $serverSupportedSignatureAlgorithms The DPoP signature algorithms that the upstream server reported as supported.
     * @param string|null $jkt                                [optional] The JKT of the JWK that must be returned.
     *                                                        This argument is provided if the token must be bound to a specific JKT.
     *
     * @throws MissingDPoPJwkException If no JWK that matches the given constraints was found.
     */
    public function selectJWK(array $serverSupportedSignatureAlgorithms, ?string $jkt = null): JwkInterface;

    /**
     * Encode a DPoP proof.
     *
     * @param JwkInterface         $jwk             The JWK that must be used to sign the DPoP proof.
     * @param array<string, mixed> $payload         The DPoP payload to encode.
     * @param array<string, mixed> $protectedHeader The DPoP protected header to encode.
     */
    public function createProof(JwkInterface $jwk, array $payload, array $protectedHeader): string;
}
