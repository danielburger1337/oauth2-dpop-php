<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Loader;

use danielburger1337\OAuth2DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2DPoP\Model\DecodedDPoPProof;

interface DPoPTokenLoaderInterface
{
    /**
     * Parse a DPoP proof.
     *
     * @param string $proof The DPoP proof to parse.
     *
     * @throws InvalidDPoPProofException If the DPoP proof is invalid.
     */
    public function loadProof(string $proof): DecodedDPoPProof;

    /**
     * The JWAs that are able to be parsed and verify.
     *
     * @return string[]
     */
    public function getSupportedAlgorithms(): array;
}
