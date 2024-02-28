<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Loader;

use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2\DPoP\Model\DecodedDPoPProof;

interface DPoPTokenLoaderInterface
{
    /**
     * Load a DPoP proof token.
     *
     * @param string $proof The DPoP proof to load.
     *
     * @throws InvalidDPoPProofException If the DPoP proof is invalid.
     */
    public function loadProof(string $proof): DecodedDPoPProof;

    /**
     * The JWAs that are able to be loaded and verified.
     *
     * @return string[]
     */
    public function getSupportedAlgorithms(): array;
}
