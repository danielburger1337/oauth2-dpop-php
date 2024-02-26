<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\ReplayAttack;

use danielburger1337\OAuth2DPoP\Model\DecodedDPoPProof;

interface ReplayAttackKeyFactoryInterface
{
    /**
     * Create the key with which to check if the DPoP proof token has already been used.
     *
     * @param DecodedDPoPProof $proof The DPoP proof to use.
     */
    public function createKey(DecodedDPoPProof $proof): string;
}
