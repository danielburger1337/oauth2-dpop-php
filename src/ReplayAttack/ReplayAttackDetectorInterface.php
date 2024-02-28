<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\ReplayAttack;

use danielburger1337\OAuth2\DPoP\Model\DecodedDPoPProof;

interface ReplayAttackDetectorInterface
{
    /**
     * Consume a DPoP proof token.
     *
     * @param DecodedDPoPProof $proof The DPoP proof token to consume.
     *
     * @return bool Returns `true` if the proof was accepted, `false` otherwise.
     */
    public function consumeProof(DecodedDPoPProof $proof): bool;
}
