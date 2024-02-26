<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\ReplayAttack;

use danielburger1337\OAuth2DPoP\Model\DecodedDPoPProof;

class ReplayAttackKeyFactory implements ReplayAttackKeyFactoryInterface
{
    public function createKey(DecodedDPoPProof $proof): string
    {
        return \hash('xxh128', $proof->jwkThumbprint.$proof->payload['jti']);
    }
}
