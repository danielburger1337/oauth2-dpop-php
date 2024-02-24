<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\ReplayAttack;

interface ReplayAttackDetectorInterface
{
    /**
     * Whether the DPoP proof was already used.
     */
    public function isReplay(string $key): bool;

    /**
     * Store the usage of the DPoP proof.
     */
    public function storeUsage(string $key): void;
}
