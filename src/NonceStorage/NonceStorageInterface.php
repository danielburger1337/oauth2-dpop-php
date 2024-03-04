<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\NonceStorage;

interface NonceStorageInterface
{
    /**
     * Get the current DPoP-Nonce of an upstream server.
     *
     * @param string $key The storage key to use.
     *
     * @return string|null The current nonce or `null` if none exists.
     */
    public function getCurrentNonce(string $key): ?string;

    /**
     * Store a new DPoP-Nonce from an upstream server.
     *
     * @param string $key   The storage key to use.
     * @param string $nonce The nonce to store.
     */
    public function storeNextNonce(string $key, string $nonce): void;
}
