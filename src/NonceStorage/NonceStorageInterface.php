<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

interface NonceStorageInterface
{
    /**
     * Create a new DPoP-Nonce.
     *
     * @param string $key The key under which to store the nonce.
     *
     * @return string The created nonce.
     */
    public function createNewNonce(string $key): string;

    /**
     * Create a new DPoP-Nonce if the given one is invalid.
     *
     * @param string $key   The storage key to use for comparisson.
     * @param string $nonce The nonce to compare.
     *
     * @return string|null The newly created nonce or null if the provided nonce is valid.
     */
    public function createNewNonceIfInvalid(string $key, string $nonce): string|null;

    /**
     * Get the current DPoP-Nonce.
     *
     * @param string $key The storage key to use.
     *
     * @return string|null The current nonce or `null` if none exists.
     */
    public function getCurrentNonce(string $key): ?string;

    /**
     * Store a new DPoP-Nonce.
     *
     * @param string $key   The storage key to use.
     * @param string $nonce The nonce to store.
     */
    public function storeNextNonce(string $key, string $nonce): void;
}
