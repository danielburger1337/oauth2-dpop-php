<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

interface NonceVerificationStorageInterface
{
    /**
     * Get the current DPoP-Nonce or create a new one.
     *
     * @param string $key The storage key to use for comparison.
     *
     * @return string The current or the newly created nonce.
     */
    public function getCurrentOrCreateNewNonce(string $key): string;

    /**
     * Create a new DPoP-Nonce if the given one is invalid.
     *
     * @param string $key   The storage key to use for comparison.
     * @param string $nonce The nonce to compare.
     *
     * @return string|null The newly created nonce or `null` if the provided nonce is valid.
     */
    public function createNewNonceIfInvalid(string $key, string $nonce): string|null;
}
