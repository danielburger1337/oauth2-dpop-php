<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

/**
 * Dummy storage that can be used if it is known that the OP does not use DPoP nonces.
 */
final class NullNonceStorage implements NonceStorageInterface
{
    public function getCurrentNonce(string $key): null
    {
        return null;
    }

    public function storeNextNonce(string $key, string $nonce): void
    {
    }
}
