<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

final class NullNonceStorage implements NonceStorageInterface
{
    public function createNewNonce(string $key): string
    {
        throw new \BadMethodCallException();
    }

    public function isNonceValid(string $key, string $nonce): bool
    {
        return false;
    }

    public function getCurrentNonce(string $key): ?string
    {
        return null;
    }

    public function storeNextNonce(string $key, string $nonce): void
    {
    }
}
