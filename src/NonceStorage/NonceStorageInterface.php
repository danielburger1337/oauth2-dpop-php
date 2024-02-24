<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

interface NonceStorageInterface
{
    public function createNewNonce(string $key): string;

    public function isNonceValid(string $key, string $nonce): bool;

    public function storeNextNonce(string $key, string $nonce): void;

    public function getCurrentNonce(string $key): ?string;
}
