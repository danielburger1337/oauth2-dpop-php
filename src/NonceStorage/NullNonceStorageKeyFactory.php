<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

use danielburger1337\OAuth2DPoP\Model\JwkInterface;

/**
 * Dummy storage key factory that can be used if it is known that the OP does not use DPoP nonces.
 */
final class NullNonceStorageKeyFactory implements NonceStorageKeyFactoryInterface
{
    public function createKey(JwkInterface $jwk, string $htu): string
    {
        return '';
    }
}
