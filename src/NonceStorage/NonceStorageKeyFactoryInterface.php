<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

interface NonceStorageKeyFactoryInterface
{
    /**
     * Create the key under which to store the nonce provided by the upstream server.
     */
    public function createKey(string $htu): string;
}
