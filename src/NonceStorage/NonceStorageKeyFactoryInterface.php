<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

use danielburger1337\OAuth2DPoP\Model\JwkInterface;

interface NonceStorageKeyFactoryInterface
{
    /**
     * Create the key under which to store the nonce provided by the upstream server.
     *
     * @param JwkInterface $jwk The JWK that was used in the request that received the "DPoP-Nonce" in the response.
     * @param string       $htu The http URL of the request that received the "DPoP-Nonce" in the response.
     */
    public function createKey(JwkInterface $jwk, string $htu): string;
}
