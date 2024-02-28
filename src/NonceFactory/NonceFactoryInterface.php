<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceFactory;

interface NonceFactoryInterface
{
    /**
     * Get the current DPoP-Nonce or create a new one.
     *
     * @param string $thumbprint The JKT that requires a new nonce.
     *
     * @return string The created nonce.
     */
    public function createNewNonce(string $thumbprint): string;

    /**
     * Create a new DPoP-Nonce if the given one is invalid.
     *
     * @param string $thumbprint The JKT that presented the nonce.
     * @param string $nonce      The nonce to compare.
     *
     * @return string|null The nonce or `null` if the provided nonce is valid.
     */
    public function createNewNonceIfInvalid(string $thumbprint, string $nonce): string|null;
}
