<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\NonceStorage;

use danielburger1337\OAuth2\DPoP\Model\JwkInterface;

class NonceStorageKeyFactory implements NonceStorageKeyFactoryInterface
{
    public function createKey(JwkInterface $jwk, string $htu): string
    {
        $parts = \parse_url($htu);

        if (false === $parts) {
            throw new \InvalidArgumentException('The htu is not a valid URL.');
        }

        if (!\array_key_exists('scheme', $parts) || !\is_string($parts['scheme']) || !\array_key_exists('host', $parts) || !\is_string($parts['host'])) {
            throw new \InvalidArgumentException('The htu has an invalid scheme or host.');
        }

        return \hash('xxh3', $jwk->thumbprint().\strtolower($parts['scheme'].$parts['host']));
    }
}
