<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

class NonceStorageKeyFactory implements NonceStorageKeyFactoryInterface
{
    public function __construct(
        private readonly string $prefix = ''
    ) {
    }

    public function createKey(string $htu): string
    {
        $parts = \parse_url($htu);

        if (false === $parts) {
            throw new \InvalidArgumentException('The htu is not a valid URL.');
        }

        if (!\array_key_exists('scheme', $parts) || !\is_string($parts['scheme'])) {
            throw new \InvalidArgumentException('The htu has an invalid scheme.');
        }

        if (!\array_key_exists('host', $parts) || !\is_string($parts['host'])) {
            throw new \InvalidArgumentException('The htu has an invalid host.');
        }

        return \hash('xxh3', $this->prefix.\strtolower($parts['scheme'].$parts['host']));
    }
}
