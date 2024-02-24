<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

use Psr\Cache\CacheItemPoolInterface;

class CacheNonceStorage implements NonceStorageInterface
{
    private readonly \DateInterval $ttl;

    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        \DateInterval|string $ttl = new \DateInterval('PT15M')
    ) {
        if (\is_string($ttl)) {
            $this->ttl = new \DateInterval($ttl);
        } else {
            $this->ttl = $ttl;
        }
    }

    public function isNonceValid(string $key, string $nonce): bool
    {
        $stored = $this->getCurrentNonce($key);

        return \is_string($stored) && \hash_equals($stored, $nonce);
    }

    public function getCurrentNonce(string $key): ?string
    {
        $item = $this->cache->getItem($key);
        if (!$item->isHit()) {
            return null;
        }

        $nonce = $item->get();

        return \is_string($nonce) ? $nonce : null;
    }

    public function storeNextNonce(string $key, string $nonce): void
    {
        $item = $this->cache->getItem($key);
        $item->set($nonce);
        $item->expiresAfter($this->ttl);

        $this->cache->save($item);
    }

    public function createNewNonce(string $key): string
    {
        $nonce = \bin2hex(\random_bytes(32));

        $this->storeNextNonce($key, $nonce);

        return $nonce;
    }
}
