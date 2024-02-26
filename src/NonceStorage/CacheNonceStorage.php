<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

use Psr\Cache\CacheItemPoolInterface;

class CacheNonceStorage implements NonceStorageInterface
{
    /**
     * @codeCoverageIgnore
     */
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly \DateInterval $ttl = new \DateInterval('PT15M')
    ) {
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
