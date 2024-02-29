<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\NonceStorage;

use Psr\Cache\CacheItemPoolInterface;

class CacheNonceStorage implements NonceStorageInterface
{
    /**
     * @param CacheItemPoolInterface $cache The PSR-6 cache used as the storage engine.
     * @param \DateInterval          $ttl   How long the nonce must be cached.
     *                                      This value should ideally match the lifetime of the nonce.
     *                                      Consult the documentation of your upstream server.
     */
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly \DateInterval $ttl = new \DateInterval('PT5M')
    ) {
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
}
