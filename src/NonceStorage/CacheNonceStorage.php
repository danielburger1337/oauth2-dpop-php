<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

use Psr\Cache\CacheItemPoolInterface;

class CacheNonceStorage implements NonceStorageInterface, NonceVerificationStorageInterface
{
    /**
     * @codeCoverageIgnore
     */
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly \DateInterval $ttl = new \DateInterval('PT15M')
    ) {
    }

    public function getCurrentOrCreateNewNonce(string $key): string
    {
        $item = $this->cache->getItem($key);
        if (!$item->isHit() || !\is_string($stored = $item->get())) {
            $nonce = $this->generateNonce();

            $item->set($nonce);
            $item->expiresAfter($this->ttl);

            $this->cache->save($item);

            return $nonce;
        }

        return $stored;
    }

    public function createNewNonceIfInvalid(string $key, string $nonce): string|null
    {
        $item = $this->cache->getItem($key);
        if (!$item->isHit() || !\is_string($stored = $item->get())) {
            $nonce = $this->generateNonce();

            $item->set($nonce);
            $item->expiresAfter($this->ttl);

            $this->cache->save($item);

            return $nonce;
        }

        return \hash_equals($stored, $nonce) ? null : $stored;
    }

    public function getCurrentNonce(string $key): string|null
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

    protected function generateNonce(): string
    {
        return \bin2hex(\random_bytes(32));
    }
}
