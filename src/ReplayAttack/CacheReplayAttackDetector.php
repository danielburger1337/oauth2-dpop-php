<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\ReplayAttack;

use Psr\Cache\CacheItemPoolInterface;

class CacheReplayAttackDetector implements ReplayAttackDetectorInterface
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

    public function isReplay(string $key): bool
    {
        return $this->cache->getItem($key)->isHit();
    }

    public function storeUsage(string $key): void
    {
        $item = $this->cache->getItem($key);
        $item->set(null);
        $item->expiresAfter($this->ttl);

        $this->cache->save($item);
    }
}
