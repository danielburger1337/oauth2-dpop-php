<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\ReplayAttack;

use Psr\Cache\CacheItemPoolInterface;

class CacheReplayAttackDetector implements ReplayAttackDetectorInterface
{
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly \DateInterval $ttl = new \DateInterval('PT15M')
    ) {
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
