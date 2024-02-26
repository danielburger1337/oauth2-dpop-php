<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\ReplayAttack;

use danielburger1337\OAuth2DPoP\Model\DecodedDPoPProof;
use Psr\Cache\CacheItemPoolInterface;

class CacheReplayAttackDetector implements ReplayAttackDetectorInterface
{
    /**
     * @param CacheItemPoolInterface $cache The PSR-6 cache to use as storage.
     * @param \DateInterval          $ttl   How long the replay information must be stored for.
     *                                      This should ideally match the lifetime of your DPoP nonces.
     */
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly \DateInterval $ttl = new \DateInterval('PT15M'),
    ) {
    }

    public function consumeProof(DecodedDPoPProof $proof): bool
    {
        $key = $this->createKey($proof);

        $item = $this->cache->getItem($key);

        if ($item->isHit()) {
            return false;
        }

        $item->set(null);
        $item->expiresAfter($this->ttl);

        $this->cache->save($item);

        return true;
    }

    protected function createKey(DecodedDPoPProof $proof): string
    {
        return \hash('xxh128', $proof->jwkThumbprint.$proof->payload['jti']);
    }
}
