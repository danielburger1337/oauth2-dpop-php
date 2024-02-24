<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests\ReplayAttack;

use danielburger1337\OAuth2DPoP\ReplayAttack\CacheReplayAttackDetector;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

#[CoversClass(CacheReplayAttackDetector::class)]
class CacheReplayAttackDetectorTest extends TestCase
{
    private const CACHE_KEY = 'cache_key';
    private const CACHE_TTL = 'PT5S';

    private CacheItemPoolInterface&MockObject $cache;

    private CacheReplayAttackDetector $replayAttackDetector;

    #[\Override]
    protected function setUp(): void
    {
        $this->cache = $this->createMock(CacheItemPoolInterface::class);

        $this->replayAttackDetector = new CacheReplayAttackDetector($this->cache, self::CACHE_TTL);
    }

    #[Test]
    public function isReplay_cacheHit_returnsTrue(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(true);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with(self::CACHE_KEY)
            ->willReturn($item);

        $returnValue = $this->replayAttackDetector->isReplay(self::CACHE_KEY);
        $this->assertTrue($returnValue);
    }

    #[Test]
    public function isReplay_cacheMiss_returnsFalse(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(false);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with(self::CACHE_KEY)
            ->willReturn($item);

        $returnValue = $this->replayAttackDetector->isReplay(self::CACHE_KEY);
        $this->assertFalse($returnValue);
    }

    #[Test]
    public function storeUsage_savesCacheItem(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('expiresAfter')
            ->with(new \DateInterval(self::CACHE_TTL));

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with(self::CACHE_KEY)
            ->willReturn($item);

        $this->cache->expects($this->once())
            ->method('save')
            ->with($item);

        $this->replayAttackDetector->storeUsage(self::CACHE_KEY);
    }
}
