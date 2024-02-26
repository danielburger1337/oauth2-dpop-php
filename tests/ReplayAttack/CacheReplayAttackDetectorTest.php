<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests\ReplayAttack;

use danielburger1337\OAuth2DPoP\Model\DecodedDPoPProof;
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
    private const JKT = 'u-OgFMUQNFo0PC7x32Il3T_n_FOgRrUZJj4DA9LKy3M';
    private const PAYLOAD = ['jti' => 'abcdefghijklmnopqrstuvwxyz'];
    private const HEADER = ['alg' => 'ES256'];

    private const CACHE_KEY = 'e72aacc2fd89916cb103b951956fd55a';

    private const CACHE_TTL = 'PT5S';

    private CacheItemPoolInterface&MockObject $cache;

    private CacheReplayAttackDetector $replayAttackDetector;
    private DecodedDPoPProof $proof;

    #[\Override]
    protected function setUp(): void
    {
        $this->proof = new DecodedDPoPProof(self::JKT, self::PAYLOAD, self::HEADER);

        $this->cache = $this->createMock(CacheItemPoolInterface::class);

        $this->replayAttackDetector = new CacheReplayAttackDetector($this->cache, new \DateInterval(self::CACHE_TTL));
    }

    #[Test]
    public function consumeProof_cacheHit_returnsFalse(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(true);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with(self::CACHE_KEY)
            ->willReturn($item);

        $returnValue = $this->replayAttackDetector->consumeProof($this->proof);
        $this->assertFalse($returnValue);
    }

    #[Test]
    public function consumeProof_cacheMiss_returnsTrue(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(false);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with(self::CACHE_KEY)
            ->willReturn($item);

        $returnValue = $this->replayAttackDetector->consumeProof($this->proof);
        $this->assertTrue($returnValue);
    }

    #[Test]
    public function consumeProof_cacheKey_isIdempotent(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(false);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with($this->logicalNot($this->equalTo(self::CACHE_KEY)))
            ->willReturn($item);

        $proof = new DecodedDPoPProof(self::JKT, [...self::PAYLOAD, 'jti' => 'abc'], self::HEADER);

        $returnValue = $this->replayAttackDetector->consumeProof($proof);
        $this->assertTrue($returnValue);
    }
}
