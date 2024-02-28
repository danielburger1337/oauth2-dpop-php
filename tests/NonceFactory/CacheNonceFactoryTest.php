<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests\NonceFactory;

use danielburger1337\OAuth2DPoP\NonceFactory\CacheNonceFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

#[CoversClass(CacheNonceFactory::class)]
class CacheNonceFactoryTest extends TestCase
{
    private const CACHE_TTL = 'PT5S';
    private const JKT = 'jkt';
    private const NONCE = 'nonce';

    private CacheItemPoolInterface&MockObject $cache;

    private CacheNonceFactory $nonceFactory;

    #[\Override]
    protected function setUp(): void
    {
        $this->cache = $this->createMock(CacheItemPoolInterface::class);

        $this->nonceFactory = new CacheNonceFactory($this->cache, new \DateInterval(self::CACHE_TTL));
    }

    #[Test]
    public function createNewNonceIfInvalid_validNonce_returnsNull(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(true);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with(self::NONCE)
            ->willReturn($item);

        $this->cache->expects($this->never())
            ->method('save');

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, self::NONCE);
        $this->assertNull($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalid_invalidNonce_createsNewNonce(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(false);

        $item2 = $this->createMock(CacheItemInterface::class);
        $item2->expects($this->once())
            ->method('set')
            ->with($this->isType('string'));

        $item2->expects($this->once())
            ->method('expiresAfter')
            ->with(new \DateInterval(self::CACHE_TTL));

        $nonce = null;

        $this->cache->expects($this->exactly(2))
            ->method('getItem')
            ->with($this->callback(function (mixed $value) use (&$nonce): bool {
                $nonce = $value;

                return true;
            }))
            ->willReturnOnConsecutiveCalls($item, $item2);

        $this->cache->expects($this->once())
            ->method('save')
            ->with($item);

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, self::NONCE);
        $this->assertEquals($nonce, $returnValue);
    }

    #[Test]
    public function createNewNonce_createsNewNonce(): void
    {
        $item = $this->createMock(CacheItemInterface::class);

        $item->expects($this->once())
            ->method('set')
            ->with($this->isType('string'));

        $item->expects($this->once())
            ->method('expiresAfter')
            ->with(new \DateInterval(self::CACHE_TTL));

        $nonce = null;

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with($this->callback(function (mixed $value) use (&$nonce): bool {
                $nonce = $value;

                return true;
            }))
            ->willReturn($item);

        $this->cache->expects($this->once())
            ->method('save')
            ->with($item);

        $returnValue = $this->nonceFactory->createNewNonce(self::JKT);
        $this->assertEquals($nonce, $returnValue);
    }
}
