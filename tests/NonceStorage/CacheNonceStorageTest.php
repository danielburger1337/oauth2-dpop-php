<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests\NonceStorage;

use danielburger1337\OAuth2DPoP\NonceStorage\CacheNonceStorage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

#[CoversClass(CacheNonceStorage::class)]
class CacheNonceStorageTest extends TestCase
{
    private const STORED_NONCE = 'abcdef';
    private const CACHE_KEY = 'cache_key';
    private const CACHE_TTL = 'PT5S';

    private CacheItemPoolInterface&MockObject $cache;

    private CacheNonceStorage $nonceStorage;

    #[\Override]
    protected function setUp(): void
    {
        $this->cache = $this->createMock(CacheItemPoolInterface::class);

        $this->nonceStorage = new CacheNonceStorage($this->cache, self::CACHE_TTL);
    }

    #[Test]
    public function isNonceValid_validNonce_returnsTrue(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(true);

        $item->expects($this->once())
            ->method('get')
            ->willReturn(self::STORED_NONCE);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with(self::CACHE_KEY)
            ->willReturn($item);

        $returnValue = $this->nonceStorage->isNonceValid(self::CACHE_KEY, self::STORED_NONCE);
        $this->assertTrue($returnValue);
    }

    #[Test]
    public function isNonceValid_invalidNonce_returnsFalse(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(true);

        $item->expects($this->once())
            ->method('get')
            ->willReturn(self::STORED_NONCE);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with(self::CACHE_KEY)
            ->willReturn($item);

        $returnValue = $this->nonceStorage->isNonceValid(self::CACHE_KEY, 'invalid nonce');
        $this->assertFalse($returnValue);
    }

    #[Test]
    public function isNonceValid_cacheMiss_returnsFalse(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(false);

        $item->expects($this->never())
            ->method('get');

        $this->cache->expects($this->once())
            ->method('getItem')
            ->with('key')
            ->willReturn($item);

        $returnValue = $this->nonceStorage->isNonceValid('key', 'nonce');
        $this->assertFalse($returnValue);
    }

    #[Test]
    public function getCurrentNonce_cacheHit_returnsValue(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(true);

        $item->expects($this->once())
            ->method('get')
            ->willReturn(self::STORED_NONCE);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->willReturn($item);

        $returnValue = $this->nonceStorage->getCurrentNonce(self::CACHE_KEY);
        $this->assertEquals(self::STORED_NONCE, $returnValue);
    }

    #[Test]
    public function getCurrentNonce_cacheHit_returnsNullValue(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(true);

        $item->expects($this->once())
            ->method('get')
            ->willReturn(null);

        $this->cache->expects($this->once())
            ->method('getItem')
            ->willReturn($item);

        $returnValue = $this->nonceStorage->getCurrentNonce(self::CACHE_KEY);
        $this->assertNull($returnValue);
    }

    #[Test]
    public function getCurrentNonce_cacheMiss_returnsNull(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('isHit')
            ->willReturn(false);

        $item->expects($this->never())
            ->method('get');

        $this->cache->expects($this->once())
            ->method('getItem')
            ->willReturn($item);

        $returnValue = $this->nonceStorage->getCurrentNonce(self::CACHE_KEY);
        $this->assertNull($returnValue);
    }

    #[Test]
    public function storeNextNonce_isSaved(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('set')
            ->with(self::STORED_NONCE);

        $item->expects($this->once())
            ->method('expiresAfter')
            ->with(new \DateInterval(self::CACHE_TTL));

        $this->cache->expects($this->once())
            ->method('getItem')
            ->willReturn($item);

        $this->cache->expects($this->once())
            ->method('save')
            ->with($item);

        $this->nonceStorage->storeNextNonce(self::CACHE_KEY, self::STORED_NONCE);
    }

    #[Test]
    public function createNewNonce_createdNonce_isStoredAndReturned(): void
    {
        $generated = null;

        $item = $this->createMock(CacheItemInterface::class);
        $item->expects($this->once())
            ->method('set')
            ->willReturnCallback(function (string $value) use (&$generated, &$item) {
                $generated = $value;

                return $item;
            });

        $this->cache->expects($this->once())
            ->method('getItem')
            ->willReturn($item);

        $this->cache->expects($this->once())
            ->method('save')
            ->with($item);

        $returnValue = $this->nonceStorage->createNewNonce(self::CACHE_KEY);

        $this->assertEquals($generated, $returnValue);
    }

    #[Test]
    public function createNewNonce_hasSufficentLength(): void
    {
        $returnValue = $this->nonceStorage->createNewNonce(self::CACHE_KEY);

        $this->assertTrue(\strlen($returnValue) >= 8);
    }

    #[Test]
    public function createNewNonce_isRandom(): void
    {
        $returnValue1 = $this->nonceStorage->createNewNonce(self::CACHE_KEY);
        $returnValue2 = $this->nonceStorage->createNewNonce(self::CACHE_KEY);

        $this->assertNotEquals($returnValue1, $returnValue2);
    }
}
