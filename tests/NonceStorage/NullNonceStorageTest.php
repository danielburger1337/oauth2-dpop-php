<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests\ReplayAttack;

use danielburger1337\OAuth2\DPoP\NonceStorage\NullNonceStorage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(NullNonceStorage::class)]
class NullNonceStorageTest extends TestCase
{
    private NullNonceStorage $nonceStorage;

    protected function setUp(): void
    {
        $this->nonceStorage = new NullNonceStorage();
    }

    #[Test]
    #[DataProvider('dataProvider')]
    public function getCurrentNonceReturnsNull(string $key): void
    {
        $returnValue = $this->nonceStorage->getCurrentNonce($key);

        $this->assertNull($returnValue);
    }

    #[Test]
    #[DataProvider('dataProvider')]
    public function storeNextNonceThrowsException(string $key): void
    {
        $this->expectException(\BadMethodCallException::class);

        $this->nonceStorage->storeNextNonce($key, 'nonce');
    }

    /**
     * @return array<string[]>
     */
    public static function dataProvider(): array
    {
        return [
            ['abc'],
            ['def'],
            ['ghi'],
        ];
    }
}
