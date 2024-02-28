<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests\NonceStorage;

use danielburger1337\OAuth2\DPoP\Model\JwkInterface;
use danielburger1337\OAuth2\DPoP\NonceStorage\NullNonceStorageKeyFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(NullNonceStorageKeyFactory::class)]
class NullNonceStorageKeyFactoryTest extends TestCase
{
    private NullNonceStorageKeyFactory $nonceStorageKeyFactory;

    protected function setUp(): void
    {
        $this->nonceStorageKeyFactory = new NullNonceStorageKeyFactory();
    }

    #[Test]
    #[DataProvider('dataProvider_createKey')]
    public function createKey_returnsEmptyString(string $thumbprint): void
    {
        $returnValue = $this->nonceStorageKeyFactory->createKey($this->createStub(JwkInterface::class), $thumbprint);

        $this->assertEquals('', $returnValue);
    }

    /**
     * @return array<array{0: string}>
     */
    public static function dataProvider_createKey(): array
    {
        return [
            ['thumbprint'],
            ['otherThumbprint'],
        ];
    }
}
