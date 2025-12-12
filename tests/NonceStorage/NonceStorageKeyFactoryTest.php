<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests\NonceStorage;

use danielburger1337\OAuth2\DPoP\Model\JwkInterface;
use danielburger1337\OAuth2\DPoP\NonceStorage\NonceStorageKeyFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;

#[CoversClass(NonceStorageKeyFactory::class)]
class NonceStorageKeyFactoryTest extends TestCase
{
    private const string JKT = 'ifwanbiofnwaiofnbafwioafhnwiafn';

    private const string URL = 'https://example.com/path?query=abc';
    private const string EXPECTED = 'e7a78bf47628267c';

    private NonceStorageKeyFactory $nonceStorageKeyFactory;
    private JwkInterface&Stub $jwk;

    protected function setUp(): void
    {
        $this->jwk = $this->createStub(JwkInterface::class);
        $this->jwk->method('thumbprint')
            ->willReturn(self::JKT);

        $this->nonceStorageKeyFactory = new NonceStorageKeyFactory();
    }

    #[Test]
    #[DataProvider('dataProviderHtu')]
    public function createKeyWithUrlReturnsExpected(string $htu): void
    {
        $returnValue = $this->nonceStorageKeyFactory->createKey($this->jwk, $htu);

        $this->assertEquals(self::EXPECTED, $returnValue);
    }

    #[Test]
    #[DataProvider('dataProviderInvalidHtu')]
    public function createKeyUrlWithoutSchemeThrowsException(string $htu): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->nonceStorageKeyFactory->createKey($this->jwk, $htu);
    }

    /**
     * @return list<string[]>
     */
    public static function dataProviderHtu(): array
    {
        return [
            [self::URL],
            [\strtoupper(self::URL)],
        ];
    }

    /**
     * @return list<string[]>
     */
    public static function dataProviderInvalidHtu(): array
    {
        return [
            ['www.example.com/path'],
            ['https://#path?query'],
            ['not an url'],
        ];
    }
}
