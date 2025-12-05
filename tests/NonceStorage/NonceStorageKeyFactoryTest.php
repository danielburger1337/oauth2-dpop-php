<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests\NonceStorage;

use danielburger1337\OAuth2\DPoP\Model\JwkInterface;
use danielburger1337\OAuth2\DPoP\NonceStorage\NonceStorageKeyFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[CoversClass(NonceStorageKeyFactory::class)]
class NonceStorageKeyFactoryTest extends TestCase
{
    private const JKT = 'ifwanbiofnwaiofnbafwioafhnwiafn';

    private const URL = 'https://example.com/path?query=abc';
    private const EXPECTED = 'e7a78bf47628267c';

    private NonceStorageKeyFactory $nonceStorageKeyFactory;
    private JwkInterface&MockObject $jwk;

    protected function setUp(): void
    {
        $this->jwk = $this->createMock(JwkInterface::class);
        $this->jwk->expects($this->any())
            ->method('thumbprint')
            ->willReturn(self::JKT);

        $this->nonceStorageKeyFactory = new NonceStorageKeyFactory();
    }

    #[Test]
    public function createKeyWithUrlReturnsExpected(): void
    {
        $returnValue = $this->nonceStorageKeyFactory->createKey($this->jwk, self::URL);

        $this->assertEquals(self::EXPECTED, $returnValue);
    }

    #[Test]
    public function createKeyUpperCaseUrlReturnsExpected(): void
    {
        $returnValue = $this->nonceStorageKeyFactory->createKey($this->jwk, \strtoupper(self::URL));

        $this->assertEquals(self::EXPECTED, $returnValue);
    }

    #[Test]
    public function createKeyInvalidUrlThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The htu has an invalid scheme or host.');

        $this->nonceStorageKeyFactory->createKey($this->jwk, 'not an url');
    }

    #[Test]
    public function createKeyMalformedUrlThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The htu is not a valid URL.');

        $this->nonceStorageKeyFactory->createKey($this->jwk, 'https://#path?query');
    }

    #[Test]
    public function createKeyUrlWithoutSchemeThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The htu has an invalid scheme or host.');

        $this->nonceStorageKeyFactory->createKey($this->jwk, 'www.example.com/path');
    }
}
