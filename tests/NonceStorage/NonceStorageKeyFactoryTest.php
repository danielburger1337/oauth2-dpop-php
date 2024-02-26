<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests\NonceStorage;

use danielburger1337\OAuth2DPoP\NonceStorage\NonceStorageKeyFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(NonceStorageKeyFactory::class)]
class NonceStorageKeyFactoryTest extends TestCase
{
    private const URL = 'https://example.com/path?query=abc';
    private const EXPECTED = '2e0dcce6014acede';
    private const PREFIX = 'dpop_nonce';
    private const PREFIX_EXPECTED = 'cdb6dbc7432d81d3';

    private NonceStorageKeyFactory $nonceStorageKeyFactory;

    protected function setUp(): void
    {
        $this->nonceStorageKeyFactory = new NonceStorageKeyFactory();
    }

    #[Test]
    public function createKey_withPrefix_returnsExpected(): void
    {
        $factory = new NonceStorageKeyFactory(self::PREFIX);

        $returnValue = $factory->createKey(self::URL);

        $this->assertEquals(self::PREFIX_EXPECTED, $returnValue);
    }

    #[Test]
    public function createKey_postUrl_returnsExpected(): void
    {
        $returnValue = $this->nonceStorageKeyFactory->createKey(self::URL);

        $this->assertEquals(self::EXPECTED, $returnValue);
    }

    #[Test]
    public function createKey_upperCaseUrl_returnsExpected(): void
    {
        $returnValue = $this->nonceStorageKeyFactory->createKey(\strtoupper(self::URL));

        $this->assertEquals(self::EXPECTED, $returnValue);
    }

    #[Test]
    public function createKey_invalidUrl_throwsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->nonceStorageKeyFactory->createKey('not an url');
    }

    #[Test]
    public function createKey_urlWithoutScheme_throwsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->nonceStorageKeyFactory->createKey('www.example.com/path');
    }

    #[Test]
    public function createKey_urlWithoutHost_throwsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->nonceStorageKeyFactory->createKey('mobile-app:///path');
    }
}
