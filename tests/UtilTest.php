<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests;

use danielburger1337\OAuth2\DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2\DPoP\Util;
use Nyholm\Psr7\Uri;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Util::class)]
class UtilTest extends TestCase
{
    private const string ACCESS_TOKEN = 'wf92ckbY6AB8KqPKdR4pEm6taHw5T2x1';
    private const string EXPECTED_HASH = '75ti-TxjY8HQdW-a7Znaj1IdZmRTOZME4kTBb3KyJ8Y';

    private const string HTU = 'https://example.com/path';

    /**
     * @param string[]|null $expected
     */
    #[Test]
    #[DataProvider('parseSupportedAlgorithmsFromHeaderDataProvider')]
    public function parseSupportedAlgorithmsFromHeaderReturnsExpected(string $header, ?array $expected): void
    {
        $returnValue = Util::parseSupportedAlgorithmsFromHeader($header);
        $this->assertEquals($expected, $returnValue);
    }

    #[Test]
    #[DataProvider('createHtuDataProvider')]
    public function createHtuWithUriReturnsHtu(string $attach): void
    {
        $returnValue = Util::createHtu(new Uri(self::HTU.$attach));

        $this->assertEquals(self::HTU, $returnValue);
    }

    #[Test]
    #[DataProvider('createHtuDataProvider')]
    public function createHtuWithStringReturnsHtu(string $attach): void
    {
        $returnValue = Util::createHtu(self::HTU.$attach);

        $this->assertEquals(self::HTU, $returnValue);
    }

    #[Test]
    public function createHtuInvalidUrlRemovesQuery(): void
    {
        $returnValue = Util::createHtu('is this working? yes');

        $this->assertEquals('is this working', $returnValue);
    }

    #[Test]
    public function createHtuInvalidUrlReturnsUnchanged(): void
    {
        $returnValue = Util::createHtu('not a url');

        $this->assertEquals('not a url', $returnValue);
    }

    #[Test]
    public function createAccessTokenHashStringReturnsExpected(): void
    {
        $returnValue = Util::createAccessTokenHash(self::ACCESS_TOKEN);

        $this->assertEquals(self::EXPECTED_HASH, $returnValue);
    }

    #[Test]
    public function createAccessTokenHashAccessTokenModelReturnsExpected(): void
    {
        $accessTokenModel = new AccessTokenModel(self::ACCESS_TOKEN, 'doesnt matter');

        $returnValue = Util::createAccessTokenHash($accessTokenModel);

        $this->assertEquals(self::EXPECTED_HASH, $returnValue);
    }

    #[Test]
    public function createAccessTokenHashAccessTokenModelWithStringableReturnsExpected(): void
    {
        $accessTokenModel = new AccessTokenModel($this->createStringableAccessToken(), 'doesnt matter');

        $returnValue = Util::createAccessTokenHash($accessTokenModel);

        $this->assertEquals(self::EXPECTED_HASH, $returnValue);
    }

    #[Test]
    public function createAccessTokenHashStringableReturnsExpected(): void
    {
        $returnValue = Util::createAccessTokenHash($this->createStringableAccessToken());

        $this->assertEquals(self::EXPECTED_HASH, $returnValue);
    }

    private function createStringableAccessToken(): \Stringable
    {
        return new class(self::ACCESS_TOKEN) implements \Stringable {
            public function __construct(
                private readonly string $accessToken,
            ) {
            }

            public function __toString(): string
            {
                return $this->accessToken;
            }
        };
    }

    /**
     * @return array<array{0: string, 1: string[]|null}>
     */
    public static function parseSupportedAlgorithmsFromHeaderDataProvider(): array
    {
        return [
            ['DPoP algs="ES256"', ['ES256']],
            ['DPoP algs="ES256 ES256K"', ['ES256', 'ES256K']],

            ['DPoP algs="EdDSA"', ['EdDSA']], // case sensitivity

            ['Bearer,error="invalid_token",DPoP algs="ES256"', ['ES256']],
            ['Bearer,error="invalid_token",DPoP algs="ES256 RS256"', ['ES256', 'RS256']],

            ['Bearer,error="invalid_token",DPoP algs="ES256', null], // missing "
            ['DPoP algs="ES256', null], // missing "
            ['', null],
            ['Bearer', null],
        ];
    }

    /**
     * @return array<string[]>
     */
    public static function createHtuDataProvider(): array
    {
        return [
            [''],
            ['#fragmet'],
            ['?query=param'],
            ['?query=param#fragment'],
        ];
    }
}
