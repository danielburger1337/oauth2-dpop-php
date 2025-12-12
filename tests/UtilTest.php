<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests;

use danielburger1337\OAuth2\DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2\DPoP\Util;
use Nyholm\Psr7\Uri as Psr7Uri;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;
use Uri\Rfc3986\Uri;

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
    public function createHtuReturnsHtu(UriInterface|Uri|string $htu, string|bool $expected): void
    {
        if (false === $expected) {
            $this->expectException(\InvalidArgumentException::class);
        }

        $returnValue = Util::createHtu($htu);

        if (false !== $expected) {
            $this->assertEquals($expected, $returnValue);
        }
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
     * @return list<array{0: UriInterface|Uri|string, 1: string|false}>
     */
    public static function createHtuDataProvider(): array
    {
        $providedData = [
            [self::HTU, self::HTU],
            [self::HTU.'#fragmet', self::HTU],
            [self::HTU.'?query=param', self::HTU],
            [self::HTU.'?query=param#fragment', self::HTU],

            [new Psr7Uri(self::HTU.'#fragmet'), self::HTU],
            [new Psr7Uri(self::HTU.'?query=param'), self::HTU],
            [new Psr7Uri(self::HTU.'?query=param#fragment'), self::HTU],
        ];

        if (\PHP_VERSION_ID >= 80500) {
            $providedData[] = [new Uri(self::HTU.'#fragmet'), self::HTU];
            $providedData[] = [new Uri(self::HTU.'?query=param'), self::HTU];
            $providedData[] = [new Uri(self::HTU.'?query=param#fragment'), self::HTU];

            $providedData[] = ['invalid uri', false];
        } else {
            $providedData[] = ['invalid uri', 'invalid uri'];
        }

        return $providedData;
    }
}
