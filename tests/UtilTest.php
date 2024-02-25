<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests;

use danielburger1337\OAuth2DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2DPoP\Util;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Util::class)]
class UtilTest extends TestCase
{
    private const ACCESS_TOKEN = 'wf92ckbY6AB8KqPKdR4pEm6taHw5T2x1';
    private const EXPECTED_HASH = '75ti-TxjY8HQdW-a7Znaj1IdZmRTOZME4kTBb3KyJ8Y';

    #[Test]
    public function createAccessTokenHash_string_returnsExpected(): void
    {
        $returnValue = Util::createAccessTokenHash(self::ACCESS_TOKEN);

        $this->assertEquals(self::EXPECTED_HASH, $returnValue);
    }

    #[Test]
    public function createAccessTokenHash_AccessTokenModel_returnsExpected(): void
    {
        $accessTokenModel = new AccessTokenModel(self::ACCESS_TOKEN, 'doesnt matter');

        $returnValue = Util::createAccessTokenHash($accessTokenModel);

        $this->assertEquals(self::EXPECTED_HASH, $returnValue);
    }

    #[Test]
    public function createAccessTokenHash_AccessTokenModelWithStringable_returnsExpected(): void
    {
        $accessTokenModel = new AccessTokenModel($this->createStringableAccessToken(), 'doesnt matter');

        $returnValue = Util::createAccessTokenHash($accessTokenModel);

        $this->assertEquals(self::EXPECTED_HASH, $returnValue);
    }

    #[Test]
    public function createAccessTokenHash_Stringable_returnsExpected(): void
    {
        $returnValue = Util::createAccessTokenHash($this->createStringableAccessToken());

        $this->assertEquals(self::EXPECTED_HASH, $returnValue);
    }

    private function createStringableAccessToken(): \Stringable
    {
        return new class(self::ACCESS_TOKEN) implements \Stringable {
            public function __construct(
                private readonly string $accessToken
            ) {
            }

            public function __toString(): string
            {
                return $this->accessToken;
            }
        };
    }
}
