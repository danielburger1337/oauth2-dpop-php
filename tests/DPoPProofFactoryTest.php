<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests;

use danielburger1337\OAuth2DPoP\DPoPProofFactory;
use danielburger1337\OAuth2DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2DPoP\JwtHandler\JwtHandlerInterface;
use danielburger1337\OAuth2DPoP\Model\JwkInterface;
use danielburger1337\OAuth2DPoP\NonceStorage\NonceStorageInterface;
use danielburger1337\OAuth2DPoP\NonceStorage\NonceStorageKeyFactoryInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

#[CoversClass(DPoPProofFactory::class)]
class DPoPProofFactoryTest extends TestCase
{
    private const JTI_LENGTH = 8;

    private DPoPProofFactory $factory;

    private MockClock $clock;
    private JwtHandlerInterface&MockObject $jwtHandler;
    private NonceStorageInterface&MockObject $nonceStorage;
    private NonceStorageKeyFactoryInterface&MockObject $nonceStorageKeyFactory;

    protected function setUp(): void
    {
        $this->clock = new MockClock();
        $this->jwtHandler = $this->createMock(JwtHandlerInterface::class);
        $this->nonceStorage = $this->createMock(NonceStorageInterface::class);
        $this->nonceStorageKeyFactory = $this->createMock(NonceStorageKeyFactoryInterface::class);

        $this->factory = new DPoPProofFactory($this->clock, $this->jwtHandler, $this->nonceStorage, $this->nonceStorageKeyFactory, self::JTI_LENGTH);
    }

    /**
     * @param string[] $supportedAlgorithms
     */
    #[Test]
    #[DataProvider('getJwkToBindDataProvider')]
    public function getJwkToBind_returnsJwk(array $supportedAlgorithms): void
    {
        $jwk = $this->createMock(JwkInterface::class);

        $this->jwtHandler->expects($this->once())
            ->method('selectJWK')
            ->with($supportedAlgorithms)
            ->willReturn($jwk);

        $this->factory->getJwkToBind($supportedAlgorithms);
    }

    #[Test]
    public function getJwkToBind_throwsException(): void
    {
        $e = $this->createStub(MissingDPoPJwkException::class);

        $this->jwtHandler->expects($this->once())
            ->method('selectJWK')
            ->with(['EdDSA'])
            ->willThrowException($e);

        $this->expectExceptionObject($e);

        $this->factory->getJwkToBind(['EdDSA']);
    }

    /**
     * @return array<array{0: string[]}>
     */
    public static function getJwkToBindDataProvider(): array
    {
        return [
            [[]],
            [['ES256']],
            [['ES256', 'ES384']],
            [['ES256', 'ES256']],
            [['ES256', 'ES256K']],
        ];
    }
}
