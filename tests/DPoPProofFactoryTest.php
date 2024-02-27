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
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
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

    #[Test]
    public function storeNextNonce_htu_isNotModified(): void
    {
        $this->nonceStorageKeyFactory->expects($this->once())
            ->method('createKey')
            ->with('https://sub.example.com/path')
            ->willReturn('storageKey');

        $this->nonceStorage->expects($this->once())
            ->method('storeNextNonce')
            ->with('storageKey', 'nonce');

        $this->factory->storeNextNonce('nonce', 'https://sub.example.com/path');
    }

    #[Test]
    public function storeNextNonce_htu_isTransformed(): void
    {
        $this->nonceStorageKeyFactory->expects($this->once())
            ->method('createKey')
            ->with('https://example.com/path')
            ->willReturn('storageKey');

        $this->nonceStorage->expects($this->once())
            ->method('storeNextNonce')
            ->with('storageKey', 'nonce');

        $this->factory->storeNextNonce('nonce', 'https://example.com/path?query=1#fragment');
    }

    #[Test]
    public function storeNextNonceFromResponse_emptyHeader_doesNothing(): void
    {
        $request = $this->createMock(RequestInterface::class);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getHeader')
            ->with('dpop-nonce')
            ->willReturn([]);

        $this->nonceStorage->expects($this->never())
            ->method($this->anything());

        $this->factory->storeNextNonceFromResponse($response, $request);
    }

    #[Test]
    public function storeNextNonceFromResponse_multipleHeader_throwsException(): void
    {
        $request = $this->createMock(RequestInterface::class);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getHeader')
            ->with('dpop-nonce')
            ->willReturn(['1', '2']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The PSR-7 response contains multiple "DPoP-Nonce" headers.');

        $this->factory->storeNextNonceFromResponse($response, $request);
    }

    #[Test]
    public function storeNextNonceFromResponse_includesNonce_storesNonce(): void
    {
        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->atLeastOnce())
            ->method('__toString')
            ->willReturn('https://example.com/path');

        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->atLeastOnce())
            ->method('getUri')
            ->willReturn($uri);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getHeader')
            ->with('dpop-nonce')
            ->willReturn(['nonceValue']);

        $this->nonceStorageKeyFactory->expects($this->once())
            ->method('createKey')
            ->with('https://example.com/path')
            ->willReturn('storageKey');

        $this->nonceStorage->expects($this->once())
            ->method('storeNextNonce')
            ->with('storageKey', 'nonceValue');

        $this->factory->storeNextNonceFromResponse($response, $request);
    }

    #[Test]
    public function storeNextNonceFromResponse_includesNonceAndQueryParameter_storesNonce(): void
    {
        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->atLeastOnce())
            ->method('__toString')
            ->willReturn('https://example.com/path?query=1#fragment');

        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->atLeastOnce())
            ->method('getUri')
            ->willReturn($uri);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getHeader')
            ->with('dpop-nonce')
            ->willReturn(['nonceValue']);

        $this->nonceStorageKeyFactory->expects($this->once())
            ->method('createKey')
            ->with('https://example.com/path')
            ->willReturn('storageKey');

        $this->nonceStorage->expects($this->once())
            ->method('storeNextNonce')
            ->with('storageKey', 'nonceValue');

        $this->factory->storeNextNonceFromResponse($response, $request);
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
