<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests;

use danielburger1337\OAuth2\DPoP\DPoPProofFactory;
use danielburger1337\OAuth2\DPoP\Encoder\DPoPTokenEncoderInterface;
use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2\DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2\DPoP\Model\JwkInterface;
use danielburger1337\OAuth2\DPoP\NonceStorage\NonceStorageInterface;
use danielburger1337\OAuth2\DPoP\NonceStorage\NonceStorageKeyFactoryInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use Symfony\Component\Clock\MockClock;

#[CoversClass(DPoPProofFactory::class)]
class DPoPProofFactoryTest extends TestCase
{
    private const string HTM = 'GET';
    private const string HTU = 'https://example.com/path';

    private const int JTI_LENGTH = 8;

    private DPoPProofFactory $factory;

    private MockClock $clock;
    private (DPoPTokenEncoderInterface&MockObject)|(DPoPTokenEncoderInterface&Stub) $encoder;
    private (NonceStorageInterface&MockObject)|(NonceStorageInterface&Stub) $nonceStorage;
    private (NonceStorageKeyFactoryInterface&MockObject)|(NonceStorageKeyFactoryInterface&Stub) $nonceStorageKeyFactory;

    protected function setUp(): void
    {
        $this->clock = new MockClock();
    }

    private function createFactory(bool $encoder = false, bool $nonceStorage = false, bool $nonceStorageKeyFactory = false): void
    {
        $this->encoder = $encoder ? $this->createMock(DPoPTokenEncoderInterface::class) : $this->createStub(DPoPTokenEncoderInterface::class);
        $this->nonceStorage = $nonceStorage ? $this->createMock(NonceStorageInterface::class) : $this->createStub(NonceStorageInterface::class);
        $this->nonceStorageKeyFactory = $nonceStorageKeyFactory ? $this->createMock(NonceStorageKeyFactoryInterface::class) : $this->createStub(NonceStorageKeyFactoryInterface::class);

        $this->factory = new DPoPProofFactory($this->clock, $this->encoder, $this->nonceStorage, $this->nonceStorageKeyFactory, self::JTI_LENGTH);
    }

    /**
     * @param string[] $supportedAlgorithms
     */
    #[Test]
    #[DataProvider('getJwkToBindDataProvider')]
    public function getJwkToBindReturnsJwk(array $supportedAlgorithms): void
    {
        $this->createFactory(encoder: true);

        $jwk = $this->createStub(JwkInterface::class);

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with($supportedAlgorithms)
            ->willReturn($jwk);

        $this->factory->getJwkToBind($supportedAlgorithms);
    }

    #[Test]
    public function getJwkToBindThrowsException(): void
    {
        $this->createFactory(encoder: true);

        $e = $this->createStub(MissingDPoPJwkException::class);

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['EdDSA'])
            ->willThrowException($e);

        $this->expectExceptionObject($e);

        $this->factory->getJwkToBind(['EdDSA']);
    }

    #[Test]
    public function storeNextNonceEmptyNonceDoesNothing(): void
    {
        $this->createFactory(nonceStorage: true, nonceStorageKeyFactory: true);

        $jwk = $this->createStub(JwkInterface::class);

        $this->nonceStorageKeyFactory->expects($this->never())
            ->method('createKey');

        $this->nonceStorage->expects($this->never())
            ->method('storeNextNonce');

        $this->factory->storeNextNonce('', $jwk, 'https://sub.example.com/path');
    }

    #[Test]
    public function storeNextNonceHtuIsNotModified(): void
    {
        $this->createFactory(nonceStorage: true, nonceStorageKeyFactory: true);

        $jwk = $this->createStub(JwkInterface::class);

        $this->nonceStorageKeyFactory->expects($this->once())
            ->method('createKey')
            ->with($jwk, 'https://sub.example.com/path')
            ->willReturn('storageKey');

        $this->nonceStorage->expects($this->once())
            ->method('storeNextNonce')
            ->with('storageKey', 'nonce');

        $this->factory->storeNextNonce('nonce', $jwk, 'https://sub.example.com/path');
    }

    #[Test]
    public function storeNextNonceHtuIsTransformed(): void
    {
        $this->createFactory(nonceStorage: true, nonceStorageKeyFactory: true);

        $jwk = $this->createStub(JwkInterface::class);

        $this->nonceStorageKeyFactory->expects($this->once())
            ->method('createKey')
            ->with($jwk, 'https://example.com/path')
            ->willReturn('storageKey');

        $this->nonceStorage->expects($this->once())
            ->method('storeNextNonce')
            ->with('storageKey', 'nonce');

        $this->factory->storeNextNonce('nonce', $jwk, 'https://example.com/path?query=1#fragment');
    }

    #[Test]
    public function storeNextNonceFromResponseEmptyHeaderDoesNothing(): void
    {
        $this->createFactory(nonceStorage: true);

        $jwk = $this->createStub(JwkInterface::class);

        $request = $this->createStub(RequestInterface::class);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getHeader')
            ->with('dpop-nonce')
            ->willReturn([]);

        $this->nonceStorage->expects($this->never())
            ->method($this->anything());

        $this->factory->storeNextNonceFromResponse($response, $request, $jwk);
    }

    #[Test]
    public function storeNextNonceFromResponseMultipleHeaderThrowsException(): void
    {
        $this->createFactory();

        $jwk = $this->createStub(JwkInterface::class);

        $request = $this->createStub(RequestInterface::class);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getHeader')
            ->with('dpop-nonce')
            ->willReturn(['1', '2']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The PSR-7 response contains multiple "DPoP-Nonce" headers.');

        $this->factory->storeNextNonceFromResponse($response, $request, $jwk);
    }

    #[Test]
    public function storeNextNonceFromResponseIncludesNonceStoresNonce(): void
    {
        $this->createFactory(nonceStorage: true, nonceStorageKeyFactory: true);

        $jwk = $this->createStub(JwkInterface::class);

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
            ->with($jwk, 'https://example.com/path')
            ->willReturn('storageKey');

        $this->nonceStorage->expects($this->once())
            ->method('storeNextNonce')
            ->with('storageKey', 'nonceValue');

        $this->factory->storeNextNonceFromResponse($response, $request, $jwk);
    }

    #[Test]
    public function storeNextNonceFromResponseIncludesNonceAndQueryParameterStoresNonce(): void
    {
        $this->createFactory(nonceStorage: true, nonceStorageKeyFactory: true);

        $jwk = $this->createStub(JwkInterface::class);

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
            ->with($jwk, 'https://example.com/path')
            ->willReturn('storageKey');

        $this->nonceStorage->expects($this->once())
            ->method('storeNextNonce')
            ->with('storageKey', 'nonceValue');

        $this->factory->storeNextNonceFromResponse($response, $request, $jwk);
    }

    #[Test]
    public function createProofBoundToAccessTokenUnsupportedJktThrowsException(): void
    {
        $this->createFactory(encoder: true);

        $accessToken = new AccessTokenModel('abc', 'def');

        $e = $this->createStub(MissingDPoPJwkException::class);

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['ES256'], 'def')
            ->willThrowException($e);

        $this->expectExceptionObject($e);

        $this->factory->createProof(self::HTM, self::HTU, ['ES256'], $accessToken);
    }

    #[Test]
    public function createProofBoundToUnsupportedJktThrowsException(): void
    {
        $this->createFactory(encoder: true);

        $e = $this->createStub(MissingDPoPJwkException::class);

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['ES256K'], 'jkt')
            ->willThrowException($e);

        $this->expectExceptionObject($e);

        $this->factory->createProof(self::HTM, self::HTU, ['ES256K'], 'jkt');
    }

    #[Test]
    public function createProofUnsupportedAlgorithmsThrowsException(): void
    {
        $this->createFactory(encoder: true);

        $e = $this->createStub(MissingDPoPJwkException::class);

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['EdDSA'], null)
            ->willThrowException($e);

        $this->expectExceptionObject($e);

        $this->factory->createProof(self::HTM, self::HTU, ['EdDSA']);
    }

    #[Test]
    public function createProofBoundToNothingCheckPayload(): void
    {
        $this->createFactory(encoder: true);

        $jwk = $this->createMock(JwkInterface::class);
        $jwk->expects($this->atLeastOnce())
            ->method('toPublic')
            ->willReturn(['kid' => 'kid', 'crv' => 'P-128']);

        $jwk->expects($this->atLeastOnce())
            ->method('algorithm')
            ->willReturn('ES256');

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['ES256'], null)
            ->willReturn($jwk);

        $this->encoder->expects($this->once())
            ->method('createProof')
            ->with($jwk, $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('htm', $value);
                $this->assertEquals(self::HTM, $value['htm']);

                $this->assertArrayHasKey('htu', $value);
                $this->assertEquals(self::HTU, $value['htu']);

                $this->assertArrayHasKey('iat', $value);
                $this->assertEquals($this->clock->now()->getTimestamp(), $value['iat']);

                $this->assertArrayHasKey('jti', $value);
                $this->assertIsString($value['jti']);
                $this->assertTrue(\strlen($value['jti']) === (self::JTI_LENGTH * 2));

                $this->assertArrayNotHasKey('ath', $value);

                return true;
            }), $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('typ', $value);
                $this->assertEquals('dpop+jwt', $value['typ']);

                $this->assertArrayHasKey('alg', $value);
                $this->assertEquals('ES256', $value['alg']);

                $this->assertArrayHasKey('jwk', $value);
                $this->assertEquals(['kid' => 'kid', 'crv' => 'P-128'], $value['jwk']);

                return true;
            }))
            ->willReturn('dpop.proof');

        $returnValue = $this->factory->createProof(self::HTM, self::HTU, ['ES256']);

        $this->assertEquals($jwk, $returnValue->jwk);
        $this->assertEquals('dpop.proof', $returnValue->proof);
    }

    #[Test]
    public function createProofBoundToJktCheckPayload(): void
    {
        $this->createFactory(encoder: true);

        $jwk = $this->createMock(JwkInterface::class);
        $jwk->expects($this->atLeastOnce())
            ->method('toPublic')
            ->willReturn(['kid' => 'keyId', 'crv' => 'P-256']);

        $jwk->expects($this->atLeastOnce())
            ->method('algorithm')
            ->willReturn('ES256');

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['ES256'], 'acbjkt')
            ->willReturn($jwk);

        $this->encoder->expects($this->once())
            ->method('createProof')
            ->with($jwk, $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('htm', $value);
                $this->assertEquals(self::HTM, $value['htm']);

                $this->assertArrayHasKey('htu', $value);
                $this->assertEquals(self::HTU, $value['htu']);

                $this->assertArrayHasKey('iat', $value);
                $this->assertEquals($this->clock->now()->getTimestamp(), $value['iat']);

                $this->assertArrayHasKey('jti', $value);
                $this->assertIsString($value['jti']);
                $this->assertTrue(\strlen($value['jti']) === (self::JTI_LENGTH * 2));

                $this->assertArrayNotHasKey('ath', $value);

                return true;
            }), $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('typ', $value);
                $this->assertEquals('dpop+jwt', $value['typ']);

                $this->assertArrayHasKey('alg', $value);
                $this->assertEquals('ES256', $value['alg']);

                $this->assertArrayHasKey('jwk', $value);
                $this->assertEquals(['kid' => 'keyId', 'crv' => 'P-256'], $value['jwk']);

                return true;
            }))
            ->willReturn('dpop.proof');

        $returnValue = $this->factory->createProof(self::HTM, self::HTU, ['ES256'], 'acbjkt');

        $this->assertEquals($jwk, $returnValue->jwk);
        $this->assertEquals('dpop.proof', $returnValue->proof);
    }

    #[Test]
    public function createProofBoundToAccessTokenAddsAthToPayload(): void
    {
        $this->createFactory(encoder: true);

        $accessToken = new AccessTokenModel('123456', 'def');

        $jwk = $this->createMock(JwkInterface::class);
        $jwk->expects($this->atLeastOnce())
            ->method('toPublic')
            ->willReturn(['kid' => 'keyId', 'crv' => 'P-256']);

        $jwk->expects($this->atLeastOnce())
            ->method('algorithm')
            ->willReturn('ES256');

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['ES256'], 'def')
            ->willReturn($jwk);

        $this->encoder->expects($this->once())
            ->method('createProof')
            ->with($jwk, $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('htm', $value);
                $this->assertEquals(self::HTM, $value['htm']);

                $this->assertArrayHasKey('htu', $value);
                $this->assertEquals(self::HTU, $value['htu']);

                $this->assertArrayHasKey('iat', $value);
                $this->assertEquals($this->clock->now()->getTimestamp(), $value['iat']);

                $this->assertArrayHasKey('jti', $value);
                $this->assertIsString($value['jti']);
                $this->assertTrue(\strlen($value['jti']) === (self::JTI_LENGTH * 2));

                $this->assertArrayHasKey('ath', $value);
                $this->assertEquals('jZae727K08KaOmKSgOaGzww_XVqGr_PKEgIMkjrcbJI', $value['ath']);

                return true;
            }), $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('typ', $value);
                $this->assertEquals('dpop+jwt', $value['typ']);

                $this->assertArrayHasKey('alg', $value);
                $this->assertEquals('ES256', $value['alg']);

                $this->assertArrayHasKey('jwk', $value);
                $this->assertEquals(['kid' => 'keyId', 'crv' => 'P-256'], $value['jwk']);

                return true;
            }))
            ->willReturn('dpop.proof');

        $returnValue = $this->factory->createProof(self::HTM, self::HTU, ['ES256'], $accessToken);

        $this->assertEquals($jwk, $returnValue->jwk);
        $this->assertEquals('dpop.proof', $returnValue->proof);
    }

    #[Test]
    public function createProofHasStoredNonceAddsNonceToPayload(): void
    {
        $this->createFactory(encoder: true, nonceStorage: true, nonceStorageKeyFactory: true);

        $jwk = $this->createMock(JwkInterface::class);
        $jwk->expects($this->atLeastOnce())
            ->method('toPublic')
            ->willReturn(['kid' => 'keyId', 'crv' => 'P-256']);

        $jwk->expects($this->atLeastOnce())
            ->method('algorithm')
            ->willReturn('ES256');

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['ES256'], null)
            ->willReturn($jwk);

        $this->nonceStorageKeyFactory->expects($this->once())
            ->method('createKey')
            ->with($jwk, self::HTU)
            ->willReturn('key');

        $this->nonceStorage->expects($this->once())
            ->method('getCurrentNonce')
            ->with('key')
            ->willReturn('storedNonce');

        $this->encoder->expects($this->once())
            ->method('createProof')
            ->with($jwk, $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('htm', $value);
                $this->assertEquals(self::HTM, $value['htm']);

                $this->assertArrayHasKey('htu', $value);
                $this->assertEquals(self::HTU, $value['htu']);

                $this->assertArrayHasKey('iat', $value);
                $this->assertEquals($this->clock->now()->getTimestamp(), $value['iat']);

                $this->assertArrayHasKey('jti', $value);
                $this->assertIsString($value['jti']);
                $this->assertTrue(\strlen($value['jti']) === (self::JTI_LENGTH * 2));

                $this->assertArrayHasKey('nonce', $value);
                $this->assertEquals('storedNonce', $value['nonce']);

                $this->assertArrayNotHasKey('ath', $value);

                return true;
            }), $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('typ', $value);
                $this->assertEquals('dpop+jwt', $value['typ']);

                $this->assertArrayHasKey('alg', $value);
                $this->assertEquals('ES256', $value['alg']);

                $this->assertArrayHasKey('jwk', $value);
                $this->assertEquals(['kid' => 'keyId', 'crv' => 'P-256'], $value['jwk']);

                return true;
            }))
            ->willReturn('dpop.proof');

        $returnValue = $this->factory->createProof(self::HTM, self::HTU, ['ES256']);

        $this->assertEquals($jwk, $returnValue->jwk);
        $this->assertEquals('dpop.proof', $returnValue->proof);
    }

    #[Test]
    public function createProofHtiIsTransformed(): void
    {
        $this->createFactory(encoder: true, nonceStorageKeyFactory: true);

        $jwk = $this->createStub(JwkInterface::class);

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['ES256'], null)
            ->willReturn($jwk);

        $this->nonceStorageKeyFactory->expects($this->once())
            ->method('createKey')
            ->with($jwk, self::HTU)
            ->willReturn('key');

        $this->encoder->expects($this->once())
            ->method('createProof')
            ->with($jwk, $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('htu', $value);
                $this->assertEquals(self::HTU, $value['htu']);

                return true;
            }))
            ->willReturn('dpop.proof');

        $returnValue = $this->factory->createProof(self::HTM, self::HTU.'?query=a#fragment', ['ES256']);

        $this->assertEquals($jwk, $returnValue->jwk);
        $this->assertEquals('dpop.proof', $returnValue->proof);
    }

    #[Test]
    public function createProofFromRequestReturnsProof(): void
    {
        $this->createFactory(encoder: true, nonceStorageKeyFactory: true);

        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method('getMethod')
            ->willReturn(self::HTM);

        $uri = $this->createMock(UriInterface::class);
        $uri->expects($this->once())
            ->method('__toString')
            ->willReturn(self::HTU.'?query=1#fragment');

        $request->expects($this->once())
            ->method('getUri')
            ->willReturn($uri);

        $jwk = $this->createStub(JwkInterface::class);

        $this->encoder->expects($this->once())
            ->method('selectJWK')
            ->with(['ES256'], null)
            ->willReturn($jwk);

        $this->nonceStorageKeyFactory->expects($this->once())
            ->method('createKey')
            ->with($jwk, self::HTU)
            ->willReturn('key');

        $this->encoder->expects($this->once())
            ->method('createProof')
            ->with($jwk, $this->callback(function (mixed $value): bool {
                $this->assertIsArray($value);

                $this->assertArrayHasKey('htu', $value);
                $this->assertEquals(self::HTU, $value['htu']);

                return true;
            }))
            ->willReturn('dpop.proof');

        $returnValue = $this->factory->createProofFromRequest($request, ['ES256']);

        $this->assertEquals($jwk, $returnValue->jwk);
        $this->assertEquals('dpop.proof', $returnValue->proof);
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
