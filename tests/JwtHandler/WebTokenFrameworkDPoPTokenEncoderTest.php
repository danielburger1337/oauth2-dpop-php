<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP;

use danielburger1337\OAuth2DPoP\Encoder\WebTokenFrameworkDPoPTokenEncoder;
use danielburger1337\OAuth2DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2DPoP\Model\JwkInterface;
use danielburger1337\OAuth2DPoP\Model\WebTokenFrameworkJwk;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(WebTokenFrameworkDPoPTokenEncoder::class)]
class WebTokenFrameworkDPoPTokenEncoderTest extends TestCase
{
    private const JKT = 'YhSb0W8aR6ZnO1gKJOWF2arpHk8QgwmUqvU2jgo_wkw';
    private const JWK_PUBLIC = [
        'kid' => 'dpopkey',
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'K_grY8EYPtGtXkQ7CCXru3zi5SApi33gaZit1lxOhws',
        'y' => 'kU_N4_T4y_M5SEmJwILgvd7Gnj_ckyljLO2FsVGXVTM',
    ];

    private JWK $jwk;
    private JWKSet $jwkSet;
    private AlgorithmManager $algorithmManager;

    private WebTokenFrameworkDPoPTokenEncoder $jwtHandler;

    protected function setUp(): void
    {
        // @phpstan-ignore-next-line
        $this->jwk = JWKFactory::createFromValues([
            'kid' => 'dpopkey',
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'E6luNsWvQPVZkgkTMj6hDYz6Vi7nxvujGCBOe7DdMrc',
            'x' => 'K_grY8EYPtGtXkQ7CCXru3zi5SApi33gaZit1lxOhws',
            'y' => 'kU_N4_T4y_M5SEmJwILgvd7Gnj_ckyljLO2FsVGXVTM',
        ]);

        // @phpstan-ignore-next-line
        $this->jwkSet = new JWKSet([$this->jwk]);

        $this->algorithmManager = new AlgorithmManager([new ES256(), new RS256()]);

        $this->jwtHandler = new WebTokenFrameworkDPoPTokenEncoder($this->jwkSet, $this->algorithmManager);
    }

    #[Test]
    public function __construct_jwk_createsJWKSet(): void
    {
        $this->expectNotToPerformAssertions();

        new WebTokenFrameworkDPoPTokenEncoder($this->jwk, $this->algorithmManager);
    }

    #[Test]
    public function selectJWK_supportedAlgorithm_returnsJwk(): void
    {
        $returnValue = $this->jwtHandler->selectJWK(['ES256']);

        $this->assertInstanceOf(WebTokenFrameworkJwk::class, $returnValue);

        $this->assertEquals(self::JKT, $returnValue->thumbprint());
        $this->assertEquals(self::JWK_PUBLIC, $returnValue->toPublic());
    }

    #[Test]
    public function selectJWK_supportedAlgorithmWithJwk_returnsJwk(): void
    {
        $returnValue = $this->jwtHandler->selectJWK(['ES256', 'EdDSA']);

        $this->assertInstanceOf(WebTokenFrameworkJwk::class, $returnValue);

        $this->assertEquals(self::JKT, $returnValue->thumbprint());
        $this->assertEquals(self::JWK_PUBLIC, $returnValue->toPublic());
    }

    #[Test]
    public function selectJWK_supportedAlgorithmWithoutJwk_throwsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK for the supported DPoP algorithms "RS256".');

        $this->jwtHandler->selectJWK(['RS256']);
    }

    #[Test]
    public function selectJWK_supportedAlgorithmWithJKTWithoutJwk_throwsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK with the "'.self::JKT.'" JKT that supports the "RS256" DPoP algorithms.');

        $this->jwtHandler->selectJWK(['RS256'], self::JKT);
    }

    #[Test]
    public function selectJWK_supportedAlgorithmWithMultipleKeys_returnsJKTMatch(): void
    {
        $jwkSet = $this->jwkSet->with(JWKFactory::createECKey('P-256'));

        $handler = new WebTokenFrameworkDPoPTokenEncoder($jwkSet, $this->algorithmManager);

        $returnValue = $handler->selectJWK(['ES256'], self::JKT);

        $this->assertInstanceOf(WebTokenFrameworkJwk::class, $returnValue);

        $this->assertEquals(self::JKT, $returnValue->thumbprint());
        $this->assertEquals(self::JWK_PUBLIC, $returnValue->toPublic());
    }

    #[Test]
    public function selectJWK_emptyServerSupportedAlgorithms_throwsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK for the supported DPoP algorithms "".');

        $this->jwtHandler->selectJWK([]);
    }

    #[Test]
    public function selectJWK_emptyServerSupportedAlgorithmsWithJKT_throwsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK with the "'.self::JKT.'" JKT that supports the "" DPoP algorithms.');

        $this->jwtHandler->selectJWK([], self::JKT);
    }

    #[Test]
    public function selectJWK_unsupportedAlgorithm_throwsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK for the supported DPoP algorithms "EdDSA".');

        $this->jwtHandler->selectJWK(['EdDSA']);
    }

    #[Test]
    public function selectJWK_unsupportedAlgorithmWithJkt_throwsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK with the "'.self::JKT.'" JKT that supports the "EdDSA" DPoP algorithms.');

        $this->jwtHandler->selectJWK(['EdDSA'], self::JKT);
    }

    #[Test]
    public function createProof_unsupportedJwk_throwsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->jwtHandler->createProof($this->createStub(JwkInterface::class), [], []);
    }

    #[Test]
    public function createProof_protectedHeader_algIsSet(): void
    {
        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());

        $returnValue = $this->jwtHandler->createProof($jwk, [], []);

        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[0]));

        $this->assertIsArray($protectedHeader);
        $this->assertArrayHasKey('alg', $protectedHeader);
        $this->assertEquals('ES256', $protectedHeader['alg']);
    }

    #[Test]
    public function createProof_protectedHeader_crvIsSet(): void
    {
        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());

        $returnValue = $this->jwtHandler->createProof($jwk, [], []);

        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[0]));

        $this->assertIsArray($protectedHeader);
        $this->assertArrayHasKey('crv', $protectedHeader);
        $this->assertEquals('P-256', $protectedHeader['crv']);
    }

    #[Test]
    public function createProof_protectedHeader_crvIsNotSet(): void
    {
        $jwk = JWKFactory::createRSAKey(1024);
        $this->assertInstanceOf(JWK::class, $jwk);

        $jwk = new WebTokenFrameworkJwk($jwk, $jwk->thumbprint('sha256'), new RS256());

        $returnValue = $this->jwtHandler->createProof($jwk, [], []);

        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[0]));

        $this->assertIsArray($protectedHeader);
        $this->assertArrayNotHasKey('crv', $protectedHeader);
    }

    #[Test]
    public function createProof_protectedHeader_kidIsSet(): void
    {
        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());

        $returnValue = $this->jwtHandler->createProof($jwk, [], []);

        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[0]));

        $this->assertIsArray($protectedHeader);
        $this->assertArrayHasKey('kid', $protectedHeader);
        $this->assertEquals('dpopkey', $protectedHeader['kid']);
    }

    #[Test]
    public function createProof_protectedHeader_kidIsNotSet(): void
    {
        $jwk = JWKFactory::createRSAKey(1024);
        $this->assertInstanceOf(JWK::class, $jwk);

        $jwk = new WebTokenFrameworkJwk($jwk, $jwk->thumbprint('sha256'), new RS256());

        $returnValue = $this->jwtHandler->createProof($jwk, [], []);

        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[0]));

        $this->assertIsArray($protectedHeader);
        $this->assertArrayNotHasKey('kid', $protectedHeader);
    }

    #[Test]
    public function createProof_protectedHeader_containsExtraKeys(): void
    {
        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());

        $returnValue = $this->jwtHandler->createProof($jwk, [], ['headerParam' => 'value']);

        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[0]));

        $this->assertIsArray($protectedHeader);
        $this->assertArrayHasKey('headerParam', $protectedHeader);
        $this->assertEquals('value', $protectedHeader['headerParam']);
    }

    #[Test]
    public function createProof_payload_isEncoded(): void
    {
        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());

        $payload = ['claim' => 'value', 'claim2' => 'value2'];

        $returnValue = $this->jwtHandler->createProof($jwk, $payload, ['headerParam' => 'value']);

        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[0]));

        $this->assertIsArray($protectedHeader);
        $this->assertArrayHasKey('headerParam', $protectedHeader);
        $this->assertEquals('value', $protectedHeader['headerParam']);

        $decodedPayload = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[1]));

        $this->assertIsArray($decodedPayload);
        $this->assertEquals($payload, $decodedPayload);
    }

    #[Test]
    public function createProof_isSignedJwt(): void
    {
        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());

        $payload = ['claim' => 'value', 'claim2' => 'value2'];

        $returnValue = $this->jwtHandler->createProof($jwk, $payload, ['headerParam' => 'value']);

        $jwsLoader = new JWSLoader(new JWSSerializerManager([new CompactSerializer()]), new JWSVerifier($this->algorithmManager), new HeaderCheckerManager([new AlgorithmChecker($this->algorithmManager->list())], [new JWSTokenSupport()]));

        $jws = $jwsLoader->loadAndVerifyWithKey($returnValue, $this->jwk, $idx);
        $signature = $jws->getSignature($idx);

        $this->assertEquals(['alg' => 'ES256', 'kid' => 'dpopkey', 'crv' => 'P-256', 'headerParam' => 'value'], $signature->getProtectedHeader());

        $this->assertEquals($payload, JsonConverter::decode($jws->getPayload() ?? ''));
    }
}
