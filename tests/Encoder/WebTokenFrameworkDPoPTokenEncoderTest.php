<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests\Encoder;

use danielburger1337\OAuth2\DPoP\Encoder\WebTokenFrameworkDPoPTokenEncoder;
use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2\DPoP\Model\JwkInterface;
use danielburger1337\OAuth2\DPoP\Model\WebTokenFrameworkJwk;
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
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'K_grY8EYPtGtXkQ7CCXru3zi5SApi33gaZit1lxOhws',
        'y' => 'kU_N4_T4y_M5SEmJwILgvd7Gnj_ckyljLO2FsVGXVTM',
    ];

    private JWK $jwk;
    private JWKSet $jwkSet;
    private AlgorithmManager $algorithmManager;

    private WebTokenFrameworkDPoPTokenEncoder $encoder;

    protected function setUp(): void
    {
        // @phpstan-ignore-next-line assign.propertyType
        $this->jwk = JWKFactory::createFromValues([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'E6luNsWvQPVZkgkTMj6hDYz6Vi7nxvujGCBOe7DdMrc',
            'x' => 'K_grY8EYPtGtXkQ7CCXru3zi5SApi33gaZit1lxOhws',
            'y' => 'kU_N4_T4y_M5SEmJwILgvd7Gnj_ckyljLO2FsVGXVTM',
        ]);

        $this->jwkSet = new JWKSet([$this->jwk]);

        $this->algorithmManager = new AlgorithmManager([new ES256(), new RS256()]);

        $this->encoder = new WebTokenFrameworkDPoPTokenEncoder($this->jwkSet, $this->algorithmManager);
    }

    #[Test]
    public function constructJwkCreatesJWKSet(): void
    {
        $this->expectNotToPerformAssertions();

        new WebTokenFrameworkDPoPTokenEncoder($this->jwk, $this->algorithmManager);
    }

    #[Test]
    public function selectJWKSupportedAlgorithmReturnsJwk(): void
    {
        $returnValue = $this->encoder->selectJWK(['ES256']);

        $this->assertInstanceOf(WebTokenFrameworkJwk::class, $returnValue);

        $this->assertEquals(self::JKT, $returnValue->thumbprint());
        $this->assertEquals(self::JWK_PUBLIC, $returnValue->toPublic());
    }

    #[Test]
    public function selectJWKSupportedAlgorithmWithJwkReturnsJwk(): void
    {
        $returnValue = $this->encoder->selectJWK(['ES256', 'EdDSA']);

        $this->assertInstanceOf(WebTokenFrameworkJwk::class, $returnValue);

        $this->assertEquals(self::JKT, $returnValue->thumbprint());
        $this->assertEquals(self::JWK_PUBLIC, $returnValue->toPublic());
    }

    #[Test]
    public function selectJWKSupportedAlgorithmWithoutJwkThrowsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK for the supported DPoP algorithms "RS256".');

        $this->encoder->selectJWK(['RS256']);
    }

    #[Test]
    public function selectJWKSupportedAlgorithmWithJKTWithoutJwkThrowsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK with the "'.self::JKT.'" JKT that supports the "RS256" DPoP algorithms.');

        $this->encoder->selectJWK(['RS256'], self::JKT);
    }

    #[Test]
    public function selectJWKSupportedAlgorithmWithMultipleKeysReturnsJKTMatch(): void
    {
        $jwkSet = $this->jwkSet->with(JWKFactory::createECKey('P-256'));

        $encoder = new WebTokenFrameworkDPoPTokenEncoder($jwkSet, $this->algorithmManager);

        $returnValue = $encoder->selectJWK(['ES256'], self::JKT);

        $this->assertInstanceOf(WebTokenFrameworkJwk::class, $returnValue);

        $this->assertEquals(self::JKT, $returnValue->thumbprint());
        $this->assertEquals(self::JWK_PUBLIC, $returnValue->toPublic());
    }

    #[Test]
    public function selectJWKEmptyServerSupportedAlgorithmsThrowsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK for the supported DPoP algorithms "".');

        $this->encoder->selectJWK([]);
    }

    #[Test]
    public function selectJWKEmptyServerSupportedAlgorithmsWithJKTThrowsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK with the "'.self::JKT.'" JKT that supports the "" DPoP algorithms.');

        $this->encoder->selectJWK([], self::JKT);
    }

    #[Test]
    public function selectJWKUnsupportedAlgorithmThrowsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK for the supported DPoP algorithms "EdDSA".');

        $this->encoder->selectJWK(['EdDSA']);
    }

    #[Test]
    public function selectJWKUnsupportedAlgorithmWithJktThrowsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a JWK with the "'.self::JKT.'" JKT that supports the "EdDSA" DPoP algorithms.');

        $this->encoder->selectJWK(['EdDSA'], self::JKT);
    }

    #[Test]
    public function createProofUnsupportedJwkThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->encoder->createProof($this->createStub(JwkInterface::class), [], []);
    }

    #[Test]
    public function createProofProtectedHeaderNoAlgThrowsException(): void
    {
        // this SHOULD (and currently is) be enforced by the JWT library
        // keep this in case of regressions
        $this->expectException(\InvalidArgumentException::class);

        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());
        $this->encoder->createProof($jwk, [], []);
    }

    #[Test]
    public function createProofProtectedHeaderEmptyAlgThrowsException(): void
    {
        // this SHOULD (and currently is) be enforced by the JWT library
        // keep this in case of regressions
        $this->expectException(\InvalidArgumentException::class);

        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());
        $this->encoder->createProof($jwk, [], ['alg' => '']);
    }

    #[Test]
    public function createProofProtectedHeaderNullAlgThrowsException(): void
    {
        // this SHOULD (and currently is) be enforced by the JWT library
        // keep this in case of regressions
        $this->expectException(\InvalidArgumentException::class);

        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());
        $this->encoder->createProof($jwk, [], ['alg' => null]);
    }

    #[Test]
    public function createProofProtectedHeaderContainsExtraKeys(): void
    {
        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());

        $returnValue = $this->encoder->createProof($jwk, [], ['alg' => 'ES256', 'headerParam' => 'value']);

        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[0]));

        $this->assertIsArray($protectedHeader);
        $this->assertArrayHasKey('headerParam', $protectedHeader);
        $this->assertEquals('value', $protectedHeader['headerParam']);
    }

    #[Test]
    public function createProofPayloadIsEncoded(): void
    {
        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());

        $payload = ['claim' => 'value', 'claim2' => 'value2'];

        $returnValue = $this->encoder->createProof($jwk, $payload, ['alg' => 'ES256', 'headerParam' => 'value']);

        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[0]));

        $this->assertIsArray($protectedHeader);
        $this->assertArrayHasKey('headerParam', $protectedHeader);
        $this->assertEquals('value', $protectedHeader['headerParam']);

        $decodedPayload = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(\explode('.', $returnValue)[1]));

        $this->assertIsArray($decodedPayload);
        $this->assertEquals($payload, $decodedPayload);
    }

    #[Test]
    public function createProofIsSignedJwt(): void
    {
        $jwk = new WebTokenFrameworkJwk($this->jwk, $this->jwk->thumbprint('sha256'), new ES256());

        $payload = ['claim' => 'value', 'claim2' => 'value2'];

        $returnValue = $this->encoder->createProof($jwk, $payload, ['alg' => 'ES256', 'headerParam' => 'value']);

        $jwsLoader = new JWSLoader(new JWSSerializerManager([new CompactSerializer()]), new JWSVerifier($this->algorithmManager), new HeaderCheckerManager([new AlgorithmChecker($this->algorithmManager->list())], [new JWSTokenSupport()]));

        $jws = $jwsLoader->loadAndVerifyWithKey($returnValue, $this->jwk, $idx);
        if (null === $idx) {
            throw new \RuntimeException('Impossible to reach codepath');
        }
        $signature = $jws->getSignature($idx);

        $this->assertEquals(['alg' => 'ES256', 'headerParam' => 'value'], $signature->getProtectedHeader());

        $this->assertEquals($payload, JsonConverter::decode($jws->getPayload() ?? ''));
    }
}
