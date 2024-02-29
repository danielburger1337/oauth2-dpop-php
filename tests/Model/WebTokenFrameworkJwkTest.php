<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests\Model;

use danielburger1337\OAuth2\DPoP\Model\WebTokenFrameworkJwk;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(WebTokenFrameworkJwk::class)]
class WebTokenFrameworkJwkTest extends TestCase
{
    private const JWK = '{"kty":"EC","crv":"P-256","d":"sEMeoG1U6USSiJdVw1J33P0OJMo0wyUuFbbWaoJ7Zt4","x":"NiQqdaWrDMjDsHhZorjo7jl0Fwvvn-ZMnRUjKHYAjrU","y":"zFVN2ZRaQk74tAtMnnLBr-_w0v3SszrB3NsVsOHVtg0"}';
    private const JWK_PUBLIC = '{"kty":"EC","crv":"P-256","x":"NiQqdaWrDMjDsHhZorjo7jl0Fwvvn-ZMnRUjKHYAjrU","y":"zFVN2ZRaQk74tAtMnnLBr-_w0v3SszrB3NsVsOHVtg0"}';
    private const JKT = 'u-OgFMUQNFo0PC7x32Il3T_n_FOgRrUZJj4DA9LKy3M';

    #[Test]
    public function thumbprint_privateKey_returnsSha256Thumbprint(): void
    {
        $jwk = JWKFactory::createFromJsonObject(self::JWK);
        $this->assertInstanceOf(JWK::class, $jwk);

        $model = new WebTokenFrameworkJwk($jwk, self::JKT, new ES256());

        $returnValue = $model->thumbprint();

        $this->assertEquals(self::JKT, $returnValue);
    }

    #[Test]
    public function thumbprint_publicKey_returnsSha256Thumbprint(): void
    {
        $jwk = JWKFactory::createFromJsonObject(self::JWK_PUBLIC);
        $this->assertInstanceOf(JWK::class, $jwk);

        $model = new WebTokenFrameworkJwk($jwk, self::JKT, new ES256());

        $returnValue = $model->thumbprint();

        $this->assertEquals(self::JKT, $returnValue);
    }

    #[Test]
    public function toPublic_privateKey_returnsPublicKey(): void
    {
        $jwk = JWKFactory::createFromJsonObject(self::JWK);
        $this->assertInstanceOf(JWK::class, $jwk);

        $model = new WebTokenFrameworkJwk($jwk, self::JKT, new ES256());

        $returnValue = $model->toPublic();

        $this->assertEquals(\json_decode(self::JWK_PUBLIC, true, flags: \JSON_THROW_ON_ERROR), $returnValue);
    }

    #[Test]
    public function toPublic_publicKey_returnsPublicKey(): void
    {
        $jwk = JWKFactory::createFromJsonObject(self::JWK_PUBLIC);
        $this->assertInstanceOf(JWK::class, $jwk);

        $model = new WebTokenFrameworkJwk($jwk, self::JKT, new ES256());

        $returnValue = $model->toPublic();

        $this->assertEquals(\json_decode(self::JWK_PUBLIC, true, flags: \JSON_THROW_ON_ERROR), $returnValue);
    }

    #[Test]
    #[DataProvider('algoritmDataProvider')]
    public function algorithm_returnsAlgorithmName(Algorithm $algorithm, string $expected): void
    {
        $jwk = JWKFactory::createFromJsonObject(self::JWK_PUBLIC);
        $this->assertInstanceOf(JWK::class, $jwk);

        $model = new WebTokenFrameworkJwk($jwk, self::JKT, $algorithm);

        $returnValue = $model->algorithm();

        $this->assertEquals($expected, $returnValue);
    }

    /**
     * @return array<array{0: Algorithm, 1: string}>
     */
    public static function algoritmDataProvider(): array
    {
        return [
            [new ES256(), 'ES256'],
            [new EdDSA(), 'EdDSA'],
            [new RS256(), 'RS256'],
        ];
    }
}
