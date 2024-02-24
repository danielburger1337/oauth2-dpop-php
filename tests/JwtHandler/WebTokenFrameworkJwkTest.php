<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests\JwtHandler;

use danielburger1337\OAuth2DPoP\JwtHandler\WebTokenFrameworkJwk;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(WebTokenFrameworkJwk::class)]
class WebTokenFrameworkJwkTest extends TestCase
{
    #[Test]
    public function toPublic_returnsPublicKey(): void
    {
        $jwk = JWKFactory::createECKey('P-256');

        $model = new WebTokenFrameworkJwk($jwk, new ES256());
        $this->assertEquals($jwk->toPublic()->jsonSerialize(), $model->toPublic());
    }
}
