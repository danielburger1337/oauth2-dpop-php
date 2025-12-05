<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests\NonceFactory;

use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2\DPoP\NonceFactory\WebTokenFrameworkNonceFactory;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

#[CoversClass(WebTokenFrameworkNonceFactory::class)]
class WebTokenFrameworkNonceFactoryTest extends TestCase
{
    private const JKT = 'key';

    private const SECRET = 'abcdefghijklmnopqrstuvwxyz1234567';
    private const TTL = 'PT5M';
    private const ALLOWED_TIME_DRIFT = 5;

    private WebTokenFrameworkNonceFactory $nonceFactory;

    private MockClock $clock;
    private JWK $jwk;
    private Algorithm $algorithm;

    #[\Override]
    protected function setUp(): void
    {
        // important: do not change time, otherwise expected tokens dont work
        $this->clock = new MockClock('2024-02-26 16:39:42');

        $this->jwk = JWKFactory::createFromSecret(self::SECRET);
        $this->algorithm = new HS256();

        $this->nonceFactory = new WebTokenFrameworkNonceFactory(
            $this->algorithm,
            new JWKSet([$this->jwk]),
            $this->clock,
            new \DateInterval(self::TTL),
            self::ALLOWED_TIME_DRIFT
        );
    }

    #[Test]
    public function createNewNonceIfInvalidCreatedNonceReturnsNull(): void
    {
        // simple dummy test that the result of "createNewNonce" is accepted as valid

        $nonce = $this->nonceFactory->createNewNonce(self::JKT);

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);

        $this->assertNull($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidInvalidJwtCreatesNewNonce(): void
    {
        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, 'not a jwt');

        $this->assertIsValidNonce($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidValidNonceReturnsNull(): void
    {
        // issued now, expires in 5 minutes
        // {"typ":"dpop+none","alg":"HS256"}.{"iat":1708965582,"exp":1708965882}
        $nonce = 'eyJ0eXAiOiJkcG9wK25vbmNlIiwiYWxnIjoiSFMyNTYifQ.eyJpYXQiOjE3MDg5NjU1ODIsImV4cCI6MTcwODk2NTg4Mn0.Ilf1Ji1jecVSQlO8uU7TR435fWUvejGrWkXTi1F7bDY';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);

        $this->assertNull($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidExpiredNonceWithinTimeDriftReturnsTrue(): void
    {
        // issued 1 minute ago, expired 3 seconds ago
        // {"typ":"dpop+none","alg":"HS256"}.{"iat":1708965522,"exp":1708965579}
        $nonce = 'eyJ0eXAiOiJkcG9wK25vbmNlIiwiYWxnIjoiSFMyNTYifQ.eyJpYXQiOjE3MDg5NjU1MjIsImV4cCI6MTcwODk2NTU3OX0.PS9D1EAz3i9v55q5LcE9Et4GNfhiyNLp42--T8F0vjk';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);

        $this->assertNull($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidExpiredNonceCreatesNewNonce(): void
    {
        // issued 1 minute ago, expired 10 seconds ago
        // {"typ":"dpop+none","alg":"HS256"}.{"iat":1708965522,"exp":1708965572}
        $nonce = 'eyJ0eXAiOiJkcG9wK25vbmNlIiwiYWxnIjoiSFMyNTYifQ.eyJpYXQiOjE3MDg5NjU1MjIsImV4cCI6MTcwODk2NTU3Mn0.JE8ktw_FRedEEfCOvNibrF20HM8E_x2T24GVHAsX-j4';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);

        $this->assertIsValidNonce($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidInvalidSignatureCreatesNewNonce(): void
    {
        // issued now, expires in 5 minutes, signed with \strrev(self::SECRET)
        // {"typ":"dpop+none","alg":"HS256"}.{"iat":1708965582,"exp":1708965882}
        $nonce = 'eyJ0eXAiOiJkcG9wK25vbmNlIiwiYWxnIjoiSFMyNTYifQ.eyJpYXQiOjE3MDg5NjU1ODIsImV4cCI6MTcwODk2NTg4Mn0.yXFg9Ci5TJ52Wlu0YlRLlGfeoNYzvuLSSc45itTe78E';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);
        $this->assertIsValidNonce($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidUnsupportedAlgorithmCreatesNewNonce(): void
    {
        // issued now, expires in 5 minutes
        // {"typ":"dpop+none","alg":"ES256"}.{"iat":1708965582,"exp":1708965882}
        $nonce = 'eyJ0eXAiOiJkcG9wK25vbmNlIiwiYWxnIjoiRVMyNTYifQ.eyJpYXQiOjE3MDg5NjU1ODIsImV4cCI6MTcwODk2NTg4Mn0.QIl-pVKCn3FnNGnu6XBKR5twC8NMX-ZgD7EMUrkQgjqrWkvo6_qtaRHMlzw7hHhYRg0Upo1wnsBP3BouNT4zAA';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);
        $this->assertIsValidNonce($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidMissingTypHeaderCreatesNewNonce(): void
    {
        // issued now, expires in 5 minutes
        // {"alg":"HS256"}.{"iat":1708965582,"exp":1708965882}
        $nonce = 'eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3MDg5NjU1ODIsImV4cCI6MTcwODk2NTg4Mn0.ZbeAmXvsc1mXerJhTyvYWB5cLf-svnM4S5vxGjOtGDc';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);
        $this->assertIsValidNonce($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidInvalidTypHeaderCreatesNewNonce(): void
    {
        // issued now, expires in 5 minutes
        // {"typ":"nonce+dpop","alg":"HS256"}.{"iat":1708965582,"exp":1708965882}
        $nonce = 'eyJ0eXAiOiJub25jZStkcG9wIiwiYWxnIjoiSFMyNTYifQ.eyJpYXQiOjE3MDg5NjU1ODIsImV4cCI6MTcwODk2NTg4Mn0.qLHrXQ6yYZa3HKZKPW5iHur9AY5E2MoIDc5NMtgSC-A';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);
        $this->assertIsValidNonce($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidInvalidPayloadCreatesNewNonce(): void
    {
        // issued now, expires in 5 minutes
        // {"typ":"dpop+nonce","alg":"HS256"}.null
        $nonce = 'eyJ0eXAiOiJkcG9wK25vbmNlIiwiYWxnIjoiSFMyNTYifQ.bnVsbA.O-W8qtpNGkEbIqLd7juSOi01_VKi-89m1GgXQjaSKdQ';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);
        $this->assertIsValidNonce($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidMissingIatClaimCreatesNewNonce(): void
    {
        // expires in 5 minutes
        // {"typ":"dpop+nonce","alg":"HS256"}.{"exp":1708965882}
        $nonce = 'eyJ0eXAiOiJkcG9wK25vbmNlIiwiYWxnIjoiSFMyNTYifQ.eyJleHAiOjE3MDg5NjU4ODJ9.3oB13vP_eQkaA1JfSF8l0OoN7l_fKVR820YZTYDMGBE';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);
        $this->assertIsValidNonce($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidMissingExpClaimCreatesNewNonce(): void
    {
        // issued now
        // {"typ":"dpop+nonce","alg":"HS256"}.{"iat":1708965582}
        $nonce = 'eyJ0eXAiOiJkcG9wK25vbmNlIiwiYWxnIjoiSFMyNTYifQ.eyJpYXQiOjE3MDg5NjU1ODJ9.1RCMEExWDg6Rw9qp-uJNZpOMyDvxKICAAC4LHt8PTBA';

        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);
        $this->assertIsValidNonce($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidValidNonceCallsClosure(): void
    {
        /**
         * @param array<string, int> $claims
         */
        $closure = function (array $claims, string $key, WebTokenFrameworkNonceFactory $factory): void {
            $this->assertEquals(['iat' => 1708965582, 'exp' => 1708965882], $claims);
            $this->assertEquals(self::JKT, $key);
            $this->assertInstanceOf(WebTokenFrameworkNonceFactory::class, $factory);
        };

        $nonceFactory = new WebTokenFrameworkNonceFactory(
            $this->algorithm,
            new JWKSet([$this->jwk]),
            $this->clock,
            new \DateInterval(self::TTL),
            self::ALLOWED_TIME_DRIFT,
            \Closure::fromCallable($closure)
        );

        // issued now, expires in 5 minutes
        // {"typ":"dpop+none","alg":"HS256"}.{"iat":1708965582,"exp":1708965882}
        $nonce = 'eyJ0eXAiOiJkcG9wK25vbmNlIiwiYWxnIjoiSFMyNTYifQ.eyJpYXQiOjE3MDg5NjU1ODIsImV4cCI6MTcwODk2NTg4Mn0.Ilf1Ji1jecVSQlO8uU7TR435fWUvejGrWkXTi1F7bDY';

        $returnValue = $nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce);
        $this->assertNull($returnValue);
    }

    #[Test]
    public function createNewNoncePayloadHasExpectedClaims(): void
    {
        $nonce = $this->nonceFactory->createNewNonce(self::JKT);
        $parts = \explode('.', $nonce);
        $this->assertCount(3, $parts);

        $payload = JsonConverter::decode(Base64UrlSafe::decodeNoPadding($parts[1]));
        $this->assertIsArray($payload);

        $this->assertArrayHasKey('exp', $payload);
        $this->assertEquals($this->clock->now()->add(new \DateInterval(self::TTL))->getTimestamp(), $payload['exp']);

        $this->assertArrayHasKey('iat', $payload);
        $this->assertEquals($this->clock->now()->getTimestamp(), $payload['iat']);

        $this->assertArrayHasKey('jti', $payload);
        $this->assertIsString($payload['jti']);
        $this->assertTrue(\strlen($payload['jti']) >= 4);

        $this->assertArrayHasKey('jkt', $payload);
        $this->assertEquals(self::JKT, $payload['jkt']);
    }

    #[Test]
    public function createNewNonceHeaderHasExpectedParameters(): void
    {
        $nonce = $this->nonceFactory->createNewNonce(self::JKT);
        $parts = \explode('.', $nonce);
        $this->assertCount(3, $parts);

        $header = JsonConverter::decode(\base64_decode($parts[0]));
        $this->assertIsArray($header);

        $this->assertArrayHasKey('alg', $header);
        $this->assertEquals($this->algorithm->name(), $header['alg']);

        $this->assertArrayHasKey('typ', $header);
        $this->assertEquals(WebTokenFrameworkNonceFactory::TYPE_PARAMETER, $header['typ']);
    }

    #[Test]
    public function createNewNonceHeaderHasKidAndCrv(): void
    {
        $jwk = JWKFactory::createECKey('P-256', ['kid' => 'abc', 'crv' => 'P-256']);

        $nonceFactory = new WebTokenFrameworkNonceFactory(
            new ES256(),
            $jwk,
            $this->clock,
            new \DateInterval(self::TTL),
            self::ALLOWED_TIME_DRIFT
        );

        $nonce = $nonceFactory->createNewNonce(self::JKT);
        $parts = \explode('.', $nonce);
        $this->assertCount(3, $parts);

        $header = JsonConverter::decode(\base64_decode($parts[0]));
        $this->assertIsArray($header);

        $this->assertArrayHasKey('kid', $header);
        $this->assertEquals($jwk->get('kid'), $header['kid']);

        $this->assertArrayHasKey('crv', $header);
        $this->assertEquals($jwk->get('crv'), $header['crv']);
    }

    #[Test]
    public function createNewNonceNoMatchingAlgorithmThrowsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a suitable JWK/JWA to sign a DPoP-Nonce token.');

        $nonceFactory = new WebTokenFrameworkNonceFactory(
            new AlgorithmManager([new ES256(), new RS256()]),
            $this->jwk,
            $this->clock,
            new \DateInterval(self::TTL),
            self::ALLOWED_TIME_DRIFT
        );

        $nonceFactory->createNewNonce(self::JKT);
    }

    #[Test]
    public function createNewNonceNoneAlgorithmThrowsException(): void
    {
        $this->expectException(MissingDPoPJwkException::class);
        $this->expectExceptionMessage('Failed to find a suitable JWK/JWA to sign a DPoP-Nonce token.');

        $nonceFactory = new WebTokenFrameworkNonceFactory(
            new AlgorithmManager([new ES256(), new RS256()]),
            $this->jwk,
            $this->clock,
            new \DateInterval(self::TTL),
            self::ALLOWED_TIME_DRIFT
        );

        $nonceFactory->createNewNonce(self::JKT);
    }

    private function assertIsValidNonce(?string $nonce): void
    {
        $this->assertIsString($nonce);
        $this->assertNull($this->nonceFactory->createNewNonceIfInvalid(self::JKT, $nonce));
    }
}
