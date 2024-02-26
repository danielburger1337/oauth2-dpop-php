<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests\NonceStorage;

use danielburger1337\OAuth2DPoP\NonceStorage\WebTokenFrameworkNonceStorage;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

#[CoversClass(WebTokenFrameworkNonceStorage::class)]
class WebTokenFrameworkNonceStorageTest extends TestCase
{
    private const KEY = 'key';

    private const SECRET = 'abcdefghijklmnopqrstuvwxyz1234567';
    private const TTL = 'PT5M';
    private const ALLOWED_TIME_DRIFT = 5;

    private WebTokenFrameworkNonceStorage $nonceStorage;

    private MockClock $clock;
    private JWK $jwk;
    private Algorithm $algorithm;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new MockClock();
        $this->jwk = JWKFactory::createFromSecret(self::SECRET, ['kid' => 'abc', 'crv' => 'def']);
        $this->algorithm = new HS256();

        $this->nonceStorage = new WebTokenFrameworkNonceStorage(
            $this->algorithm,
            new JWKSet([$this->jwk]),
            $this->clock,
            new \DateInterval(self::TTL),
            self::ALLOWED_TIME_DRIFT
        );
    }

    #[Test]
    public function isNonceValid_createdNonce_returnsTrue(): void
    {
        $nonce = $this->nonceStorage->createNewNonce(self::KEY);

        $returnValue = $this->nonceStorage->isNonceValid(self::KEY, $nonce);

        $this->assertTrue($returnValue);
    }

    #[Test]
    public function isNonceValid_validNonce_returnsTrue(): void
    {
        $nonce = $this->createNonce(
            $this->clock->now()->getTimestamp(),
            $this->clock->now()->add(new \DateInterval(self::TTL))->getTimestamp()
        );

        $returnValue = $this->nonceStorage->isNonceValid(self::KEY, $nonce);
        $this->assertTrue($returnValue);
    }

    #[Test]
    public function isNonceValid_expiredNonceWithinTimeDrift_returnsFalse(): void
    {
        $nonce = $this->createNonce(
            $this->clock->now()->getTimestamp(),
            $this->clock->now()->sub(new \DateInterval('PT'.(self::ALLOWED_TIME_DRIFT - 1).'S'))->getTimestamp()
        );

        $returnValue = $this->nonceStorage->isNonceValid(self::KEY, $nonce);
        $this->assertTrue($returnValue);
    }

    #[Test]
    public function isNonceValid_expiredNonce_returnsFalse(): void
    {
        $nonce = $this->createNonce(
            $this->clock->now()->getTimestamp(),
            $this->clock->now()->sub(new \DateInterval('PT'.(self::ALLOWED_TIME_DRIFT + 1).'S'))->getTimestamp()
        );

        $returnValue = $this->nonceStorage->isNonceValid(self::KEY, $nonce);
        $this->assertFalse($returnValue);
    }

    #[Test]
    public function isNonceValid_invalidSignature_returnsFalse(): void
    {
        $nonce = $this->createNonce(
            $this->clock->now()->getTimestamp(),
            $this->clock->now()->getTimestamp(),
            JWKFactory::createFromSecret(\random_bytes(32))
        );

        $returnValue = $this->nonceStorage->isNonceValid(self::KEY, $nonce);
        $this->assertFalse($returnValue);
    }

    #[Test]
    public function isNonceValid_invalidJwt_returnsFalse(): void
    {
        $returnValue = $this->nonceStorage->isNonceValid(self::KEY, 'not a valid jwt');

        $this->assertFalse($returnValue);
    }

    #[Test]
    public function createNewNonce_payload_hasExpectedClaims(): void
    {
        $nonce = $this->nonceStorage->createNewNonce(self::KEY);
        $parts = \explode('.', $nonce);
        $this->assertCount(3, $parts);

        $payload = JsonConverter::decode(\base64_decode($parts[1]));
        $this->assertIsArray($payload);

        $this->assertArrayHasKey('exp', $payload);
        $this->assertEquals($this->clock->now()->add(new \DateInterval(self::TTL))->getTimestamp(), $payload['exp']);

        $this->assertArrayHasKey('iat', $payload);
        $this->assertEquals($this->clock->now()->getTimestamp(), $payload['iat']);

        $this->assertArrayHasKey('jti', $payload);
        $this->assertTrue(\strlen($payload['jti']) >= 4);
    }

    #[Test]
    public function createNewNonce_header_hasExpectedParameters(): void
    {
        $nonce = $this->nonceStorage->createNewNonce(self::KEY);
        $parts = \explode('.', $nonce);
        $this->assertCount(3, $parts);

        $header = JsonConverter::decode(\base64_decode($parts[0]));
        $this->assertIsArray($header);

        $this->assertArrayHasKey('alg', $header);
        $this->assertEquals($this->algorithm->name(), $header['alg']);

        $this->assertArrayHasKey('typ', $header);
        $this->assertEquals(WebTokenFrameworkNonceStorage::TYPE_PARAMETER, $header['typ']);

        $this->assertArrayHasKey('kid', $header);
        $this->assertEquals($this->jwk->get('kid'), $header['kid']);

        $this->assertArrayHasKey('crv', $header);
        $this->assertEquals($this->jwk->get('crv'), $header['crv']);
    }

    #[Test]
    public function storeNextNonce_doesNothing(): void
    {
        $this->expectNotToPerformAssertions();

        $this->nonceStorage->storeNextNonce(self::KEY, 'def');
    }

    #[Test]
    public function getCurrentNonce_createsNewNonce(): void
    {
        $returnValue1 = $this->nonceStorage->createNewNonce(self::KEY);
        $returnValue2 = $this->nonceStorage->createNewNonce(self::KEY);

        $this->assertNotEquals($returnValue1, $returnValue2);
    }

    private function createNonce(int $iat, int $exp, ?JWK $jwk = null): string
    {
        $header = ['typ' => WebTokenFrameworkNonceStorage::TYPE_PARAMETER, 'alg' => $this->algorithm->name()];
        $payload = [
            'iat' => $iat,
            'exp' => $exp,
            ];

        $builder = (new JWSBuilder(new AlgorithmManager([$this->algorithm])))
            ->create()
            ->withPayload(JsonConverter::encode($payload))
            ->addSignature($jwk ?? $this->jwk, $header);

        return (new CompactSerializer())->serialize($builder->build());
    }
}
