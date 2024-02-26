<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests\ReplayAttack;

use danielburger1337\OAuth2DPoP\Model\DecodedDPoPProof;
use danielburger1337\OAuth2DPoP\ReplayAttack\ReplayAttackKeyFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(ReplayAttackKeyFactory::class)]
class ReplayAttackKeyFactoryTest extends TestCase
{
    private const JKT = 'u-OgFMUQNFo0PC7x32Il3T_n_FOgRrUZJj4DA9LKy3M';
    private const PAYLOAD = ['jti' => 'abcdefghijklmnopqrstuvwxyz'];
    private const HEADER = ['alg' => 'ES256'];

    private const EXPECTED = 'e72aacc2fd89916cb103b951956fd55a';

    private DecodedDPoPProof $proof;
    private ReplayAttackKeyFactory $replayAttackKeyFactory;

    protected function setUp(): void
    {
        $this->proof = new DecodedDPoPProof(self::JKT, self::PAYLOAD, self::HEADER);
        $this->replayAttackKeyFactory = new ReplayAttackKeyFactory();
    }

    #[Test]
    public function createKey_idempotency_returnsExpected(): void
    {
        $returnValue = $this->replayAttackKeyFactory->createKey($this->proof);

        $this->assertEquals(self::EXPECTED, $returnValue);
    }

    #[Test]
    public function createKey_idempotency_returnsDifferent(): void
    {
        $proof = new DecodedDPoPProof(self::JKT, [...self::PAYLOAD, 'jti' => 'changed'], self::HEADER);

        $returnValue = $this->replayAttackKeyFactory->createKey($proof);

        $this->assertNotEquals(self::EXPECTED, $returnValue);
    }
}
