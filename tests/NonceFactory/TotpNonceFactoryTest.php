<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests\NonceFactory;

use danielburger1337\OAuth2\DPoP\NonceFactory\TotpNonceFactory;
use OTPHP\TOTPInterface;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

#[CoversClass(TotpNonceFactory::class)]
class TotpNonceFactoryTest extends TestCase
{
    private const THUMBPRINT = 'thumprint';
    private const SECRET = 'abcdefghijklmnopqrstuvwxyz';
    private const DIGITS = 10;
    private const PERIOD = 180;
    private const DIGEST = 'sha1';
    private const EPOCH = 0;

    private TotpNonceFactory $nonceFactory;
    private MockClock $clock;

    protected function setUp(): void
    {
        $this->clock = new MockClock('2024-02-28 11:30:00');

        $this->nonceFactory = new TotpNonceFactory($this->clock, self::SECRET, self::DIGITS, self::PERIOD, self::DIGEST, self::EPOCH);
    }

    #[Test]
    #[DataProvider('dataProvider_createNewNonce')]
    public function createNewNonceReturnsExpected(string $clock, string $thumbprint, string $secret, int $digits, int $period, string $digest, int $epoch, string $expected): void
    {
        $clock = new MockClock($clock);

        // @phpstan-ignore-next-line
        $nonceFactory = new TotpNonceFactory($clock, $secret, $digits, $period, $digest, $epoch);

        $returnValue = $nonceFactory->createNewNonce($thumbprint);

        $this->assertEquals($expected, $returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidValidNonceReturnsNull(): void
    {
        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::THUMBPRINT, '0573455172');

        $this->assertNull($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidValidNonceWithClosureInvokesClosureAndReturnsNull(): void
    {
        $closure = function (TOTPInterface $totp): void {
            // this test is important, it ensures that each JKT has a unique nonce
            $this->assertEquals(Base32::encodeUpperUnpadded(self::SECRET.self::THUMBPRINT), $totp->getSecret());
        };

        $nonceFactory = new TotpNonceFactory($this->clock, self::SECRET, self::DIGITS, self::PERIOD, self::DIGEST, self::EPOCH, $closure);

        $returnValue = $nonceFactory->createNewNonceIfInvalid(self::THUMBPRINT, '0573455172');

        $this->assertNull($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidValidNextNonceReturnsNull(): void
    {
        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::THUMBPRINT, '1585442449');

        $this->assertNull($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidValidNonceWithClosureDoesNotInvokeClosureAndReturnsNull(): void
    {
        $closure = function (TOTPInterface $totp): void {
            // fail if invoked
            $this->assertFalse($totp);
        };

        $nonceFactory = new TotpNonceFactory($this->clock, self::SECRET, self::DIGITS, self::PERIOD, self::DIGEST, self::EPOCH, $closure);

        $returnValue = $nonceFactory->createNewNonceIfInvalid(self::THUMBPRINT, '1585442449');

        $this->assertNull($returnValue);
    }

    #[Test]
    public function createNewNonceIfInvalidInvalidNonceReturnsCurrentNonce(): void
    {
        $returnValue = $this->nonceFactory->createNewNonceIfInvalid(self::THUMBPRINT, 'invalid');

        $this->assertEquals('0573455172', $returnValue);
    }

    /**
     * @return array<array{0: string, 1: string, 2: string, 3: int, 4: int, 5: string, 6: int, 7: string}>
     */
    public static function dataProvider_createNewNonce(): array
    {
        return [
            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 10, 180, 'sha1', 0, '0157955733'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 10, 180, 'sha1', 0, '0157955733'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 10, 180, 'sha1', 0, '0769711488'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 10, 180, 'sha1', 0, '1274974627'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 10, 180, 'sha1', 0, '1274974627'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 10, 180, 'sha1', 0, '1922093268'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 10, 180, 'sha1', 0, '1804688071'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 10, 180, 'sha1', 0, '1804688071'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 10, 180, 'sha1', 0, '1087143384'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha1', 0, '1789295349'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha1', 0, '1789295349'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha1', 0, '0346026844'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 8, 180, 'sha1', 0, '57955733'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 8, 180, 'sha1', 0, '57955733'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 8, 180, 'sha1', 0, '69711488'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 8, 180, 'sha1', 0, '04688071'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 8, 180, 'sha1', 0, '04688071'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 8, 180, 'sha1', 0, '87143384'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 8, 180, 'sha1', 0, '74974627'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 8, 180, 'sha1', 0, '74974627'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 8, 180, 'sha1', 0, '22093268'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha1', 0, '89295349'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha1', 0, '89295349'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha1', 0, '46026844'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 8, 240, 'sha1', 0, '40459464'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 8, 240, 'sha1', 0, '40459464'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 8, 240, 'sha1', 0, '03947323'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 8, 240, 'sha1', 0, '17108362'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 8, 240, 'sha1', 0, '17108362'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 8, 240, 'sha1', 0, '50011912'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 8, 240, 'sha1', 0, '60862993'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 8, 240, 'sha1', 0, '60862993'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 8, 240, 'sha1', 0, '91972201'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha1', 0, '21102314'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha1', 0, '21102314'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha1', 0, '04111331'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 10, 240, 'sha1', 0, '0340459464'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 10, 240, 'sha1', 0, '0340459464'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 10, 240, 'sha1', 0, '1203947323'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 10, 240, 'sha1', 0, '1917108362'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 10, 240, 'sha1', 0, '1917108362'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 10, 240, 'sha1', 0, '1750011912'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 10, 240, 'sha1', 0, '0160862993'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 10, 240, 'sha1', 0, '0160862993'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 10, 240, 'sha1', 0, '0391972201'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha1', 0, '2021102314'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha1', 0, '2021102314'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha1', 0, '1204111331'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 10, 180, 'sha256', 0, '1298568790'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 10, 180, 'sha256', 0, '1298568790'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 10, 180, 'sha256', 0, '1630759546'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 10, 180, 'sha256', 0, '0498757178'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 10, 180, 'sha256', 0, '0498757178'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 10, 180, 'sha256', 0, '1344569473'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 10, 180, 'sha256', 0, '0808721797'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 10, 180, 'sha256', 0, '0808721797'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 10, 180, 'sha256', 0, '1201574763'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha256', 0, '0698288674'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha256', 0, '0698288674'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha256', 0, '1637984068'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 8, 180, 'sha256', 0, '98568790'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 8, 180, 'sha256', 0, '98568790'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 8, 180, 'sha256', 0, '30759546'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 8, 180, 'sha256', 0, '08721797'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 8, 180, 'sha256', 0, '08721797'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 8, 180, 'sha256', 0, '01574763'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 8, 180, 'sha256', 0, '98757178'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 8, 180, 'sha256', 0, '98757178'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 8, 180, 'sha256', 0, '44569473'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha256', 0, '98288674'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha256', 0, '98288674'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha256', 0, '37984068'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 8, 240, 'sha256', 0, '89922211'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 8, 240, 'sha256', 0, '89922211'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 8, 240, 'sha256', 0, '31251489'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 8, 240, 'sha256', 0, '76628146'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 8, 240, 'sha256', 0, '76628146'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 8, 240, 'sha256', 0, '96726408'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 8, 240, 'sha256', 0, '48716176'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 8, 240, 'sha256', 0, '48716176'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 8, 240, 'sha256', 0, '09841644'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha256', 0, '18136178'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha256', 0, '18136178'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha256', 0, '33806411'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 10, 240, 'sha256', 0, '0189922211'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 10, 240, 'sha256', 0, '0189922211'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 10, 240, 'sha256', 0, '1631251489'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 10, 240, 'sha256', 0, '1776628146'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 10, 240, 'sha256', 0, '1776628146'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 10, 240, 'sha256', 0, '0096726408'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 10, 240, 'sha256', 0, '0248716176'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 10, 240, 'sha256', 0, '0248716176'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 10, 240, 'sha256', 0, '0809841644'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha256', 0, '0618136178'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha256', 0, '0618136178'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha256', 0, '1733806411'],

            // ######################
            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 10, 180, 'sha1', 1503554299, '1003843579'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 10, 180, 'sha1', 1503554299, '1003843579'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 10, 180, 'sha1', 1503554299, '0986010663'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 10, 180, 'sha1', 1503554299, '0520729269'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 10, 180, 'sha1', 1503554299, '0520729269'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 10, 180, 'sha1', 1503554299, '1707998584'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 10, 180, 'sha1', 1503554299, '1545907376'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 10, 180, 'sha1', 1503554299, '1545907376'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 10, 180, 'sha1', 1503554299, '0679393402'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha1', 1503554299, '0969341774'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha1', 1503554299, '0969341774'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha1', 1503554299, '0113043600'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 8, 180, 'sha1', 1503554299, '03843579'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 8, 180, 'sha1', 1503554299, '03843579'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 8, 180, 'sha1', 1503554299, '86010663'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 8, 180, 'sha1', 1503554299, '45907376'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 8, 180, 'sha1', 1503554299, '45907376'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 8, 180, 'sha1', 1503554299, '79393402'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 8, 180, 'sha1', 1503554299, '20729269'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 8, 180, 'sha1', 1503554299, '20729269'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 8, 180, 'sha1', 1503554299, '07998584'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha1', 1503554299, '69341774'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha1', 1503554299, '69341774'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha1', 1503554299, '13043600'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 8, 240, 'sha1', 1503554299, '11802638'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 8, 240, 'sha1', 1503554299, '11802638'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 8, 240, 'sha1', 1503554299, '13022845'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 8, 240, 'sha1', 1503554299, '43403172'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 8, 240, 'sha1', 1503554299, '43403172'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 8, 240, 'sha1', 1503554299, '24117034'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 8, 240, 'sha1', 1503554299, '49937355'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 8, 240, 'sha1', 1503554299, '49937355'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 8, 240, 'sha1', 1503554299, '42124554'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha1', 1503554299, '17863653'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha1', 1503554299, '17863653'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha1', 1503554299, '22386341'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 10, 240, 'sha1', 1503554299, '0811802638'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 10, 240, 'sha1', 1503554299, '0811802638'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 10, 240, 'sha1', 1503554299, '0013022845'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 10, 240, 'sha1', 1503554299, '0743403172'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 10, 240, 'sha1', 1503554299, '0743403172'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 10, 240, 'sha1', 1503554299, '0024117034'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 10, 240, 'sha1', 1503554299, '0149937355'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 10, 240, 'sha1', 1503554299, '0149937355'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 10, 240, 'sha1', 1503554299, '0042124554'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha1', 1503554299, '0217863653'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha1', 1503554299, '0217863653'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha1', 1503554299, '0422386341'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 10, 180, 'sha256', 1503554299, '1252508510'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 10, 180, 'sha256', 1503554299, '1252508510'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 10, 180, 'sha256', 1503554299, '0614424619'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 10, 180, 'sha256', 1503554299, '0460832508'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 10, 180, 'sha256', 1503554299, '0460832508'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 10, 180, 'sha256', 1503554299, '0956467324'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 10, 180, 'sha256', 1503554299, '0047214120'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 10, 180, 'sha256', 1503554299, '0047214120'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 10, 180, 'sha256', 1503554299, '0532617118'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha256', 1503554299, '1783001752'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha256', 1503554299, '1783001752'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 10, 180, 'sha256', 1503554299, '0311867693'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 8, 180, 'sha256', 1503554299, '52508510'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 8, 180, 'sha256', 1503554299, '52508510'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 8, 180, 'sha256', 1503554299, '14424619'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 8, 180, 'sha256', 1503554299, '47214120'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 8, 180, 'sha256', 1503554299, '47214120'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 8, 180, 'sha256', 1503554299, '32617118'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 8, 180, 'sha256', 1503554299, '60832508'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 8, 180, 'sha256', 1503554299, '60832508'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 8, 180, 'sha256', 1503554299, '56467324'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha256', 1503554299, '83001752'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha256', 1503554299, '83001752'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 8, 180, 'sha256', 1503554299, '11867693'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 8, 240, 'sha256', 1503554299, '04207141'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 8, 240, 'sha256', 1503554299, '04207141'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 8, 240, 'sha256', 1503554299, '72771572'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 8, 240, 'sha256', 1503554299, '04989691'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 8, 240, 'sha256', 1503554299, '04989691'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 8, 240, 'sha256', 1503554299, '33708179'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 8, 240, 'sha256', 1503554299, '52218695'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 8, 240, 'sha256', 1503554299, '52218695'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 8, 240, 'sha256', 1503554299, '46703297'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha256', 1503554299, '07768609'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha256', 1503554299, '07768609'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 8, 240, 'sha256', 1503554299, '62226877'],

            ['2024-02-28 10:00:00', 'thumbprint', 'secret', 10, 240, 'sha256', 1503554299, '0804207141'],
            ['2024-02-28 10:01:00', 'thumbprint', 'secret', 10, 240, 'sha256', 1503554299, '0804207141'],
            ['2024-02-28 10:05:00', 'thumbprint', 'secret', 10, 240, 'sha256', 1503554299, '0372771572'],

            ['2024-02-28 10:00:00', 'thumbprint', 'otherSecret', 10, 240, 'sha256', 1503554299, '0504989691'],
            ['2024-02-28 10:01:00', 'thumbprint', 'otherSecret', 10, 240, 'sha256', 1503554299, '0504989691'],
            ['2024-02-28 10:05:00', 'thumbprint', 'otherSecret', 10, 240, 'sha256', 1503554299, '0133708179'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'secret', 10, 240, 'sha256', 1503554299, '0352218695'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'secret', 10, 240, 'sha256', 1503554299, '0352218695'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'secret', 10, 240, 'sha256', 1503554299, '0846703297'],

            ['2024-02-28 10:00:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha256', 1503554299, '0607768609'],
            ['2024-02-28 10:01:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha256', 1503554299, '0607768609'],
            ['2024-02-28 10:05:00', 'otherThumbprint', 'otherSecret', 10, 240, 'sha256', 1503554299, '0162226877'],
        ];
    }
}
