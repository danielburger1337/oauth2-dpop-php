<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceFactory;

use OTPHP\TOTP;
use OTPHP\TOTPInterface;
use ParagonIE\ConstantTime\Base32;
use Psr\Clock\ClockInterface;

/***
 * @experimental
 */
class TotpNonceFactory implements NonceFactoryInterface
{
    /**
     * @param non-empty-string $secret
     * @param int<1, max>      $digits
     * @param int<1, max>      $period
     * @param non-empty-string $digest
     */
    public function __construct(
        private readonly ClockInterface $clock,
        private readonly string $secret,
        private readonly int $digits = 10,
        private readonly int $period = 180,
        private readonly string $digest = TOTPInterface::DEFAULT_DIGEST,
        private readonly int $epoch = TOTPInterface::DEFAULT_EPOCH,
        private readonly \Closure|null $closure = null,
    ) {
    }

    public function createNewNonce(string $thumbprint): string
    {
        return $this->createTOTP($thumbprint)->at($this->clock->now()->getTimestamp());
    }

    public function createNewNonceIfInvalid(string $thumbprint, string $nonce): ?string
    {
        $totp = $this->createTOTP($thumbprint);

        $time = $this->clock->now()->getTimestamp();

        // Check the current OTP code
        if (\hash_equals($totp->at($time), $nonce)) {
            // Resource server can use this closure to send the client
            // a new "DPoP-Nonce" before the current one is invalid
            // @see https://datatracker.ietf.org/doc/html/rfc9449#section-8.2
            if (null !== $this->closure) {
                \call_user_func($this->closure, $totp);
            }

            return null;
        }

        // Check the next OTP code incase client already uses next
        if (\hash_equals($totp->at($time + $this->period), $nonce)) {
            return null;
        }

        return $this->createNewNonce($thumbprint);
    }

    private function createTOTP(string $thumbprint): TOTPInterface
    {
        return TOTP::create(Base32::encodeUpper($this->secret.$thumbprint), $this->period, $this->digest, $this->digits, $this->epoch);
    }
}
