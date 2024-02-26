<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Exception;

class DPoPReplayAttackException extends DPoPException
{
    public function __construct(
        public readonly string $jti,
        string $message = 'The given DPoP proof was already presented.',
        int $code = 0,
        \Throwable|null $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}
