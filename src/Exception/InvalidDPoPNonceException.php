<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Exception;

class InvalidDPoPNonceException extends InvalidDPoPProofException
{
    /**
     * @codeCoverageIgnore
     */
    public function __construct(
        #[\SensitiveParameter]
        public readonly string $newNonce,
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }
}
