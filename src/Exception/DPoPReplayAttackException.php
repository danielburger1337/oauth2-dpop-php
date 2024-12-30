<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Exception;

use danielburger1337\OAuth2\DPoP\Model\DecodedDPoPProof;

class DPoPReplayAttackException extends DPoPException
{
    /**
     * @codeCoverageIgnore
     */
    public function __construct(
        public readonly DecodedDPoPProof $proof,
        string $message = 'The given DPoP proof was already presented.',
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }
}
