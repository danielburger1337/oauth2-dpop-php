<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Model;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(DPoPProof::class)]
class DPoPProofTest extends TestCase
{
    #[Test]
    public function toStringReturnsProof(): void
    {
        $jwk = $this->createMock(JwkInterface::class);

        $proof = new DPoPProof($jwk, 'abcdefg');

        $returnValue = $proof->__toString();

        $this->assertEquals('abcdefg', $returnValue);
    }
}
