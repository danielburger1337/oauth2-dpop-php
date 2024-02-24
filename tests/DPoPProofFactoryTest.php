<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests;

use danielburger1337\OAuth2DPoP\DPoPProofFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(DPoPProofFactory::class)]
class DPoPProofFactoryTest extends TestCase
{
    #[Test]
    public function parseSupportedAlgorithmsFromHeader_validHeader_returnsAlgorithm(): void
    {
        $returnValue = DPoPProofFactory::parseSupportedAlgorithmsFromHeader('DPoP algs="ES256"');
        $this->assertEquals(['ES256'], $returnValue);
    }

    #[Test]
    public function parseSupportedAlgorithmsFromHeader_validHeader_returnsAlgorithms(): void
    {
        $returnValue = DPoPProofFactory::parseSupportedAlgorithmsFromHeader('DPoP algs="ES256 ES256K"');
        $this->assertEquals(['ES256', 'ES256K'], $returnValue);
    }

    #[Test]
    public function parseSupportedAlgorithmsFromHeader_validHeader_checkCaseSensitive(): void
    {
        $returnValue = DPoPProofFactory::parseSupportedAlgorithmsFromHeader('DPoP algs="EdDSA"');
        $this->assertEquals(['EdDSA'], $returnValue);
    }

    #[Test]
    public function parseSupportedAlgorithmsFromHeader_validMultipleHeader_returnsAlgorithm(): void
    {
        $returnValue = DPoPProofFactory::parseSupportedAlgorithmsFromHeader('Bearer,error="invalid_token",DPoP algs="ES256"');
        $this->assertEquals(['ES256'], $returnValue);
    }

    #[Test]
    public function parseSupportedAlgorithmsFromHeader_validMultipleHeader_returnsAlgorithms(): void
    {
        $returnValue = DPoPProofFactory::parseSupportedAlgorithmsFromHeader('Bearer,error="invalid_token",DPoP algs="ES256 RS256"');
        $this->assertEquals(['ES256', 'RS256'], $returnValue);
    }

    #[Test]
    public function parseSupportedAlgorithmsFromHeader_emptyHeader_returnsNull(): void
    {
        $returnValue = DPoPProofFactory::parseSupportedAlgorithmsFromHeader('');
        $this->assertNull($returnValue);
    }

    #[Test]
    public function parseSupportedAlgorithmsFromHeader_invalidHeader_returnsNull(): void
    {
        $returnValue = DPoPProofFactory::parseSupportedAlgorithmsFromHeader('Bearer');
        $this->assertNull($returnValue);
    }

    #[Test]
    public function parseSupportedAlgorithmsFromHeader_malformedHeader_returnsNull(): void
    {
        $returnValue = DPoPProofFactory::parseSupportedAlgorithmsFromHeader('DPoP algs="ES256');
        $this->assertNull($returnValue);
    }

    #[Test]
    public function parseSupportedAlgorithmsFromHeader_malformedHeaderWithOther_returnsNull(): void
    {
        $returnValue = DPoPProofFactory::parseSupportedAlgorithmsFromHeader('Bearer,error="invalid_token",DPoP algs="ES256');
        $this->assertNull($returnValue);
    }
}
