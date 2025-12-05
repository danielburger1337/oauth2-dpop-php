<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\Tests;

use danielburger1337\OAuth2\DPoP\DPoPProofVerifier;
use danielburger1337\OAuth2\DPoP\Exception\DPoPReplayAttackException;
use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPNonceException;
use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPProofException;
use danielburger1337\OAuth2\DPoP\Loader\DPoPTokenLoaderInterface;
use danielburger1337\OAuth2\DPoP\Model\AccessTokenModel;
use danielburger1337\OAuth2\DPoP\Model\DecodedDPoPProof;
use danielburger1337\OAuth2\DPoP\Model\JwkInterface;
use danielburger1337\OAuth2\DPoP\NonceFactory\NonceFactoryInterface;
use danielburger1337\OAuth2\DPoP\ReplayAttack\ReplayAttackDetectorInterface;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(DPoPProofVerifier::class)]
class DPoPProofVerifierTest extends TestCase
{
    private const ALLOWED_TIME_DRIFT = 5;
    private const ALLOWED_MAX_AGE = 30;

    private const PROOF_TOKEN = 'non-empty-string';

    private const HTM = 'GET';
    private const HTU = 'https://example.com/path';

    private MockClock $clock;
    private DPoPTokenLoaderInterface&MockObject $tokenLoader;

    private DPoPProofVerifier $verifier;

    private JWK $jwk;

    protected function setUp(): void
    {
        // @phpstan-ignore-next-line
        $this->jwk = JWKFactory::createFromValues([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'E6luNsWvQPVZkgkTMj6hDYz6Vi7nxvujGCBOe7DdMrc',
            'x' => 'K_grY8EYPtGtXkQ7CCXru3zi5SApi33gaZit1lxOhws',
            'y' => 'kU_N4_T4y_M5SEmJwILgvd7Gnj_ckyljLO2FsVGXVTM',
        ]);

        $this->clock = new MockClock();
        $this->tokenLoader = $this->createMock(DPoPTokenLoaderInterface::class);

        $this->verifier = new DPoPProofVerifier($this->clock, $this->tokenLoader, null, null, self::ALLOWED_TIME_DRIFT, self::ALLOWED_MAX_AGE);
    }

    #[Test]
    public function verifyFromRequestHttpFoundationPassesThrough(): void
    {
        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());
        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $request = Request::create('https://example.com/path?query#fragment', self::HTM, server: ['HTTP_DPOP' => self::PROOF_TOKEN]);

        $returnValue = $this->verifier->verifyFromRequest($request, null);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestHttpFoundationPassesThroughWithAccessToken(): void
    {
        $jwk = $this->createJwkMock();
        $accessToken = new AccessTokenModel('abc', $jwk->thumbprint());

        $payload = $this->createDecodedPayload();
        $payload['ath'] = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());
        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $request = Request::create('https://example.com/path?query#fragment', self::HTM, server: ['HTTP_DPOP' => self::PROOF_TOKEN]);

        $returnValue = $this->verifier->verifyFromRequest($request, $accessToken);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestHttpFoundationNoHeadersThrowsException(): void
    {
        $request = Request::create(self::HTU, self::HTM);

        $this->expectException(MissingDPoPProofException::class);
        $this->expectExceptionMessage('The request did not contain a "DPoP" header.');

        $this->verifier->verifyFromRequest($request);
    }

    #[Test]
    public function verifyFromRequestHttpFoundationMultipleHeadersThrowsException(): void
    {
        $request = Request::create(self::HTU, self::HTM, server: ['HTTP_DPOP' => ['value1', 'value2']]);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The request must contain exactly one "DPoP" header.');

        $this->verifier->verifyFromRequest($request);
    }

    #[Test]
    public function verifyFromRequestPsr7PassesThrough(): void
    {
        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());
        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $request = new ServerRequest(\strtolower(self::HTM), 'https://example.com/path?query#fragment');
        $request = $request->withHeader('DPoP', self::PROOF_TOKEN);

        $returnValue = $this->verifier->verifyFromRequest($request, null);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPsr7PassesThroughWithAccessToken(): void
    {
        $jwk = $this->createJwkMock();
        $accessToken = new AccessTokenModel('abc', $jwk->thumbprint());

        $payload = $this->createDecodedPayload();
        $payload['ath'] = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());
        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $request = new ServerRequest(\strtolower(self::HTM), 'https://example.com/path?query#fragment');
        $request = $request->withHeader('DPoP', self::PROOF_TOKEN);

        $returnValue = $this->verifier->verifyFromRequest($request, $accessToken);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPsr7NoHeaderThrowsException(): void
    {
        $request = new ServerRequest(self::HTM, self::HTU);

        $this->expectException(MissingDPoPProofException::class);
        $this->expectExceptionMessage('The request did not contain a "DPoP" header.');

        $this->verifier->verifyFromRequest($request);
    }

    #[Test]
    public function verifyFromRequestPsr7MultipleHeadersThrowsException(): void
    {
        $request = new ServerRequest(self::HTM, self::HTU);
        $request = $request->withHeader('DPoP', ['value1', 'value2']);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The request must contain exactly one "DPoP" header.');

        $this->verifier->verifyFromRequest($request);
    }

    #[Test]
    public function verifyFromRequestPartsEmptyStringThrowsException(): void
    {
        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof must be a non empty string.');

        $this->verifier->verifyFromRequestParts('', self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsPrivateJwkThrowsException(): void
    {
        $jwk = $this->createJwkMock(toPublic: false);

        $protectedHeader = $this->createDecodedProtectedHeader();
        $protectedHeader['jwk'] = $this->jwk->jsonSerialize();

        $decoded = new DecodedDPoPProof($jwk, $this->createDecodedPayload(), $protectedHeader);

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('DPoP proof must not contain a private key in the "jwk" header parameter.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsMissingTypHeaderThrowsException(): void
    {
        $protectedHeader = $this->createDecodedProtectedHeader();
        unset($protectedHeader['typ']);

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $protectedHeader);

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "typ" header parameter is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsInvalidTypHeaderThrowsException(): void
    {
        $protectedHeader = $this->createDecodedProtectedHeader();
        $protectedHeader['typ'] = 'invalidValue';

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $protectedHeader);

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "typ" header parameter is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsMissingHtmClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        unset($payload['htm']);

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is missing the required "htm" claim.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsInvalidHtmClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['htm'] = 1; // not a string

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is missing the required "htm" claim.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsUnexpectedHtmClaimThrowsException(): void
    {
        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "htm" claim is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, 'POST', self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsHtmClaimIsCaseInsensitive(): void
    {
        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, \strtolower(self::HTM), self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsMissingJtiClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        unset($payload['jti']);

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is missing the required "jti" claim.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsInvalidJtiClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['jti'] = 1; // not a string

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is missing the required "jti" claim.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsJtiClaimTooShortThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['jti'] = 'abcdef';

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is "jti" claim does not match the required format.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsJtiClaimTooLongThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['jti'] = \bin2hex(\random_bytes(2049));

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is "jti" claim does not match the required format.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsMissingHtuClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        unset($payload['htu']);

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is missing the required "htu" claim.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsInvalidHtuClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['htu'] = 1; // not a string

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is missing the required "htu" claim.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsUnexpectedHtuClaimThrowsException(): void
    {
        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "htu" claim is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, 'https://subdomain.example.com');
    }

    #[Test]
    public function verifyFromRequestPartsHtuClaimIsCaseInsensitive(): void
    {
        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, \strtoupper(self::HTU));

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsMissingIatClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        unset($payload['iat']);

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "iat" claim is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsInvalidIatClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['iat'] = $this->clock->now()->format('c'); // not a unix timestamp

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "iat" claim is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsIatInFutureThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['iat'] = $this->clock->now()->add(new \DateInterval('PT10S'))->getTimestamp();

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof was issued in the future.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsIatInFutureButWithinAllowedTimeDriftReturnsDecoded(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['iat'] = $this->clock->now()->add(new \DateInterval('PT3S'))->getTimestamp();

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsIatUnreasonablyFarInPastThrowsException(): void
    {
        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof was issued unreasonably far back in the past.');

        $payload = $this->createDecodedPayload();
        $payload['iat'] = $this->clock->now()->getTimestamp() - self::ALLOWED_MAX_AGE;

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsIatInPastButWithinAllowedTimeDriftReturnsDecoded(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['iat'] = $this->clock->now()->getTimestamp() - self::ALLOWED_MAX_AGE + self::ALLOWED_TIME_DRIFT;

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsExpClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['exp'] = $this->clock->now()->add(new \DateInterval('PT15M'))->getTimestamp();

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsInvalidExpClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['exp'] = $this->clock->now()->format('c'); // not a unix timestamp

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "exp" claim is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsExpInPastThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['exp'] = $this->clock->now()->sub(new \DateInterval('PT10S'))->getTimestamp();

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof has expired.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsExpInPastButWithinAllowedTimeDriftReturnsDecoded(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['exp'] = $this->clock->now()->sub(new \DateInterval('PT3S'))->getTimestamp();

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsNbfClaimReturnsDecoded(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['nbf'] = $this->clock->now()->getTimestamp();

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsInvalidNbfClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['nbf'] = $this->clock->now()->format('c'); // not a unix timestamp

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "nbf" claim is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsNbfInFutureThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['nbf'] = $this->clock->now()->add(new \DateInterval('PT10S'))->getTimestamp();

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is not yet valid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsNbfInFutureButWithinAllowedTimeDriftReturnsDecoded(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['nbf'] = $this->clock->now()->add(new \DateInterval('PT3S'))->getTimestamp();

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsAthClaimReturnsDecoded(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['ath'] = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU, new AccessTokenModel('abc', $this->jwk->thumbprint('sha256')));

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsAthWithoutAccessTokenIsIgnored(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['ath'] = 'abc';

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
    }

    #[Test]
    public function verifyFromRequestPartsMissingAthClaimThrowsException(): void
    {
        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof is missing the required "ath" claim.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU, new AccessTokenModel('abcdefg', $this->jwk->thumbprint('sha256')));
    }

    #[Test]
    public function verifyFromRequestPartsInvalidAthClaimThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['ath'] = 1; // not a string

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "ath" claim is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU, new AccessTokenModel('abcdefg', $this->jwk->thumbprint('sha256')));
    }

    #[Test]
    public function verifyFromRequestPartsInvalidAthHashThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['ath'] = 'invalid hash';

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof "ath" claim is invalid.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU, new AccessTokenModel('abc', $this->jwk->thumbprint('sha256')));
    }

    #[Test]
    public function verifyFromRequestPartsAccessTokenInvalidThumbprintThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['ath'] = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof was signed by a different JWK than was used to issue the access token.');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU, new AccessTokenModel('abc', 'invalidThumbprint'));
    }

    #[Test]
    public function verifyFromRequestPartsMatchingThumbprintReturnsDecoded(): void
    {
        $payload = $this->createDecodedPayload();

        $decoded = new DecodedDPoPProof($this->createJwkMock(), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $returnValue = $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU, $this->jwk->thumbprint('sha256'));
        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsThumbprintThrowsException(): void
    {
        $payload = $this->createDecodedPayload();

        $decoded = new DecodedDPoPProof($this->createJwkMock(realThumbprint: false), $payload, $this->createDecodedProtectedHeader());

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof was signed by a different JWK than the provided JKT');

        $this->verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU, $this->jwk->thumbprint('sha256'));
    }

    #[Test]
    public function verifyFromRequestPartsMissingNonceThrowsException(): void
    {
        $jwk = $this->createJwkMock();
        $decoded = new DecodedDPoPProof($jwk, $this->createDecodedPayload(), $this->createDecodedProtectedHeader());

        $nonceFactory = $this->createMock(NonceFactoryInterface::class);
        $nonceFactory->expects($this->once())
            ->method('createNewNonce')
            ->with($jwk->thumbprint())
            ->willReturn('abc123');

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $verifier = new DPoPProofVerifier($this->clock, $this->tokenLoader, $nonceFactory);

        $this->expectException(InvalidDPoPNonceException::class);
        $this->expectExceptionMessage('The DPoP proof is missing the required "nonce" claim.');

        try {
            $verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
        } catch (InvalidDPoPNonceException $e) {
            $this->assertEquals('abc123', $e->newNonce);

            throw $e;
        }
    }

    #[Test]
    public function verifyFromRequestPartsMalformedNonceThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['nonce'] = 1; // not a string

        $jwk = $this->createJwkMock();
        $decoded = new DecodedDPoPProof($jwk, $payload, $this->createDecodedProtectedHeader());

        $nonceFactory = $this->createMock(NonceFactoryInterface::class);
        $nonceFactory->expects($this->once())
            ->method('createNewNonce')
            ->with($jwk->thumbprint())
            ->willReturn('abc123');

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $verifier = new DPoPProofVerifier($this->clock, $this->tokenLoader, $nonceFactory);

        $this->expectException(InvalidDPoPNonceException::class);
        $this->expectExceptionMessage('The DPoP proof is missing the required "nonce" claim.');

        try {
            $verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
        } catch (InvalidDPoPNonceException $e) {
            $this->assertEquals('abc123', $e->newNonce);

            throw $e;
        }
    }

    #[Test]
    public function verifyFromRequestPartsValidNonceReturnsDecoded(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['nonce'] = 'thisNonce123';

        $jwk = $this->createJwkMock();
        $decoded = new DecodedDPoPProof($jwk, $payload, $this->createDecodedProtectedHeader());

        $nonceFactory = $this->createMock(NonceFactoryInterface::class);
        $nonceFactory->expects($this->never())
            ->method('createNewNonce');

        $nonceFactory->expects($this->once())
            ->method('createNewNonceIfInvalid')
            ->with($jwk->thumbprint(), 'thisNonce123')
            ->willReturn(null);

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $verifier = new DPoPProofVerifier($this->clock, $this->tokenLoader, $nonceFactory);

        $returnValue = $verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsInvalidNonceThrowsException(): void
    {
        $payload = $this->createDecodedPayload();
        $payload['nonce'] = 'thisNonce123';

        $jwk = $this->createJwkMock();
        $decoded = new DecodedDPoPProof($jwk, $payload, $this->createDecodedProtectedHeader());

        $nonceFactory = $this->createMock(NonceFactoryInterface::class);
        $nonceFactory->expects($this->never())
            ->method('createNewNonce');

        $nonceFactory->expects($this->once())
            ->method('createNewNonceIfInvalid')
            ->with($jwk->thumbprint(), 'thisNonce123')
            ->willReturn('newNonce321');

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $verifier = new DPoPProofVerifier($this->clock, $this->tokenLoader, $nonceFactory);

        $this->expectException(InvalidDPoPNonceException::class);

        try {
            $verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
        } catch (InvalidDPoPNonceException $e) {
            $this->assertEquals('newNonce321', $e->newNonce);

            throw $e;
        }
    }

    #[Test]
    public function verifyFromRequestPartsNoReplayAttackReturnsDecoded(): void
    {
        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());

        $replayAttackDetector = $this->createMock(ReplayAttackDetectorInterface::class);
        $replayAttackDetector->expects($this->once())
            ->method('consumeProof')
            ->with($decoded)
            ->willReturn(true);

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $verifier = new DPoPProofVerifier($this->clock, $this->tokenLoader, null, $replayAttackDetector);

        $returnValue = $verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);

        $this->assertEquals($decoded, $returnValue);
    }

    #[Test]
    public function verifyFromRequestPartsReplayAttackThrowsException(): void
    {
        $decoded = new DecodedDPoPProof($this->createJwkMock(), $this->createDecodedPayload(), $this->createDecodedProtectedHeader());

        $replayAttackDetector = $this->createMock(ReplayAttackDetectorInterface::class);
        $replayAttackDetector->expects($this->once())
            ->method('consumeProof')
            ->with($decoded)
            ->willReturn(false);

        $this->tokenLoader->expects($this->once())
            ->method('loadProof')
            ->with(self::PROOF_TOKEN)
            ->willReturn($decoded);

        $verifier = new DPoPProofVerifier($this->clock, $this->tokenLoader, null, $replayAttackDetector);

        $this->expectException(DPoPReplayAttackException::class);

        try {
            $verifier->verifyFromRequestParts(self::PROOF_TOKEN, self::HTM, self::HTU);
        } catch (DPoPReplayAttackException $e) {
            $this->assertEquals($decoded, $e->proof);

            throw $e;
        }
    }

    #[Test]
    public function createWwwAuthenticateChallengeLineReturnsTokenLoaderSupportedAlgorithms(): void
    {
        $this->tokenLoader->expects($this->once())
            ->method('getSupportedAlgorithms')
            ->willReturn(['ES256', 'EdDSA']);

        $returnValue = $this->verifier->createWwwAuthenticateChallengeLine();

        $this->assertEquals('DPoP algs="ES256 EdDSA"', $returnValue);
    }

    private function createJwkMock(bool $toPublic = true, bool $realThumbprint = true): JwkInterface&MockObject
    {
        $mock = $this->createMock(JwkInterface::class);
        $mock->expects($this->any())
            ->method('toPublic')
            ->willReturn($toPublic ? $this->jwk->toPublic()->jsonSerialize() : $this->jwk->jsonSerialize());

        $mock->expects($this->any())
            ->method('thumbprint')
            ->willReturn($realThumbprint ? $this->jwk->thumbprint('sha256') : $this->jwk->thumbprint('sha1'));

        return $mock;
    }

    /**
     * @return array<string, string|int>
     */
    private function createDecodedPayload(): array
    {
        return [
            'iat' => $this->clock->now()->getTimestamp(),
            'htm' => self::HTM,
            'htu' => self::HTU,
            'jti' => 'abcdefghijklmnopqrstuvwxyz',
        ];
    }

    /**
     * @return array<string, string|array<string, string>>
     */
    private function createDecodedProtectedHeader(): array
    {
        return ['typ' => 'dpop+jwt', 'jwk' => $this->jwk->toPublic()->jsonSerialize(), 'alg' => 'ES256'];
    }
}
