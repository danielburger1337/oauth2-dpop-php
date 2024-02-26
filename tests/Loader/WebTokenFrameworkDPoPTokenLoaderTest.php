<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\Tests\Loader;

use danielburger1337\OAuth2DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2DPoP\Loader\WebTokenFrameworkDPoPTokenLoader;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(WebTokenFrameworkDPoPTokenLoader::class)]
class WebTokenFrameworkDPoPTokenLoaderTest extends TestCase
{
    private WebTokenFrameworkDPoPTokenLoader $loader;

    protected function setUp(): void
    {
        $this->loader = new WebTokenFrameworkDPoPTokenLoader(new AlgorithmManager([new ES256(), new HS256(), new None()]));
    }

    #[Test]
    public function loadProof_returnsExpected(): void
    {
        // {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC"...}.{"iat": 1708956826,"ath":"123","nonce":"abc"}
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiSUpRcm5FNTVBeXcycVFmcnFjRnJRSGdCdTNCTnFmUUUxLTdzYU03OVN4YyIsInkiOiJWTGFkLVdyZXJnUGdnSzI4T0VrdmlsR0VDZ1ppeU5NUVlIV2FVZGtTd0RVIn19.eyJpYXQiOjE3MDg5NTY4MjYsImF0aCI6IjEyMyIsIm5vbmNlIjoiYWJjIn0.uEf2x9f6tpmGWuwrBVQaC8rJp3VJ-AdlAA7SPdbY7ukTsulR8So09bgd9xYneJm1nE1U3ec1bO-MEzZ_VBggMA';

        $returnValue = $this->loader->loadProof($proof);

        $this->assertEquals('MIzAqZn7LRtWcKtGvHX65PBMo9rYaiKzhJTZLZxU0Hk', $returnValue->jwk->thumbprint());
        $this->assertEquals([
            'iat' => 1708956826,
            'ath' => '123',
            'nonce' => 'abc',
        ], $returnValue->payload);
        $this->assertEquals([
            'typ' => 'dpop+jwt',
            'alg' => 'ES256',
            'jwk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'IJQrnE55Ayw2qQfrqcFrQHgBu3BNqfQE1-7saM79Sxc',
                'y' => 'VLad-WrergPggK28OEkvilGECgZiyNMQYHWaUdkSwDU',
            ],
        ], $returnValue->protectedHeader);
    }

    #[Test]
    public function loadProof_notAJwt_throwsException(): void
    {
        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The presented DPoP proof is not in a supported JWT format.');

        $this->loader->loadProof('not a jwt');
    }

    #[Test]
    public function loadProof_noJwkInHeader_throwsException(): void
    {
        // {"typ":"dpop+jwt","alg":"ES256"}.{"iat": 1708956826,"ath":"123","nonce":"abc"}
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0.eyJpYXQiOjE3MDg5NTY4MjYsImF0aCI6IjEyMyIsIm5vbmNlIjoiYWJjIn0.G-EsowaAiZL6kG1sb8pqCkfZU6dMu_jUvvTzvC_0RR7bRSZPv4RZXsHBoE1-ZpyhkLcfL1ukUnykvQxew0gX1A';

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('Failed to get "jwk" from DPoP proof header.');

        $this->loader->loadProof($proof);
    }

    #[Test]
    public function loadProof_privateJwkInHeader_throwsException(): void
    {
        // {"typ":"dpop+jwt","alg":"ES256","jwk":{...}.{"iat": 1708956826,"ath":"123","nonce":"abc"}
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJkIjoicW00T2MyM1JSMmVBQnB4aHZiU1hLT2NGRmtDQXFYcE5GWV81U2FUZDRScyIsIngiOiJXVUNZNTh1WEZIY2VTNE9ycVlFUzV1UFJTSm8tNWs4UGljS3ZubEZEYlo0IiwieSI6IlVaMjhWd3FfS0FRTVNkdDh6WnBoSzhtWXRPNTFRbkdSNTFiZnJVUEJqOWcifX0.eyJpYXQiOjE3MDg5NTY4MjYsImF0aCI6IjEyMyIsIm5vbmNlIjoiYWJjIn0.mpUwGWjSii80WuIAu9mN6pILfBD7FZv4vBDMU3Bap4agMFbHf27yjA_-Ab5zfsf2-ZgR8es-ZuI1D212z0PjBQ';

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('DPoP proof must not contain a private key in the "jwk" header parameter.');

        $this->loader->loadProof($proof);
    }

    #[Test]
    public function loadProof_unsupportedAlgorithm_throwsException(): void
    {
        // {"typ":"dpop+jwt","alg":"EdDSA","jwk":{...}.{"iat": 1708956826,"ath":"123","nonce":"abc"}
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVkRFNBIiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiU1M4Q1RzdFFQdjl1ZW9lT3c1Q0xWQWNRN1BMMG9mVnFjTmgxcUY4ZGZEZyJ9fQ.eyJpYXQiOjE3MDg5NTY4MjYsImF0aCI6IjEyMyIsIm5vbmNlIjoiYWJjIn0.Ud_4w9tOTD3cgA_7x6mnY957xog71osp0pdDmdxe_MbATpJRgXTDEcQr6d45hte9jic1N9ER7SD1D1O54bB2Bw';

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof either has an invalid signature or uses an unsupported algorithm.');

        $this->loader->loadProof($proof);
    }

    #[Test]
    public function loadProof_invalidSignature_throwsException(): void
    {
        // {"typ":"dpop+jwt","alg":"EdDSA","jwk":{...}.{"iat": 1708956826,"ath":"123","nonce":"abc"}
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVkRFNBIiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiU1M4Q1RzdFFQdjl1ZW9lT3c1Q0xWQWNRN1BMMG9mVnFjTmgxcUY4ZGZEZyJ9fQ.eyJpYXQiOjE3MDg5NTY4MjYsImF0aCI6IjEyMyIsIm5vbmNlIjoiYWJjIn0.invalidsignature';

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof either has an invalid signature or uses an unsupported algorithm.');

        $this->loader->loadProof($proof);
    }

    #[Test]
    public function loadProof_signedByOtherJwk_throwsException(): void
    {
        // the "jwk" in the header is not the one that signed the token

        // {"typ":"dpop+jwt","alg":"ES256","jwk":{...}.{"iat": 1708956826,"ath":"123","nonce":"abc"}
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid3BsTVhFNzl1QlZLSkY4Rkl3MVpkbmk1dXdDeXlWUnlVc2dOS0JzQWNiVSIsInkiOiJlSHVPOEMwcUxzanNqNVIxaTlXdnJHS0xvR1hrVEFia21Fa1pSSVg4MDZBIn19.eyJpYXQiOjE3MDg5NTY4MjYsImF0aCI6IjEyMyIsIm5vbmNlIjoiYWJjIn0.JBRhMZ3z0ePYQEOrGf8uTV14u-S0B4FgTYM-i-Up6Hz_RLT384SlQh1a6ZXaTO_EQKBqrgQHPS0GFvV4gz3Y9A';

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof either has an invalid signature or uses an unsupported algorithm.');

        $this->loader->loadProof($proof);
    }

    #[Test]
    public function loadProof_missingAlgHeader_throwsException(): void
    {
        // {"typ":"dpop+jwt","jwk":{...}.{"iat": 1708956826,"ath":"123","nonce":"abc"}
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ik91U2x3OGNEX042WW9EZE5xMjlRYkd0YzRTR2NEaERPaHVKa0J5aU9YbjAiLCJ5IjoiWWxpVzU2cHAybUpUWnBXMlRJb2tlbzVFMm9RRkpQY2U2cERrbVVPSmtNbyJ9fQ.eyJpYXQiOjE3MDg5NTY4MjYsImF0aCI6IjEyMyIsIm5vbmNlIjoiYWJjIn0.SeuoDSzk2iOdGFa3wlxo4LUKsuETgMeoUm4XBnABktVqkuC7V2mzlnSAZj7FJ_6e1qbNuP4TLG_7xaZwhtpt8w';

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof either has an invalid signature or uses an unsupported algorithm.');

        $this->loader->loadProof($proof);
    }

    #[Test]
    public function loadProof_macAlgorithm_throwsException(): void
    {
        // {"typ":"dpop+jwt","alg":"HS256","jwk":{"kty":"oct"...}.{"iat": 1708956826,"ath":"123","nonce":"abc"}
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkhTMjU2IiwiandrIjp7Imt0eSI6Im9jdCIsImsiOiJuM2JjU0RFUFBUdTB3cW10enlSSmMxbkp1Zlh6Mm94SFJiVFFDaEhGNmRVIn19.eyJpYXQiOjE3MDg5NTY4MjYsImF0aCI6IjEyMyIsIm5vbmNlIjoiYWJjIn0.zQ2PZl32eKr6yj9kRyllFPn0Wr7ZiHWDQf4AE5rxED0';

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof must not use a symmetric signature algorithm (MAC).');

        $this->loader->loadProof($proof);
    }

    #[Test]
    public function loadProof_noneAlgorithm_throwsException(): void
    {
        // {"typ":"dpop+jwt","alg":"none","jwk":{"kty":"none"...}.{"iat": 1708956826,"ath":"123","nonce":"abc"}
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6Im5vbmUiLCJqd2siOnsia3R5Ijoibm9uZSIsImFsZyI6Im5vbmUiLCJ1c2UiOiJzaWcifX0.eyJpYXQiOjE3MDg5NTY4MjYsImF0aCI6IjEyMyIsIm5vbmNlIjoiYWJjIn0.';

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof must not use the "none" signature algorithm.');

        $this->loader->loadProof($proof);
    }

    #[Test]
    public function loadProof_invalidPayload_throwsException(): void
    {
        // {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC"...}.null
        $proof = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiQm5DNGNwcmNZck5hSm8tYTlJdFlKZFdIYS1OUkc4Q0RSMTAyNk4zRGpZbyIsInkiOiJBTUVQYkF5U2ZsY3h4MzdSWExwSURzd1FVLUdhRFlOTEMwWHJFWlBKZGJRIn19.bnVsbA.RWTiF1-s2bBVR2I6fJh6JS3k0M2SAW0EZm3xBr9T1rPqqJIHFOhMbDSMR_rbpi5RoKaNnakEB8u334aVPdC0bQ';

        $this->expectException(InvalidDPoPProofException::class);
        $this->expectExceptionMessage('The DPoP proof has an invalid payload.');

        $this->loader->loadProof($proof);
    }

    /**
     * @param string[] $expected
     */
    #[Test]
    #[DataProvider('algorithmManagerDataProvider')]
    public function getSupportedAlgorithms_returnsList(AlgorithmManager $algorithmManager, array $expected): void
    {
        $loader = new WebTokenFrameworkDPoPTokenLoader($algorithmManager);

        $returnValue = $loader->getSupportedAlgorithms();

        $this->assertEquals($expected, $returnValue);
    }

    /**
     * @return array<array{0: AlgorithmManager, 1: string[]}>
     */
    public static function algorithmManagerDataProvider(): array
    {
        return [
            [new AlgorithmManager([new ES256()]), ['ES256']],
            [new AlgorithmManager([new ES256(), new RS256()]), ['ES256', 'RS256']],
            [new AlgorithmManager([new ES256(), new RS256(), new PS256()]), ['ES256', 'RS256', 'PS256']],
        ];
    }
}
