<?php declare(strict_types=1);

namespace danielburger1337\OAuth2\DPoP\NonceStorage;

use danielburger1337\OAuth2\DPoP\Model\JwkInterface;
use Uri\InvalidUriException;
use Uri\Rfc3986\Uri;

class NonceStorageKeyFactory implements NonceStorageKeyFactoryInterface
{
    public function createKey(JwkInterface $jwk, string $htu): string
    {
        $scheme = $host = $e = null;

        if (\PHP_VERSION_ID >= 80500) {
            try {
                $url = new Uri($htu);
                $scheme = $url->getScheme();
                $host = $url->getHost();
            } catch (InvalidUriException $e) {
            }
        } else {
            $parts = \parse_url($htu);
            if (false !== $parts) {
                $scheme = $parts['scheme'] ?? null;
                $host = $parts['host'] ?? null;
            }
        }

        if (empty($scheme) || empty($host)) {
            throw new \InvalidArgumentException('The htu has an invalid scheme or host.', previous: $e);
        }

        return \hash('xxh3', $jwk->thumbprint().\strtolower($scheme.$host));
    }
}
