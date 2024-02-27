<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\NonceStorage;

use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;

class CacheNonceStorage implements NonceStorageInterface, NonceVerificationStorageInterface
{
    /**
     * @codeCoverageIgnore
     */
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly \DateInterval $ttl = new \DateInterval('PT15M')
    ) {
    }

    public function createNewNonce(string $thumbprint): string
    {
        $nonce = $this->generateNonce();

        $item = $this->cache->getItem($nonce);

        $item->set($nonce);
        $item->expiresAfter($this->ttl);

        $this->cache->save($item);

        return $nonce;
    }

    public function createNewNonceIfInvalid(string $thumbprint, string $nonce): string|null
    {
        try {
            $item = $this->cache->getItem($nonce);

            if ($item->isHit()) {
                return null;
            }
        } catch (InvalidArgumentException) {  // @codeCoverageIgnore
        }

        return $this->createNewNonce($thumbprint);
    }

    public function getCurrentNonce(string $key): string|null
    {
        $item = $this->cache->getItem($key);
        if (!$item->isHit()) {
            return null;
        }

        $nonce = $item->get();

        return \is_string($nonce) ? $nonce : null;
    }

    public function storeNextNonce(string $key, string $nonce): void
    {
        $item = $this->cache->getItem($key);
        $item->set($nonce);
        $item->expiresAfter($this->ttl);

        $this->cache->save($item);
    }

    protected function generateNonce(): string
    {
        return \bin2hex(\random_bytes(32));
    }
}
