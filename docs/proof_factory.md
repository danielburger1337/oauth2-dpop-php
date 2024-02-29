# Configuring the DPoP Proof Factory

> This documentation only applies to clients.

This library provides the [DPoPProofFactory](../src/DPoPProofFactory.php) to create DPoP proof tokens.

Its two main components are an implementation of [DPoPTokenEncoderInterface](../src/Encoder/DPoPTokenEncoderInterface.php) and an implementation of [NonceStorageInterface](../src/NonceStorage/NonceStorageInterface.php).

See the [Token Encoder](token_encoder.md) docs to see what implementations are available or how to create your own.
See the [Nonce Storage](nonce_storage.md) docs to see what implementations are available or how to create your own.

```php
use danielburger1337\OAuth2\DPoP\DPoPProofFactory;
use danielburger1337\OAuth2\DPoP\Encoder\WebTokenFrameworkDPoPProofTokenEncoder;
use danielburger1337\OAuth2\DPoP\NonceStorage\CacheNonceStorage;
use danielburger1337\OAuth2\DPoP\NonceStorage\NonceStorageKeyFactory;

$verifier = new DPoPProofFactory(
    // Required: PSR-20 implementation
    new Clock(),
    // Required: DPoPTokenLoaderInterface implementation
    new WebTokenFrameworkDPoPProofTokenEncoder(...),
    // Required: NonceStorageInterface implementation
    new CacheNonceStorage(...),
    // Optional: NonceStorageKeyFactoryInterface implementation
    new NonceStorageKeyFactory(...),
    // Optional: Length of the generated "jti" claim
    32,
);
```
