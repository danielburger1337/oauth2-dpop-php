## Token Encoder

> This section is only used for token creation.
> If your application only uses token verification, you can skip this part.

This library defines the [DPoPTokenEncoderInterface](../src/Encoder/DPoPTokenEncoderInterface.php) to encode DPoP proofs.

One concrete implementation based on [web-token/jwt-framework](https://github.com/web-token/jwt-framework) is provided.

## WebTokenFrameworkDPoPTokenEncoder

[WebTokenFrameworkDPoPTokenEncoder](../src/Encoder/WebTokenFrameworkDPoPTokenEncoder.php) takes two arguments:

-   The first is the JWK/JWKSet that you want to use to sign created tokens
-   The second is an instance of `Jose\Component\Core\AlgorithmManager` that defines what JWAs are supported for signing.<br>
    This is required to find an algorithm that is supported by both this library and the upstream server.

```php
use danielburger1337\OAuth2\DPoP\DPoPProofFactory;
use danielburger1337\OAuth2\DPoP\Encoder\WebTokenFrameworkDPoPTokenEncoder;
use danielburger1337\OAuth2\DPoP\NonceStorage\CacheNonceStorage;
use danielburger1337\OAuth2\DPoP\NonceStorage\NonceStorageKeyFactory;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\EdDSA;

$jwk = JWKFactory::createECKey('P-256');

$tokenEncoder = new WebTokenFrameworkDPoPTokenEncoder(
    $jwk,
    new AlgorithmManager([new ES256(), new EdDSA()])
);

$factory = new DPoPProofFactory(
    new Clock(), // some psr-20 implementation
    $tokenEncoder,
    new CacheNonceStorage(...),
    new NonceStorageKeyFactory()
);
```
