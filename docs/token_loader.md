## Token Loader

> This section is only used for token verification.
> If your application only uses token creation, you can skip this part.

This library defines the [DPoPTokenLoaderInterface](../src/Loader/DPoPTokenLoaderInterface.php) to load DPoP proofs for verification.

One concrete implementation based on [web-token/jwt-framework](https://github.com/web-token/jwt-framework) is provided.

## WebTokenFrameworkDPoPTokenLoader

[WebTokenFrameworkDPoPTokenLoader](../src/Loader/WebTokenFrameworkDPoPTokenLoader.php) only takes one argument.
That argument is an instance `Jose\Component\Core\AlgorithmManager` that defines what JWAs are supported.

```php
use danielburger1337\OAuth2\DPoP\DPoPProofVerifier;
use danielburger1337\OAuth2\DPoP\Loader\WebTokenFrameworkDPoPTokenLoader;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\EdDSA;

$clock = new Clock(); // some psr-20 implementation

$tokenLoader = new WebTokenFrameworkDPoPTokenLoader(
    new AlgorithmManager([new ES256(), new EdDSA()])
);

$verifier = new DPoPProofVerifier($clock, $tokenLoader);
```
