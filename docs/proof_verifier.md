# Configuring the DPoP Proof Verifier

This library provides the [DPoPProofVerifier](../src/DPoPProofVerifier.php). Its only mandatory dependencies are a [PSR-20](https://www.php-fig.org/psr/psr-20/) compliant clock and an implementation of this libraries [DPoPProofTokenLoaderInterface](../src/Loader/DPoPTokenLoaderInterface.php).

See the [Token Loader](token_loader.md) docs to see what implementations are available or how to create your own.

It also has optional dependencies to support the [DPoP-Nonce](https://datatracker.ietf.org/doc/html/rfc9449#section-8) header and to detect [replay attacks](https://datatracker.ietf.org/doc/html/rfc9449#section-11.1).

Please see the [Replay Attack](replay_attack.md) and [Nonce Factory](nonce_factory.md) docs for more information.

```php
use danielburger1337\OAuth2\DPoP\DPoPProofVerifier;
use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPProofException;
use danielburger1337\OAuth2\DPoP\NonceFactory\TotpNonceFactory;
use danielburger1337\OAuth2\DPoP\ReplayAttack\CacheReplayAttackDetector;

$verifier = new DPoPProofVerifier(
    // Required: PSR-20 implementation
    new Clock(),
    // Required: DPoPTokenLoaderInterface implementation
    new WebTokenFrameworkDPoPProofTokenLoader(...),
    // Optional: NonceFactoryInterface implementation or null to disable
    new TotpNonceFactory(...),
    // Optional: ReplayAttackDetectorInterface implementation or null to disable
    new CacheReplayAttackDetector(...),
    // Optional: Allowed time drift of the "iat" claim (not every client has a perfectly synchronized clock)
    5,
    // Optional: Maximum age in seconds of the presented DPoP proof
    30
);
```
