## DPoP Proof Replay

See section [11.1](https://datatracker.ietf.org/doc/html/rfc9449#section-11.1) from RFC-9449 as reference:

The `DPoP-Nonce` is not a cryptographic nonce and therefor it is acceptable for clients to use the same nonce multiple times and for the server to accept the same nonce multiple times.

---

> If an adversary is able to get hold of a DPoP proof JWT, the adversary could replay that token at the same endpoint (the HTTP endpoint and method are enforced via the respective claims in the JWTs).

To combat against this attack vector, [DPoPProofVerifier](../src/DPoPProofVerifier.php) has the `$allowedMaxAge` constructor argument. This argument sets maximum amount of seconds in the past allowed, that the DPoP proof was issued. If the DPoP proof was issued before that cut-off time, an [InvalidDPoPProofException](../src/Exception/InvalidDPoPProofException.php) is thrown.

Together with a DPoP-Nonce that rotates in a timespan of seconds or minutes, this offers good protection but still allows an adversary to replay a token immediatly after it was captured.

---

## Further Prevention

> This feature is highly recommended but not mandatory.<br>
> To opt out of this, use `null` as the [DPoPProofVerifier::$replayAttackDector](../src/DPoPProofVerifier.php) constructor argument.

To prevent DPoP proof tokens being used multiple times, this library provides the [ReplayAttackDetectorInterface](../src/ReplayAttack/ReplayAttackDetectorInterface.php) with the [CacheReplayAttackDetector](../src/ReplayAttack/CacheReplayAttackDetector.php) implementation that uses a PSR-6 cache as storage. This stores a hash of the `jti` claim and used JKT of every DPoP token for a specified amount of time (ideally the same lifetime as `DPoPProofVerifier::$allowedMaxAge`) and prevents them being used together multiple times in that time frame by throwing a [DPoPReplayAttackException](../src/Exception/DPoPReplayAttackException.php).

```php

$detector = new CacheReplayAttackDetector(...);
$verifier = new DPoPProofVerifier(..., $detector, ...);

try {
    $verifier->verifyFromRequest($request);
} catch (DPoPReplayAttackException $e) {
    // as the OP
    return new Response(json_encode(['error' => 'invalid_dpop_proof']), 400);

    // as the RP
    return new Response(null, 401, [
        'WWW-Authenticate' => 'DPoP error="invalid_token" error_description="DPoP proof was already used."'
    ]);
}

```

> In the context of the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP proof. HTTP requests to the same URI for which the jti value has been seen before would be declined. When strictly enforced, such a single-use check provides a very strong protection against DPoP proof replay, but it may not always be feasible in practice, e.g., when multiple servers behind a single endpoint have no shared state.
