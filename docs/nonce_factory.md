# Nonce Factory

> This documentation only applies to authorization and resource servers.

When you are the server and are verifying DPoP proofs, you have the option to require clients to include a `nonce` claim in their DPoP proof that you generated.

Nonces prevent a client from [pre-generating](https://datatracker.ietf.org/doc/html/rfc9449#section-11.2) proof tokens by making the `nonce` only valid for a short period of time (seconds or a few minutes).

This library uses the [NonceFactoryInterface](../src/NonceFactory/NonceFactoryInterface.php) interface to create and "refresh" these nonces.

The [DPoPProofVerifier](../src/DPoPProofVerifier.php) uses this factory to verify, and if necessary create new nonces.

---

## Stateful vs. Stateless

Stateful factories generate nonces and store them somewhere (most of the time in a cache or DB). This has the advantage of giving you full control of a nonce and being able to "revoke" it at any time. The drawback is concurrency. It is very hard to implement them in such a way that when a client sends concurrent requests, they don't end up creating a race condition when both have an invalid/expired nonce. Using a lock when accessing the nonce is a potential solution but currently out of scope of this library.

A stateless nonce factory entirely avoids this problem by using something arbitrary like the current timestamp to create a nonce that is valid for a specific time window. Now, when both clients are sending a request in the same time window, they will both get newly generated nonces that are valid at the same time. They also make it very easy to send the client a new DPoP nonce before their current nonce has expired (to avoid unnecesarry 400/401 errors) without pending requests starting to fail.

This library provides two different stateless implementations.

-   [WebTokenFrameworkNonceFactory](../src/NonceFactory/WebTokenFrameworkNonceFactory.php) <br>
    This generates a JWT that expires in a configured amount of time.

    See the PHPDoc for information on how to configure this factory.

-   **RECOMMENDED** [TotpNonceFactory](../src/NonceFactory/TotpNonceFactory.php) <br>
    This uses the [TOTP](https://datatracker.ietf.org/doc/html/rfc6238) standard to generate a nonce that is valid for a specified time period. The generated nonce is way shorter than the JWT implementation but keeps a comparable amount of security.

    See the PHPDoc for information on how to configure this factory.
