## What is a nonce?

The [DPoP specification](https://datatracker.ietf.org/doc/html/rfc9449) defines the `DPoP-Nonce` header. It tells the client that the DPoP proof token MUST contain a `nonce` claim with the specified header value. This mechanism prevents an application from pre-generating DPoP proof tokens.

## Nonces when creating DPoP proof tokens

When you are the client (aka. making the request to a protected endpoint), you need to keep track of the upstream servers nonce.

The [DPoPProofFactory](../src/DPoPProofFactory.php) automatically attaches the currently stored nonce to the generated DPoP proof token.

See the [Nonce Storage](nonce_storage.md) documentation for more information on how to configure it.

If no nonce is currently stored, the `nonce` claim will be ommited from the generated DPoP token and the next request is expected to fail.

-   If the upstream server is an authorization server, the http response will look like

    ```http
    HTTP/1.1 400 Bad Request
    DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v

    {
    "error": "use_dpop_nonce",
    "error_description": "Authorization server requires nonce in DPoP proof"
    }
    ```

-   If the upstream server is a resource server, the http response will look like

    ```http
    HTTP/1.1 401 Unauthorized
    WWW-Authenticate: DPoP error="use_dpop_nonce",
    error_description="Resource server requires nonce in DPoP proof"
    DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v
    ```

You must now store the new `DPoP-Nonce` value, create a new DPoP proof token (which will use the stored nonce) and then retry the request.

Regardless of http status code, you must always check if the upstream server included a `DPoP-Nonce` header.
To optimize network traffic (to prevent an unnecessary 400/401 error), the upstream server can include a new nonce within a successfull response.
The specification requires the client (YOU) to use the supplied nonce in each subsequent request until a new nonce is issued.

```php
use danielburger1337\OAuth2\DPoP\DPoPProofFactory;
use danielburger1337\OAuth2\DPoP\Util;

// hard coded or retrieved from discovery metadata
$serverSupportedAlgorithms = ['ES256'];

$dpopFactory = new DPoPProofFactory(...);

$request = $requestFactory->createRequest('POST', 'https://op.example.com/oauth2/token');

$proof = $dpopFactory->createProofFromRequest($request, $serverSupportedAlgorithms);

$request = $request->withHeader('DPoP', $proof->proof);

$response = $httpClient->sendRequest($request);

// call this or $dpopFactory->storesNextNonce() after every request
$dpopFactory->storeNextNonceFromResponse($response, $request, $proof->jwk);

// do your logic
if ($response->getStatus(200)) {
    ...
}

$body = $response->toArray();

// if upstream is a authorization server
if ($response->getStatus(400) && 'use_dpop_nonce' === ($body['error'] ?? null)) {
    // retry the request
    $proof = $dpopFactory->createProofFromRequest($request, $serverSupportedAlgorithms);
    $request = $request->withHeader('DPoP', $proof->proof);
    $response = $httpClient->sendRequest($request);
}

// if upstream is a resource server
if ($response->getStatus(401) && str_contains($response->getHeaderLine('www-authentication'), 'error="use_dpop_nonce"')) {
    // retry the request
    $proof = $dpopFactory->createProofFromRequest($request, $serverSupportedAlgorithms);
    $request = $request->withHeader('DPoP', $proof->proof);
    $response = $httpClient->sendRequest($request);
}
```

## Nonces when verifying DPoP proof tokens

When you are the server (aka. clients are making requests to your protected endpoints), you can require clients to use a `nonce` inside their DPoP proof token to prevent them from pre-generating tokens.

> This feature is highly recommended but not mandatory.<br>
> To opt out of this, use `null` as the [DPoPProofVerifier::$nonceFactory](../src/DPoPProofVerifier.php) constructor argument.

With this library, you either have the choice of using a stateful or stateless nonce factory that implements [NonceFactorInterface](../src/NonceFactory/NonceFactoryInterface.php).

Stateful factories generate nonces and store them somewhere (most of the time in a cache or DB). This has the advantage of giving you full control of a nonce and being able to "revoke" it at any time. The drawback is concurrency. It is very hard to implement them in such a way that when a client sends concurrent requests, they don't end up creating a race condition when both have an invalid/expired nonce. Using a lock when accessing the nonce is a potential solution but currently out of scope of this library.

A stateless nonce factory entirely avoids this problem by using something arbitrary like the current timestamp to create a nonce that is valid for a specific time window. Now, when both clients are sending a request in the same time window, they will both get newly generated nonces that are valid at the same time. They also make it very easy to send the client a new DPoP nonce before their current nonce has expired (to avoid unnecesarry 400/401 errors) without pending requests starting to fail.

This library provides two different stateless implementations.

-   [WebTokenFrameworkNonceFactory](../src/NonceFactory/WebTokenFrameworkNonceFactory.php) <br>
    This generates a JWT that expires in a configured amount of time.

    See the PHPDoc for information on how to configure this factory.

-   **RECOMMENDED** [TotpNonceFactory](../src/NonceFactory/TotpNonceFactory.php) <br>
    This uses the [TOTP](https://datatracker.ietf.org/doc/html/rfc6238) standard to generate a nonce that is valid for a specified time period. The generated nonce is way shorter than the JWT implementation but keeps a comparable amount of security.

    See the PHPDoc for information on how to configure this factory.

The [DPoPProofVerifier](../src/DPoPProofVerifier.php) throws an [InvalidDPoPNonceException](../src/Exception/InvalidDPoPNonceException.php) when ever the provided DPoP proof token has in invalid `nonce` claim or it is entirely missing.

```php
use danielburger1337\OAuth2\DPoP\DPoPProofVerifier;
use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPNonceException;

$verifier = new DPoPProofVerifier(...);

try {
    // http-foundation or psr-7
    // use verifyFromRequestParts otherwise
    $decodedProof = $verifier->verifyFromRequest($request, /** $accessToken */);
} catch (InvalidDPoPNonceException $e) {
    // as OP
    return new Response(json_encode(['error' => 'use_dpop_nonce']), 400, ['DPoP-Nonce' => $e->newNonce]);

    // as RP
    return new Response(null, 401, [
        'DPoP-Nonce' => $e->newNonce,
        'WWW-Authenticate' => 'DPoP error="use_dpop_nonce"'
    ]);
}
```
