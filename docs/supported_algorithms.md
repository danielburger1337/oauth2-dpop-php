# What DPoP algorithms does this library support?

DPoP uses signed JWTs. The specification defines an allowed algorithm as followed:

> An identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS](https://www.iana.org/assignments/jose/jose.xhtml). It MUST NOT be none or an identifier for a symmetric algorithm (Message Authentication Code (MAC)).

To put it simple, this library supports all JWS asymmetric digital signatures that your implementation supports.

# How do I know what DPoP algorithms are supported by the upstream server?

Whenever you want to create a new DPoP proof with the [DPoPProofFactory](../src/DPoPProofFactory.php), you have to provide the upstream servers supported algorithms.
The [DPoP specification](https://datatracker.ietf.org/doc/html/rfc9449#section-5.1) defines two ways of dynamically dicovering what DPoP algorithms are supported:

-   Via the `dpop_signing_alg_values_supported` discovery metadata value
-   Via the `WWW-Authenticate` header when no / an invalid DPoP proof was presented

Alternativly you can hard code the supported algorithms. The `ES256` algorithm is the most commonly used algorithm.
It offers great security with a very short key size.

```php
use danielburger1337\OAuth2\DPoP\DPoPProofFactory;
use danielburger1337\OAuth2\DPoP\Util;

$dpopFactory = new DPoPProofFactory(...);

// hard coded or retrieved from discovery metadata
$serverSupportedAlgorithms = ['ES256'];

$request = $requestFactory->createRequest('GET', 'https://op.example.com/protected');
$proof = $dpopFactory->createProofFromRequest($request, $serverSupportedAlgorithms);
$request = $request->withHeader('DPoP', $proof->proof);
$response = $httpClient->sendRequest($request);

if ($response->getStatus() === 401 && str_contains('error="invalid_token"', $wwwAuthenticate)) {
    throw new \Exception('Access Token has expired.');
}

if ($response->getStatus() === 400 || $response->getStatus() === 401) {
    $wwwAuthenticate = $request->getHeaderLine('WWW-Authenticate');

    $supportedAlgorithms = Util::parseSupportedAlgorithmsFromHeader($wwwAuthenticate);
    $supportedAlgorithms ??= $serverSupportedAlgorithms;

    // retry the request
    $proof = $dpopFactory->createProofFromRequest($request, $supportedAlgorithms);
    $request = $request->withHeader('DPoP', $proof->proof);
    $response = $httpClient->sendRequest($request);
}
```

---

## As the token verifier

When you are the token verifier, you decide what algorithms are supported.
This is done in the implementation of [DPoPTokenLoaderInterface](../src/Loader/DPoPTokenLoaderInterface.php) that is passed to [DPoPProofVerifier](../src/DPoPProofVerifier.php) via its constructor.

This library provides the concrete [WebTokenFrameworkDPoPTokenLoader](../src/Loader/WebTokenFrameworkDPoPTokenLoader.php) implementation that uses the [web-token/jwt-framework](https://github.com/web-token/jwt-framework).

The JWT-Framework supports pretty much all existing JWAs.

See [Token Loader](./token_loader.md) for more information.
