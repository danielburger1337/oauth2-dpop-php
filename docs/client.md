## Usage as a Client

The client is the application that is making requests to OAuth2 and DPoP protected resources.

This library provides the [DPoPProofFactory](../src/DPoPProofFactory.php) for creating DPoP proof tokens.

See the [DPoPProofFactory](proof_factory.md) docs for more information on how to configure it.

# Nonces

As the client, you need to keep track of the servers `DPoP-Nonce`.

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

The examples below will show you how to automatically store the nonces.

## Difference between Authorization Server and Resource Server

DPoP varies slightly depending on whether you are talking to an OAuth2 authorization server or a protected resource.

Their error responses are different and it also varies a little bit with what you need to create the DPoP proof token:

This library provides an integraton with [PSR-7](https://www.php-fig.org/psr/psr-7/) to make proof creation simple.
If your applications http-client does not use PSR-7, you can use the `createProofFromRequestParts` and `storeNextNonce` of the [DPoPProofFactory](../src/DPoPProofFactory.php).

### Authorization Server

When making a request to the authorizations server `token_endpoint` endpoint, you only need to provide the `htm` and the `htu`.

```php
use danielburger1337\OAuth2\DPoP\DPoPProofFactory;
use Psr\Http\Message\ResponseInterface;

function makeTokenRequest(bool $retry = true): ResponseInterface {
    $dpopFactory = new DPoPProofFactory(...);

    // hard coded or retrieved from discovery metadata (dpop_signing_alg_values_supported)
    $serverSupportedAlgorithms = ['ES256'];

    $request = $requestFactory->createRequest('POST', 'https://op.example.com/oauth2/token');

    // see "Authorization Code" section below for information on $jkt
    // The JKT will have been stored along with your "state"/"code_verifier" during token creation
    $proof = $dpopFactory->createProofFromRequest($request, $serverSupportedAlgorithms, /** $jkt*/);

    $request = $request->withHeader('DPoP', $proof->proof);

    $response = $httpClient->sendRequest($request);

    // always store the next nonce
    // REMEMBER: the server can also include it on a successfull response
    $dpopFactory->storeNextNonceFromResponse($response, $request, $proof->jwk);

    if ($response->getStatus() === 400) {
        $body = $response->toArray();

        if ($body['error'] === 'use_dpop_nonce') {
            return makeTokenRequest(false);
        }
    }

    return $response;
}

$response = makeTokenRequest();

// do the rest of your logic
```

### OAuth2 protected resources

When making a request to an OAuth2 protected resource, you need to provide the `htm`, the `htu` and an `ath`.
The `ath` is a hash of the access token that is used to authenticate at the protected resource.
It is also required to know the JKT that the access token is bound to.
See the [Access Token](access_token.md) documentation to learn how to get this information.

```php
use danielburger1337\OAuth2\DPoP\DPoPProofFactory;
use danielburger1337\OAuth2\DPoP\Util;

function makeRequest(bool $retry = true, ?array $serverSupportedAlgorithms = null): ResponseInterface {
    $dpopFactory = new DPoPProofFactory(...);

    // hard coded or somehow discovered
    $serverSupportedAlgorithms ??= ['ES256'];

    // the access token to use
    $accessToken = 'abcdef';
    // the JKT that the token is bound to (found during token introspection)
    $jkt = '12345';

    $model = new AccessTokenModel($accessToken, $jkt);

    $request = $requestFactory->createRequest('POST', 'https://rp.example.com/protected')
        ->withHeader('Authorization', $accessToken);

    try {
        $proof = $dpopFactory->createProofFromRequest($request, $serverSupportedAlgorithms, $model);
    } catch (MissindDPoPJwkException $e) {
        // this error is thrown when the JWK the access token is bound to
        // is not registered with the token encoder
        throw $e;
    }

    $request = $request->withHeader('DPoP', $proof->proof);

    $response = $httpClient->sendRequest($request);

    // always store the next nonce
    // REMEMBER: the server can also include it on a successfull response
    $dpopFactory->storeNextNonceFromResponse($response, $request, $proof->jwk);

    if ($response->getStatus() === 401) {
        // the RP can tell you to use a different DPoP algorithm
        $wwwAuthenticate = $request->getHeaderLine('WWW-Authenticate');
        $supportedAlgorithms = Util::parseSupportedAlgorithmsFromHeader($wwwAuthenticate);

        if (str_contains($wwwAuthenticate, 'error="use_dpop_nonce"')) {
            // we stored the nonce above, so it is save to retry
            return makeRequest(false, $supportedAlgorithms);
        }

        if (str_contains($wwwAuthenticate, 'error="invalid_token"') && null !== $supportedAlgorithms) {
            // You need custom logic to know whether authorization was denied because of an
            // invalid dpop proof or whether the token has expired / is not intended for this resource.
            // This can usually be done by looking at the error_description
            return makeRequest(false, $supportedAlgorithms);
        }
    }

    return $response;
}

$response = makeTokenRequest();

// do the rest of your logic
```

## Authorization Code Flow

During the authorization code flow, you **SHOULD** make use of end-to-end token binding.

This means that the issued authorization code is already bound to the JKT that subsequent issued tokens from the `token_endpoint` will be.

To do this, you have to provide the `dpop_jkt` query parameter when redirecting the user to the `authorization_endpoint`.

This also works for [PAR](https://datatracker.ietf.org/doc/html/rfc9126) requests. Include the `dpop_jkt` inside the body of the request instead of the query parameter.

Now, the issued authorization code is bound to that JKT and can only be exchanged for an access token when the `token_endpoint` has a DPoP proof token that is signed by a JWK that matches that JKT.

To dynamically get the JKT that the authorization code should be bound to:

```php
use danielburger1337\OAuth2\DPoP\DPoPProofFactory;
use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPJwkException;

$dpopFactory = new DPoPProofFactory(...);

// hard coded or retrieved from discovery metadata (dpop_signing_alg_values_supported)
$serverSupportedAlgorithms = ['ES256'];

try {
    $jwk = $dpopFactory->getJwkToBind($serverSupportedAlgorithms);
} catch (MissingDPoPJwkException $e) {
    // thrown when no supported JWK is registered with your token encoder
    throw $e;
}

// store the JKT along side your state/code_verifier to ensure
// that when exchanging the authorization code, you use the same JWK

// now redirect the user to the authorization_endpoint
$url = 'https://op.example.com/authorize?'.http_build_query([
    'client_id' => 'your client id',
    ...
    'dpop_jkt' => $jwk->thumbprint()
]);

header('Location: ' . $url);

```

To exchange the now bound authorization code for an access token, look at the "Authorization Server" section above.
The code example mentions "$jkt" in a code comment.
