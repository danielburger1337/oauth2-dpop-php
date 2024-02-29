# Usage as a Resource Server

> This documentation tries to explain most concepts of DPoP, but please familiarize yourself with the [Specification](https://datatracker.ietf.org/doc/html/rfc9449) before continuing.

This library uses the [DPoPProofVerifier](../src/DPoPProofVerifier.php) to verify DPoP proof tokens.
See the [Proof Verifier docs](proof_verifier.md) to learn how to conifgure the verifier.

> If you are looking for the documentation of how to send a DPoP protected request, see the [Client](client.md) docs.

## Verifying a request

Traditionally OAuth2 protected resources used the `Bearer` access token type to secure their endpoints. A bearer token simply means that _whoever_ bears the token can use it.
This authentication scheme is very simple, but offers no protection against the missuse of an access token when an adversary gets ahold of it. Unless you are aware that the token was _stolen_ and the token is able to be _revoked_, the adversary can use the access token for the remainder of its lifetime.

To solve this issue and to ensure that the access token can only be used by the user that it was issued to, the DPoP specification defines the [DPoP](https://datatracker.ietf.org/doc/html/rfc9449#figure-5) access token type.

If an access token of type `DPoP` is presented at the resource server, the resource server **MUST** ensure that a DPoP proof matching the JKT that was used to issue the access token, is included in the `DPoP` http header.

```http
https://datatracker.ietf.org/doc/html/rfc9449#figure-12

GET /protectedresource HTTP/1.1
Host: resource.example.org
Authorization: DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik\
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR\
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE\
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj\
 oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z\
 WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF\
 c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E\
 OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA
```

If the access token is included with the `Bearer` prefix in the `Authorization` http header or the `DPoP` header is missing, an error response **MUST** be returned.
See [Section 7.2](https://datatracker.ietf.org/doc/html/rfc9449#section-7.2) for more information on that.

This library provides an integraton with both [symfony/http-foundation](https://github.com/symfony/http-foundation) and [PSR-7](https://www.php-fig.org/psr/psr-7/) to verify the presented DPoP proof and access token:

```php
use danielburger1337\OAuth2\DPoP\DPoPProofVerifier;
use danielburger1337\OAuth2\DPoP\Exception\DPoPReplayAttackException;
use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPNonceException;
use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPProofException;
use Symfony\Component\HttpFoundation\Response;

$accessToken = $request->headers->get('Authorization');

// introspect the access token from the authorization header
$introspectedAccessToken = [
    'active' => true,
    'cnf' => [
        'jkt' => 'thumbprint'
    ]
];

if (!isset($introspectedAccessToken['cnf']['jkt'])) {
    // access token is not protected with DPoP
    // continue with your logic as if it was a bearer token
    return;
}

// Authorization: DPoP accesstoken
// is the required format
if (!str_starts_with($accessToken, 'DPoP ')) {
    return new Response(null, 401, [
        'WWW-Authenticate' => sprintf(
            'DPoP error="invalid_token", error_description="Invalid token.", algs="%s"',
            $verifier->getSupportedAlgorithms()
        )
    ]);
}

$verifier = new DPoPProofVerifier(...);

try {
    $accessToken = new AccessTokenModel(explode(' ', $accessToken[1]), $introspectedAccessToken['cnf']['jkt']);

    // By passing the access token, it is both verified that the DPoP proof was signed
    // using a JWK matching the cnf.jkt AND that the DPoP proof contains an "ath" claim that
    // identifies the access token
    $decodedProof = $verifier->verifyFromRequest($request, $accessToken);
} catch (MissingDPoPProofException) {
    return new Response(null, 401, [
        'WWW-Authenticate' => sprintf(
            'DPoP error="invalid_token", error_description="The presented access token requires DPoP.", algs="%s"',
            $verifier->getSupportedAlgorithms()
        )
    ]);
} catch (InvalidDPoPProofException $e) {
    return new Response(null, 401, [
        'WWW-Authenticate' => sprintf(
            'DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="%s"',
            $verifier->getSupportedAlgorithms()
        )
    ]);
} catch (InvalidDPoPNonceException $e) {
    return new Response(null, 401, [
        'WWW-Authenticate' => 'DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"'
    ]);
} catch (DPoPReplayAttackException $e) {
    return new Response(null, 401, [
        'WWW-Authenticate' => 'DPoP error="invalid_token", error_description="DPoP proof was already used"'
    ]);
}
```

### How do I know what JKT was used to issue the DPoP protected access token

This information is provided by the authorization server through [token introspection](https://datatracker.ietf.org/doc/html/rfc7662).
The introspection response will include the `cnf.jkt` parameter if the access token is protected with DPoP.

```http
https://datatracker.ietf.org/doc/html/rfc9449#figure-10

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "active": true,
  "sub": "someone@example.com",
  "iss": "https://server.example.com",
  "nbf": 1562262611,
  "exp": 1562266216,
  "cnf":
  {
    "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  }
}
```

Alternativly, if the access token is a JWT, it can include the `cnf.jkt` claim.

```jsonc
// https://datatracker.ietf.org/doc/html/rfc9449#figure-8
{
    "sub": "someone@example.com",
    "iss": "https://server.example.com",
    "nbf": 1562262611,
    "exp": 1562266216,
    "cnf": {
        "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    }
}
```
