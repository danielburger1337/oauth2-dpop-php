### How do I know that an access token uses DPoP?

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

## Using that information

Whenever you verify an access token or create a proof token for an access token, this library uses the [AccessTokenModel](../src/Model/AccessTokenModel.php) to hold that vital information.

```php
use danielburger1337\OAuth2\DPoP\Model\AccessTokenModel;

// access token from the Authorization header
$accessToken = 'abcdef';

// introspect the access token
$introspectedAccessToken = [
    'active' => true,
    'cnf' => [
        'jkt' => 'thumbprint'
    ]
];

// pass this to DPoPProofVerifer::verifyFromRequest / DPoPProoVerifer::veriyFromRequestParts
// or pass this to DPoPProofFactory::createProof
$boundTo = new AccessTokenModel($accessToken, $introspectedAccessToken['cnf']['jkt']);
```
