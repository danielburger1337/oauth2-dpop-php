# Usage as the Authorization Server

> This documentation tries to explain most concepts of DPoP, but please familiarize yourself with the [Specification](https://datatracker.ietf.org/doc/html/rfc9449) before continuing.

The authorization server only verifies DPoP proof tokens. It does not create them.

This library uses the [DPoPProofVerifier](../src/DPoPProofVerifier.php) to verify DPoP proof tokens.
See the [Verifier docs](verifier.md) to learn how to conifgure the verifier.

## Token Requests

In a token request (a request to your `token_endpoint`), the client can specify a `DPoP` http header containing the DPoP proof token in form of a JWT.<br>
If DPoP is required by either the client configuration (see [Section 5.2](https://datatracker.ietf.org/doc/html/rfc9449#section-5.2)) or your servers policy, the request **MUST** fail.

This library provides an integraton with both [symfony/http-foundation](https://github.com/symfony/http-foundation) and [PSR-7](https://www.php-fig.org/psr/psr-7/):

```php
use danielburger1337\OAuth2\DPoP\DPoPProofVerifier;
use danielburger1337\OAuth2\DPoP\Exception\DPoPReplayAttackException;
use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPNonceException;
use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPProofException;
use Symfony\Component\HttpFoundation\Response;

$verifier = new DPoPProofVerifier(...);

try {
    // http-foundation or PSR-7
    $decodedProof = $verifier->verifyFromRequest($request);
} catch (MissingDPoPProofException) {
    if ($client->requiresDPoPBoundAccessTokens() || $authorizationServerPolicy->requiresDPoPBoundAccessTokens()) {
        return new Response(json_encode([
            'error' => 'invalid_dpop_proof',
            'error_description' => 'Missing required DPoP header.'
        ]), 400);
    }

    // else: do nothing
} catch (InvalidDPoPProofException|DPoPReplayAttackException $e) {
    return new Response(json_encode([
        'error' => 'invalid_dpop_proof',
        'error_description' => $e->getMessage()
    ]), 400);
} catch (InvalidDPoPNonceException $e) {
    return new Response(json_encode([
        'error' => 'use_dpop_nonce',
        'error_description' => $e->getMessage()
    ]), 400, [
        'DPoP-Nonce' => $e->newNonce
    ]);
}
```

If your application does not use either PSR-7 or http-foundation, you can use the [DPoPProofVerifier::verifyFromRequestParts](../src/DPoPProofVerifier.php) method manually.
This method does **NOT** throw [MissingDPoPProofException](../src/Exception/MissingDPoPProofException.php). You have to check yourself before calling the `verifyFromRequestParts` method if the http header is present and whether the request is allowed to continue if it is not.

---

## Authorization Code Flow

> Using JKT binding for the authorization code is entirely optional (even if the client configuration requires DPoP bound access tokens), but highly recommended.

Specifing the JKT that the authorization code must be bound to adds an extra level of security by ensuring complete end-to-end binding of the entire authorization flow.

During the authorization code flow, the client can specify the `dpop_jkt` query parameter that must be stored alongside the authorization code.
This parameter contains the JWK thumbprint (JKT) that the authorization code and subsequent issued access token must be bound to.

When the client is now exchanging their authorization code at your `token_endpoint`, the attached DPoP proof must have been signed with a JWK that matches that thumbprint.

The authorization code flow uses the `dpop_jkt` query paramter because it is not possible when redirecting the user to your `authorization_endpoint` to include custom http headers.

---

## Pushed Authorization Requests (PAR)

If your authorization server supports [PAR](https://datatracker.ietf.org/doc/html/rfc9126) and supports end-to-end binding, your implementation **MUST** both support the `dpop_jkt` request paramter as well as the `DPoP` header.

If the client only specifies the `dpop_jkt` request parameter, the control flow is the same as if the parameter was attached to the query parameter at the `authorization_endpoint`.

If the client only specifies the `DPoP` http header, the authorization code and subsequent issued access token must be bound to the JKT of the JWK that was used to sign this DPoP proof.

If the client specifies both, the DPoP headers JKT **MUST** match the JKT provided in the `dpop_jkt` request parameter.

The following is a control flow example using http-foundation:

```php
use danielburger1337\OAuth2\DPoP\DPoPProofVerifier;
use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPNonceException;
use danielburger1337\OAuth2\DPoP\Exception\InvalidDPoPProofException;
use danielburger1337\OAuth2\DPoP\Exception\MissingDPoPProofException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class PushedAuthorizationRequest
{
    private DPoPProofVerifier $dpopVerifier;

    public function getDPoPJktToBind(Request $request): ?string
    {
        /** @var string|null */
        $jkt = null;

        if ($request->request->has('dpop_jkt')) {
            $jkt = $request->request->getString('dpop_jkt');
        }

        try {
            // NOTICE THE SECOND ARGUMENT
            // This ensures that the DPoP proof is signed with a JWK that matches that JKT
            $decodedProof = $this->dpopVerifier->verifyFromReqeust($request, $jkt);

            return $decodedProof->jwk->thumbprint();
        } catch (MissingDPoPProofException) {
            // DPoP header doesnt exist
            // Fallback to the request parameter
            return $jkt;
        } catch (InvalidDPoPProofException $e) {
            $response = new Response(json_encode([
                'error' => 'invalid_dpop_proof',
                'error_description' => $e->getMessage()
            ]), 400);

            // somehow send that response to the client
            throw $response;
        } catch (InvalidDPoPNonceException $e) {
            $response = new Response(json_encode([
                'error' => 'use_dpop_nonce',
                'error_description' => $e->getMessage()
            ]), 400, [
                'DPoP-Nonce' => $e->newNonce
            ]);

            // somehow send that response to the client
            throw $response;
        }
    }
}

$par = new PushedAuthorizationRequest();
$jkt = $par->getDPoPJktToBind();
 if (null === $jkt && ($client->requiresDPoPBoundAccessTokens() || $authorizationServerPolicy->requiresDPoPBoundAccessTokens())) {
    return new Response(json_encode([
        'error' => 'invalid_dpop_proof',
        'error_description' => 'Missing required DPoP header.'
    ]), 400);
}

// attach the JKT to the authorization request
```
