# Nonce Storage

> This documentation only applies to clients.

When you make requests to DPoP protected resources, most authorization servers / resource servers use the `DPoP-Nonce` header.

The DPoP specification explains it as followed:

> Malicious XSS code executed in the context of the browser-based client application is also in a position to create DPoP proofs with timestamp values in the future and exfiltrate them in conjunction with a token. These stolen artifacts can later be used independent of the client application to access protected resources. To prevent this, servers can optionally require clients to include a server-chosen value into the proof that cannot be predicted by an attacker (nonce).<br>
> ~ [Section 2](https://datatracker.ietf.org/doc/html/rfc9449#section-2)

The managing of the nonce is abstracted through the [DPoPProofFactory](proof_factory).

The factory uses the [NonceStorageInterface](../src/NonceStorage/NonceStorageInterface.php) to keep track of the server provided nonce.
One concrete implementation of that interface, the [CacheNonceStorage](../src/NonceStorage/CacheNonceStorage.php) which uses a [PSR-6](https://www.php-fig.org/psr/psr-6/) cache as storage, is provided. See the PHPDoc of its constructor to learn more information about the arguments that it takes.

If you want/need to use an incompatible storage backend, you have to implement the [NonceStorageInterface](../src/NonceStorage/NonceStorageInterface.php) interface yourself.

---

The factory also uses the [NonceStorageKeyFactoryInterface](../src/NonceStorage/NonceStorageKeyFactoryInterface.php) to generate the storage key under which the server provided nonce is stored. In pretty much all cases, the default implementation [NonceStorageKeyFactory](../src/NonceStorage/NonceStorageKeyFactory.php) is perfectly reasonable to use. It generates a hash of the combination of JKT used to sign the DPoP proof and the http URL that responded with the DPoP-Nonce header.

In case you need deeper control of that logic, you can implement the interface yourself and pass your implementation to the constructor of [DPoPProofFactory](../src/DPoPProofFactory.php).

## I know that the upstream server does not use nonces

If you know that the server you are sending requests to does not make use of the `DPoP-Nonce` header, you can use the [NullNonceStorage](../src/NonceStorage/NullNonceStorage.php) and [NullNonceStorageKeyFactory](../src/NonceStorage/NullNonceStorageKeyFactory.php) in the constructor of the [DPoPProofFactory](../src/DPoPProofFactory.php) to disable nonce support.
