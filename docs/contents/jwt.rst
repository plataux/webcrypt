JOSE Standard
=============

A few terms:

* JWK is a single cyptographic key that can be used for one or more purposes
* JWKS is a keyset, that can be used collective for one or multiple purposes
* JWT a token to be exchanged between internal or external applications, which can be:

    * JWS that is signed and verified within the same organization, or across different ones
    * JWE to encrypt and decrypt content


a JWK object
************

* A runtime object that has been validated, and ready for high performance production use
* Can be stored in JSON format along with its current config and parameters, that can change over time
* Can be loaded from an existing JSON jwk including all parameters, uses and algorithms
* JWK is expected to have a lifetime, rotation with other keys during operation, and eventually retired
* capabilities, uses or operations can change over time. For example to retire certain keys From doing future encryptions or signing, but kept to perform decryption and verifying of existing tokens. These changes operational changes must be stored in the JSON JWK format.
* Can be loaded from other formats such as PEM, DER or base16 or bas64 representations
* when loaded from none JSON JWK formats, can optionally accept config and parameters, but
* can also default recommended setup for alg, keysizes, etc.



RSA Private Key
---------------

* Signing (RS256-384-512 and PS256-384-512)
* Verifying
* Encryption (For wrapping an AES128-192-256 key)
* Decryption

RSA Public Key
    * Verifying
    * Encryption


EC Private Key
    * Signing
    * Verifying
    * Deriving an AES key with another Public Key


EC Public Key
    * Verifying


HMAC Key
    * Signing
    * Verifying

AES Key
    * Encryption (Dir or KW)
    * Decryption


JWT Encoding
************

This step is the easiest part, which usually happens at the server, and the least susceptible
to most forms of security attacks.

* Verify structural and data type validity of all claims of the Token using pydantic
* In general, the Payload must be JSON serializable, with a few data types allowed, including

    * string
    * int
    * float
    * bool
    * arrays
    * object
* In general though, JWT standard
* Define and verify the mandatory fields during encoding, like the at_hash and other claims
* Verify logical correctness of the token: the ``iat`` ``nbf`` and ``exp`` claims specially
* Base64 encode the payload, and pass it for signing

JWT Signing
***********

* Initialize JWK, and ensure that valid ``kty``, ``alg`` and ``hashing_alg`` components
* load (and test) the cryptographic objects to ensure that the JWK is valid
* Ensure that the JWK meets the specs:
    * >= 2048 bits RSA Keys
    * RSA PSS Signature Padding salt to match hash digest
    * Specific Hashing Algorithms to be used with Specific Supported Elliptic Curve Keys
    * HMAC Keysize to be >= 256 bits, and  >= to the hash_alg digest size
* Cache the Validated JWK For faster Runtime Token Performance in production
* Generate (and Cache) the token header, with required claims (including kid and alg, and kty)
* receive the b64 encoded payload from the Encoder
* encode the header
* sign and wrap up and return the JWT


Challenges with JWT Verification and Decoding
**********************************************

This is a complex step in the process, where many things can go wrong, including security
threats and malicious attacks. The complexity arises from the fact that
JWT verification and decoding may need to happen at one or several places including, but
not limited to:

* A server receiving a token from the "subject"
* A server receiving a token from a "client", operating on behalf of a subject
* A client receiving a token from the server, to be authorized on behalf of the subject


Verification and Decoding Steps
*******************************

* inspect the raw token, and ensure



The jwt JOSE Spec Module
************************

.. automodule:: webcrypt.jwe
   :members: