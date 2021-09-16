# Webcrypt

Webcrypt is a collection of Python3 tools and constructs that aim to simplify the implementation
of all sorts of high-level cryptographic functionality commonly needed in the 
development of modern, distributed, and security-focused web applications.

At its core, Webcrypt relies entirely and **only** on the Python Library ``cryptography`` for all 
cryptographic operations, and acts as a thin wrapper around this library's primitives to provide 
a high level API that is easier to use in the context of business software development.

This project borrows ideas from, and is inspired by other Python libraries including:

* ``pycryptodome``
* ``python-jose``

``pip install "git+https://github.com/plataux/webcrypt@v0.6.1"``

## Project Goals

* Provide all the essential cryptographic tools:
  * That can be used directly: encryption/decryption, signing/verification
  * upon which higher level business protocols can be established (for example, nesting of JWTs)
* Implement most of the essential aspects of JOSE spec to maximize interoperability with other frameworks
* optimize for Production use:
  * Focusing on Performance (by caching and reusing validated cryptographic constructs as much as possible)
  * Focusing on Security (apply thorough validation steps when handling external signatures and other external entities)
* Promote secure practices:
  * wherever applicable, rejecting algorithms of insufficient strengths or known vulnerabilities
  * Defaults to algorithms / key lengths that are reasonably secure and reasonably fast
  * Make it easier to create new keys, and retire old ones

## Current Features

* Support for most of the JWS signature algorithms: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1:
  * All HMAC algorithms: ``HS256``, ``HS384``, ``HS512``
  * All RSA algorithms: ``RS256``, ``RS384``, ``RS512`` and ``PS256``, ``PS384``, ``PS512``
  * All Elliptic Curve Algorithms: ``ES256``, ``ES384``, ``ES512``
  * Leaving out only ``none`` algorithm for JWT signatures

* Support for all the JWE Encryption and Key Wrapping Algorithms https://datatracker.ietf.org/doc/html/rfc7518#section-4.1:
  * All content encryption algorithms: ``A128GCM``, ``A192GCM``, ``A256GCM``, ``A128CBC-HS256``, ``A192CBC-HS384``, ``A256CBC-HS512``
  * direct ``dir`` encryption using any of the Encryption Algorithms defined by the standard
  * AES key wrapping of a newly, randomly Generated CEK: ``A128KW``, ``A192KW`` and ``A256KW``
  * AES-GCM encryption of a newly, randomly generated CEK: ``A128GCMKW``, ``A192GCMKW`` and ``A256GCMKW``
  * Password-Based Encryption algorithms: ``PBES2-HS256+A128KW``, ``PBES2-HS384+A192KW``, ``PBES2-HS512+A256KW``
  * RSA key wrapping of CEKs: ``RSA1_5``, ``RSA-OAEP`` and ``RSA-OAEP-256``
  * ECDH-ES key derivation for direct use, or wrapping of a CEK: ``ECDH-ES``, ``ECDH-ES+A128KW``, ``ECDH-ES+A192KW``, ``ECDH-ES+A256KW``

* Simple API to export and import key sets (JWKS), and public JWKS from Private JWKS
* Using ``Pydantic`` to validate, serialize and deserialize JWT Tokens 


## Usage

### JWS Signing and Verification

#### Default Creation and usage of JWS Signing Objects

Sign and retrieve byte payloads to and from unicode JWTs. The ``verify`` method will raise
many kinds of ``TokenException`` if the JWT is fabricated, corrupted or tampered with in any way
```python
from webcrypt.jws import JWS

# Creates a new signing key with algorithm ES256 by default - it is fast, and can be verified by clients
signer = JWS()

payload = b'Byte Data to be signed and verified'

token: str = signer.sign(payload)

print(token)
# will produce something like this
# eyJhbGciOiJFUzI1NiIsImt0eSI6IkVDIiwia2lkIjoiZWFjNTgyMWMtZDQ3Yi00ZTA4LWEwMTMtOWQxOWUzNmNkNGRkIn0.
# RGF0YSB0byBiZSBzaWduZWQgYW5kIHZlcmlmaWVk.tvQcT6S33H9auuGqNyYm_VHsA8I0Bw6NaLGi6plJCwmnr9oKXS78lZYI
# 9ndlju6dnNXdP3nCAxZuyR9I0vxS-A

decoded_payload = signer.verify(token)

assert payload == decoded_payload
```

#### Creation and usage of other JWS algorithms
The ``Algorithm`` Enum in the JWS class contains all Algorithms defined by the JOSE spec.
The following is an example of newly created signature keys:

* All newly created RSA keys are 2048 bits (minimal recommended, and faster than 3072 and 4096 bit key sizes)
* All newly created HMAC and EC keys match the length of the Hashing Algorithm used
```python
from webcrypt.jws import JWS

k1 = JWS(JWS.Algorithm.RS512) # new RSA 2048 bit key with SHA512 hashing and PKCS1v15 Padding
k2 = JWS(JWS.Algorithm.PS384) # new RSA 2048 bit with SHA384 hashing and PSS Padding
k3 = JWS(JWS.Algorithm.HS256) # new HMAC signing key with SHA256 Hashing
k4 = JWS(JWS.Algorithm.ES512) # new Elliptic Curve P-521 (SECP521R1) key, with SHA512 Hashing
```

#### Loading Existing Keys

JWS Signing keys can be loaded from existing keys in various formats:

* PEM formats
* ``cryptography`` key objects
* JWK (JSON Web Key) JSON Format

##### From PEM
```python
from webcrypt.jws import JWS

# This is a P-256 Curve EC key
privkey_pem = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2/Hi1u+D8HYixWoY
Cl0uQnq9KscIlSw5N2sGJJaWcv+hRANCAASmX7fu++yJAxOCUODmf9ZX14zU0IXb
dXn5a9lL4Dswt/LLzVAo2DQQWe9nviYx0xb2txYXbtssaqEDUPeKAklF
-----END PRIVATE KEY-----
"""

# Since this is a P-256 curve key, a The JWS Algorithm ES256 MUST be used, as per the JOSE spec
# This key can sign, and verify
ec_jws = JWS.from_pem(privkey_pem,algorithm=JWS.Algorithm.ES256)


# this is a 3072 RSA Public Key - can only verify JWTs, but cannot be used to sign
pubkey_pem="""-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqBALJZGWr4zAvQsnj8e5
xIX5KA74Nel7+Q8RR9HW80y+5t2pGpQuObX7WvuXhrkCFGgWxqvaIu7Z9XsxYAv/
I4waVtoYOjUVH4w4aDI+SpOe8duiF5nAxpiaHp5h4ubDjQcipzsJyp3QQS7qqUAf
wwNRwJQcYrdchJrFO9AQ/Wg7Actd7O8Ijhh0mSXID/hEVanBwrRuAq8GwQfDSv1Q
MXNzC9k6ZlecKkUD2aRpTHPUbjbTZcGfPBnACdih2QMkQ+8XvOfIQqKuCM/MDVmD
qbmQG6t/Bbsxa32cGBXVGmb+JW+e1TnQCF9i5xnOwKj6F08NVCzWaub8+heQeUJX
gwpdVeejQS9w1q+eO5Ts6EGxOvnTbEs2WboRP7Hi8y1NE7PlKmOCHRQrdWdTaqTH
j/BXR2V9LT0nNwC2/SnpDtqz9lbFJSvEKpLp4h7BDBuhnjfw6kywyRYaM5Q3HvHM
iiiRP4MeERT4cYKkGiV+GtpjzKqRqYpkDSzcueTNRUhlAgMBAAE=
-----END PUBLIC KEY-----
"""

# all JWS RSA Algorithms are applicable with this (or any other) RSA keys (of size 2048 bits or larger)
rsa_verifier = JWS.from_pem(pubkey_pem,JWS.Algorithm.PS512)

# based on the above parameters, this key can verify signatures by the corresponding Private Key
# With the specified PS512 JWS Algorithm
```

##### From cryptography objects
```python
from webcrypt.jws import JWS
from cryptography.hazmat.primitives.asymmetric import rsa

# assuming this is an existing 4096 bit RSA Private key
privkey = rsa.generate_private_key(public_exponent=65537,key_size=1024*4)

# The corresponding Public key to be shared with partners, clients and other third parties
pubkey = privkey.public_key()

data = b'Some data to be signed and verified'

# Uses SHA384 and PKCS1v15 Padding. Can be used to sign and verify
priv_jwk = JWS(algorithm=JWS.Algorithm.RS384, key_obj=privkey)

token = priv_jwk.sign(data)

#######################
# Somewhere else, construct the JWS object with the public key, and the agreed upon algorithm

# cannot sign, but can verify signatures
pub_jwk = JWS(algorithm=JWS.Algorithm.RS384,key_obj=pubkey)

signed_data = pub_jwk.verify(token)
assert signed_data == data
```


##### Exporting and Importing JWK JSON objects

This is the preferred and easiest method to store, and restore JWK objects, since it includes
the private and/or the public key components, as well as the algorithm and the intended usage of the key

```python
privkey_jwk="""
{
  "use": "sig",
  "kid": "23b5973e-7257-4fbc-944b-3f79e01da799",
  "kty": "EC",
  "alg": "ES384",
  "key_ops": [
    "sign",
    "verify"
  ],
  "crv": "P-384",
  "x": "xcICJQvPvomxkue8ZOE9AsKSSlGwYhEOBpscwdpiFK4jzkh2zGvaq1Ek5wY1BkxU",
  "y": "Q6VVuYPTlVvZLZYTbtOoxfNUD3kqJs4ZEqQ6mt5cxfOHCc0mGqrGGcnhAZ95YKZ0",
  "d": "mhKUB-5-leY-XBciNcSRFDEeUJuA4h6rzwaDoxyCeNkTLtauElWoWsRvN8Xu9rIh"
}
"""

from webcrypt.jws import JWS
import json

# can sign and verify
signer = JWS.from_jwk(json.loads(privkey_jwk))

# export public components
public_jwk = signer.public_jwk()

# which looks something like this:
pubkey_jwk = """{
  "use": "sig",
  "kid": "23b5973e-7257-4fbc-944b-3f79e01da799",
  "kty": "EC",
  "alg": "ES384",
  "key_ops": [
    "verify"
  ],
  "crv": "P-384",
  "x": "xcICJQvPvomxkue8ZOE9AsKSSlGwYhEOBpscwdpiFK4jzkh2zGvaq1Ek5wY1BkxU",
  "y": "Q6VVuYPTlVvZLZYTbtOoxfNUD3kqJs4ZEqQ6mt5cxfOHCc0mGqrGGcnhAZ95YKZ0"
}"""

# can verify, but cannot sign
verifier = JWS.from_jwk(json.loads(pubkey_jwk))

```

### JWE Key Wrapping and Encryption

Most JWE Algorithm involve using a private key to directly encrypt, or to wrap
a newly created CEK (Content Encryption Key)

#### JWE private AES keys for direct ``dir`` encryption:

```python
from webcrypt.jwe import JWE
import json

# generate a new 192-bit key used directly in content Encryption
jwk1 = JWE(algorithm=JWE.Algorithm.DIR, encryption=JWE.Encryption.A192GCM)

# generate a new 256-bit key used directly in content Encryption + HMAC Authentication
jwk2 = JWE(algorithm=JWE.Algorithm.DIR, encryption=JWE.Encryption.A128CBC_HS256)

# export jwk1:
print(json.dumps(jwk1.to_jwk(),indent=4))

# will look like this:
privkey = """{
    "use": "enc",
    "kid": "be29da9a-3a89-4839-a664-68de669f145a",
    "kty": "oct",
    "alg": "dir",
    "enc": "A128GCM",
    "key_ops": [
        "encrypt",
        "decrypt"
    ],
    "k": "L35wm0tFTg12nKcZviyv1Q"
}
"""

jwk_reloaded = JWE.from_jwk(json.loads(privkey))

data = b'Some byte data to be encrypted then decrypted'

token = jwk_reloaded.encrypt(data,compress=True) # option to compress the data

data_decrypted = jwk_reloaded.decrypt(token)

assert data_decrypted == data

```


#### JWE Key-wrapping Algorithms:

```python
from webcrypt.jwe import JWE
import json

# Generate a 192-bit private key to wrap a 256-bit CEK for encrypting and decrypting data
jwk1 = JWE(algorithm=JWE.Algorithm.A192KW, encryption=JWE.Encryption.A256GCM)

# Generate a 256-bit private key to encrypt and wrap a 512-bit key for Encryption + Authentication
jwk2 = JWE(algorithm=JWE.Algorithm.A256GCMKW, encryption=JWE.Encryption.A256CBC_HS512)

# Generate a 128-bit private key to wrap a 192-bit CEK for encrypting and decrypting data
jwk3 = JWE(algorithm=JWE.Algorithm.A128KW, encryption=JWE.Encryption.A192GCM)

print(json.dumps(jwk2.to_jwk(),indent=4))

# will produce something like this:

jwk_json = """{
    "use": "enc",
    "kid": "f47a54c3-85d8-46b8-a9cb-8a1b5f47eddb",
    "kty": "oct",
    "alg": "A256GCMKW",
    "enc": "A256CBC-HS512",
    "key_ops": [
        "wrapKey",
        "unwrapKey"
    ],
    "k": "dkcM5Fnj7oYN4r4NGs7RMVxSX1jcT9gwvoRgxXJ4um8"
}

"""

# which can later be reloaded for encryption / decryption operations
jwe_key = JWE.from_jwk(json.loads(jwk_json))
```


#### JWE RSA Key-wrapping Algorithms

```python
from webcrypt.jwe import JWE

# Examples of all RSA Algorithms, with different CEK sizes

jwe1 = JWE(algorithm=JWE.Algorithm.RSA_OAEP_256, encryption=JWE.Encryption.A192GCM)
jwe2 = JWE(algorithm=JWE.Algorithm.RSA_OAEP, encryption=JWE.Encryption.A128CBC_HS256)
jwe3 = JWE(algorithm=JWE.Algorithm.RSA1_5, encryption=JWE.Encryption.A256GCM)


# Load a Public JWE key from the JWK of a private one
pub_jwe = JWE.from_jwk(jwe1.public_jwk())

data = b'Byte data to be encrypted and decrypted'

# encrypt data, and wrap the CEK
token = pub_jwe.encrypt(data)

# Raises an Error, a public key cannot decrypt the CEK!
pub_jwe.decrypt(token)

# only the corresponding private key can unwrap the CEK and decrypt the data
data_decrypted = jwe1.decrypt(token)

assert data_decrypted == data
```


#### JWE PBE (Passphrase based Encryption) Algorithms

```python
from webcrypt.jwe import JWE
import json

# Generate a 192-bit private key to wrap a 384-bit key for Authentication + Encryption
jwk = JWE(algorithm=JWE.Algorithm.PBES2_HS384_A192KW,
          encryption=JWE.Encryption.A256GCM,
          key="I love python")

data = b'Some secret data'

token = jwk.encrypt(data)

print(json.dumps(JWE.decode_header(token), indent=4))

# the Token header will look something like this, including the alg, enc and
# the PBE salt and iteration count (p2s and p2c)
header="""{
    "alg": "PBES2-HS384+A192KW",
    "enc": "A256GCM",
    "kid": "08842033-5f83-477b-9be3-c91ab6e7635c",
    "p2s": "7jByuyCgOWc4aEfkoAJ0VQ",
    "p2c": 1644
}"""
```
