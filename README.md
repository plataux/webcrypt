# webcrypt

High level Constructs for Web App cryptography and JOSE spec implementation

## Version 0.4.0

* Basic Constructs (AES, RSA, EC and ED Curves) for signing, verification, encryption, decryption
* JWS JOSE Specification, implementing all spec algorithms
* JWE JOSE Specification, implementing most encryption schemes and algorithms
* JWT Specification, for encoding and decoding JSON Web Tokens


## Version 0.5.0

* allow loading jwks from a dict object as well as JSON text
* Allow JWT object to expose available keys and algorithms
* Allow JWT to return a list of signing JWKS, and a list of encrypting JWKS
* Allow JWT to sign or encrypt with a specific algorithm, if it exists
* Move the ts_offset() function as a static method in the Token class
* remove the ts_now() method

``pip install "git+https://github.com/plataux/webcrypt@v0.5.0"``

