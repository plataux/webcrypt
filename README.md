# webcrypt

High level APIs for general purpose web cryptography,
security and password management

## Version 0.3.0

* Asymmetric Crypto Operations based on Elliptic Curve and ED Curve
* All Crypto functions now use the library ``cryptography`` as the backend, including AES, RSA, EC and ED Curves
* project no longer requires ``pycryptodomex`` package, with rfc1751 functionality copied and adapted
install with

``pip install "git+https://github.com/plataux/webcrypt@v0.3.0"``