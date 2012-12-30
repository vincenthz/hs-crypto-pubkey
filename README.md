Crypto-pubkey
=============

An extensive public key cryptography library for haskell.

Features
--------

* RSA
    * all major modes supported: PKCS15, OAEP, PSS
    * Support fast RSA decryption and signing: using RSA key by-product when possible
    * RSA with blinder: not comprimising security for performance.
* DSA
* Diffie Hellman: just primitives
* ElGamal
    * signature/verification scheme
    * encryption/decryption primitive

TODO
----

See TODO file.
one major item is support for Elliptic curve crypto (ECC) with ECDH, ECDSA.

Tests
-----

An extensive battery of tests is available in the Tests directory.
It contains quickcheck properties, and KATs (Known-Answer-Tests).

Benchmarks
----------

Operations (mainly RSA for now) can be benchmarks using the benchmark suite
available in the Benchmarks directory.
