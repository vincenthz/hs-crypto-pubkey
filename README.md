Crypto-pubkey
=============

[![Build Status](https://travis-ci.org/vincenthz/hs-crypto-pubkey.png?branch=master)](https://travis-ci.org/vincenthz/hs-crypto-pubkey)
[![BSD](http://b.repl.ca/v1/license-BSD-blue.png)](http://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](http://b.repl.ca/v1/language-haskell-lightgrey.png)](http://haskell.org)

An extensive public key cryptography library for haskell.

Features
--------

* RSA
    * all major modes supported: PKCS15, OAEP, PSS
    * Support fast RSA decryption and signing: using RSA key by-product when possible
    * RSA with blinder: not comprimising security for performance.
* DSA
* ECDSA
    * There is no protection against timing attacks yet. Signing may leak the
      public key, verification should be fine.
    * It's slow, not optimized yet.
* Diffie Hellman: just primitives
* ElGamal
    * signature/verification scheme
    * encryption/decryption primitive

TODO
----

See TODO file.

Tests
-----

An extensive battery of tests is available in the Tests directory.
It contains quickcheck properties, and KATs (Known-Answer-Tests).

Benchmarks
----------

Operations (mainly RSA for now) can be benchmarks using the benchmark suite
available in the Benchmarks directory.
