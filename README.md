# caddy-scep

A [Caddy](https://caddyserver.com/) module for issuing certificates using Simple Certificate Enrollment Protocol (SCEP, [RFC8894](https://tools.ietf.org/html/rfc8894)).

## Description

This is a simple POC [Caddy](https://caddyserver.com/) module for issuing certificates using the Simple Certificate Enrollment Protocol (SCEP, [RFC8894](https://tools.ietf.org/html/rfc8894)).

The module uses [micromdm/scep](https://github.com/micromdm/scep) to power the SCEP functionality.
Caddy is the host for the SCEP endpoints and provides the PKI functionality.

By default Caddy uses ECDSA keys but SCEP expects them to be RSA keys.
This is why it's required to supply your own RSA private key and certificate to Caddy instead of making Caddy fully manage the PKI.

__This module is (currently) experimental__

## Things That Can Be Done

* Fix the issue with PKCS7 verification. Currently the verfication is skipped entirely.
* Sign with intermediate. Currently we sign with the root. We could either generate a new intermediate specifically for SCEP from the root private key or provide an intermedate RSA private key and certificate manually. It should become a configuration, though.
* Store the generated certificates in a Caddy storage. We'll probably need to create one specifically for the SCEP functionality, because it's not exposed directly by the Caddy CA.
* Properly track the certificate serial number.
* Implement more options from the `micromdm/scep` implementation, like challenge passwords and CSR verification.
* Test (automatically) with SCEP clients. So far the `micromdm/scep` client seems to work correctly.
* ...

## References

* [RFC8894](https://tools.ietf.org/html/rfc8894)