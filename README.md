# caddy-scep

## Description

Currently, doesn't seem to work fully as expected, because Caddy uses ECDSA and SCEP expects RSA keys.
I've hacked together some certificate generation steps that are similar to what Caddy does for the PKI, but with RSA keys

Things to try:

* Influence Caddy configuration in such a way that we can use RSA keys. 
~~From initial inspection this does not seem possible.~~ 
It seems that we can supply the `key_type` parameter for this.
* Use a user provides private key in RSA format and see if the Caddy PKI will configure itself to use RSA keys instead of ECDSA keys. This might work, because the underlying libraries seem to check for the type of key in use. Not sure if that will result in different type of key/certificates being generated, though.
* ...

## References

* [RFC8894](https://tools.ietf.org/html/rfc8894)