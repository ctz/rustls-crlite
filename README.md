# rustls-crlite

This project adds [crlite/Clubcard][]-based revocation support to rustls: for efficient,
reliable and private determination of revocation status for publicly trusted
certificates.

It consists of four parts:

- [`rustls-crlite`][]: a [rustls server certificate verifier][] that verifies a
  server's purported certificate using [`rustls-webpki`][], and then checks its
  revocation status using the crlite revocation system.  This component is
  published as a [rust crate][`rustls-crlite`].
- `rustls-crlite-fetch`: a system service program to be run regularly on any
  system that uses `rustls-crlite`. This downloads clubcard data from the internet.
- `rustls-crlite-query`: an optional system program that answers revocation queries,
  using the same mechanics as [`rustls-crlite`][] but suitable for easy integration
  with other systems.  For example, you can hook this up to a monitoring system, or
  call it from an OpenSSL certificate verification callback.
- `backend`: this consumes the upstream crlite filters as published on the Mozilla
  Firefox remote settings service, and republishes them on <https://crlite.rustls.dev>.
  This the default source used by `rustls-crlite-fetch`.

[`rustls-crlite`]: https://crates.io/crates/rustls-clubcard
[`rustls-webpki`]: https://crates.io/crates/rustls-webpki
[crlite/Clubcard]: https://research.mozilla.org/files/2025/04/clubcards_for_the_webpki.pdf

## Usage

After checking out this repo:

```shell
$ python fetch/prototype.py --user
INFO:root:Synchronising https://crlite.rustls.dev/ into /home/jbp/.cache/rustls/crlite/...
DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): crlite.rustls.dev:443
(...)
DEBUG:root:Saving metadata
INFO:root:Success.
INFO:root:Success

$ cargo run --example simpleclient valid.r6.roots.globalsign.com
(...)

$ cargo run --example simpleclient revoked.r6.roots.globalsign.com
Error: Custom { kind: InvalidData, error: InvalidCertificate(Revoked) }
```

## Packaging
TODO

## License
All rights reserved for now.
