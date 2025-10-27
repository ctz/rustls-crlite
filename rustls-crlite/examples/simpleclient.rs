//! This is the simplest possible client using rustls that does something useful:
//! it accepts the default configuration, loads some root certs, and then connects
//! to rust-lang.org and issues a basic HTTP request.  The response is printed to stdout.
//!
//! It makes use of rustls::Stream to treat the underlying TLS connection as a basic
//! bi-directional stream -- the underlying IO is performed transparently.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::RootCertStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hostname = std::env::args()
        .nth(1)
        .expect("call with a hostname to access");
    let path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/".to_string());

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let verifier = rustls_crlite::CrliteWebpkiServerVerifier::new(
        provider.clone(),
        root_store.into(),
        rustls_crlite::Policy::default(),
        &(Arc::new(rustls_crlite::UserCacheStorage::new()?) as Arc<dyn rustls_crlite::Storage>),
    )?;

    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = hostname.clone().try_into()?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect(format!("{hostname}:443"))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        format!(
            "GET {path} HTTP/1.1\r\n\
            Host: {hostname}\r\n\
            Connection: close\r\n\
            Accept-Encoding: identity\r\n\
            \r\n"
        )
        .as_bytes(),
    )?;
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext)?;
    stdout().write_all(&plaintext)?;

    Ok(())
}
