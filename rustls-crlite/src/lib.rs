use core::fmt;
use std::sync::Arc;

use clubcard_crlite::CRLiteStatus;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::hash::{Hash, HashAlgorithm};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertRevocationListError, CertificateError, ExtendedKeyPurpose, RootCertStore,
    SupportedCipherSuite,
};
use webpki::{EndEntityCert, InvalidNameContext, KeyUsage, VerifiedPath};

pub struct CrliteWebpkiServerVerifier {
    provider: Arc<CryptoProvider>,
    policy: Policy,
    storage: Arc<dyn Storage>,
    roots: Arc<RootCertStore>,
    sha256: &'static dyn Hash,
}

impl CrliteWebpkiServerVerifier {
    /// Make a verifier that checks revocation using crlite.
    ///
    /// This first verifies the certificate using the `webpki` crate, against the supplied `roots`.
    /// This uses cryptography specified in `provider`.
    ///
    /// A certificate which is acceptable in the normal way, issued by one of the `roots` and
    /// valid for the given server name, is then checked for revocation.  `policy` controls
    /// whether failures in this process are hard errors.  `storage` defines how to access
    /// the crlite filter data.
    pub fn new(
        provider: Arc<CryptoProvider>,
        roots: Arc<RootCertStore>,
        policy: Policy,
        storage: &Arc<dyn Storage>,
    ) -> Result<Self, rustls::Error> {
        let sha256 = provider
            .cipher_suites
            .iter()
            .find_map(|scs| {
                let hash = match scs {
                    SupportedCipherSuite::Tls12(tls12) => tls12.common.hash_provider,
                    SupportedCipherSuite::Tls13(tls13) => tls13.common.hash_provider,
                };

                match hash.algorithm() {
                    HashAlgorithm::SHA256 => Some(hash),
                    _ => None,
                }
            })
            .expect("no cipher suites supported with SHA256");

        let storage = storage.clone();

        // Pre-roll storage to check it works, and bring (eg permanant configuration) errors
        // to forefront prior to any networking happens.
        let filters = storage.filters()?;
        if filters.is_empty() {
            policy.missing_data.as_result()?;
        }

        Ok(Self {
            provider,
            policy,
            storage,
            roots,
            sha256,
        })
    }

    /// Determine the revocation status of `ee`.
    ///
    /// This should have been determined to be issued by a trusted root.  `verified_path`
    /// proves this.
    ///
    /// This returns errors only for hard failure cases.
    fn check_revocation_status(
        &self,
        ee: &EndEntityCert,
        verified_path: &VerifiedPath,
    ) -> Result<RevocationStatus, rustls::Error> {
        let issuer_spki = verified_path.issuer_spki();
        let issuer_spki_hash = self.sha256.hash(&issuer_spki);
        let issuer_spki_hash = issuer_spki_hash
            .as_ref()
            .try_into()
            .expect("sha256 must have a 32-byte output");

        // Lacking SCTs means we cannot check revocation, and the certificate
        // cannot be publicly trusted anyway.
        let Ok(sct_timestamps) = ee.sct_log_timestamps() else {
            return self.policy.cert_has_no_scts.as_result();
        };

        let crlite_key = clubcard_crlite::CRLiteKey::new(issuer_spki_hash, ee.serial());

        let mut filter_count = 0;
        for filter in self.storage.filters()? {
            filter_count += 1;

            match filter.contains(
                &crlite_key,
                sct_timestamps
                    .iter()
                    .map(|(id, ts)| (&id.0, ts.0)),
            ) {
                CRLiteStatus::Revoked => return Ok(RevocationStatus::CertainlyRevoked),
                CRLiteStatus::Good | CRLiteStatus::NotEnrolled | CRLiteStatus::NotCovered => {
                    continue;
                }
            }
        }

        match filter_count {
            0 => self.policy.missing_data.as_result(),
            _ => Ok(RevocationStatus::NotCoveredByRevocationData),
        }
    }
}

impl ServerCertVerifier for CrliteWebpkiServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ee = webpki::EndEntityCert::try_from(end_entity).map_err(webpki_error)?;

        let verified_path = ee
            .verify_for_usage(
                self.provider
                    .signature_verification_algorithms
                    .all,
                &self.roots.roots,
                intermediates,
                now,
                KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(webpki_error)?;

        ee.verify_is_valid_for_subject_name(server_name)
            .map_err(webpki_error)?;

        match self.check_revocation_status(&ee, &verified_path)? {
            RevocationStatus::NotRevoked => Ok(ServerCertVerified::assertion()),
            RevocationStatus::NotCoveredByRevocationData => self
                .policy
                .cert_not_covered
                .as_result()
                .map(|_| ServerCertVerified::assertion()),
            RevocationStatus::CertainlyRevoked => Err(CertificateError::Revoked.into()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self
                .provider
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self
                .provider
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        None
    }
}

impl fmt::Debug for CrliteWebpkiServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrliteWebpkiServerVerifier")
            .field("provider", &self.provider)
            .field("roots", &self.roots)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum RevocationStatus {
    /// We couldn't determine the revocation status.
    ///
    /// Most likely, this certificate
    NotCoveredByRevocationData,

    /// This certificate has been revoked.
    CertainlyRevoked,

    /// This certificate was covered by revocation data, and it is not
    /// currently revoked.
    NotRevoked,
}

#[derive(Debug)]
pub struct Policy {
    /// What to do if crlite filter data is missing
    pub missing_data: Outcome,

    /// What to do if crlite filter data does not cover a certificate
    ///
    /// A certificate can be not covered by the crlite filter if:
    ///
    /// - the data is out of date, perhaps because it has not been fetched recently.
    /// - the data does not cover the certificate, because the backend processing does not cover
    ///   it (at the time of writing, this is the case for some certifcates).
    pub cert_not_covered: Outcome,

    /// What to do if certificate was not logged in CT
    pub cert_has_no_scts: Outcome,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            missing_data: Outcome::Error(rustls::Error::General("crlite data is missing".into())),
            cert_not_covered: Outcome::Allowed,
            cert_has_no_scts: Outcome::Allowed,
        }
    }
}

#[derive(Debug)]
pub enum Outcome {
    /// The certificate is treated as revoked.
    TreatAsRevoked,

    /// The given error is returned.
    Error(rustls::Error),

    /// It's not an error.
    Allowed,
}

impl Outcome {
    fn as_result(&self) -> Result<RevocationStatus, rustls::Error> {
        match self {
            Self::TreatAsRevoked => Err(rustls::CertificateError::Revoked.into()),
            Self::Error(err) => Err(err.clone()),
            Self::Allowed => Ok(RevocationStatus::NotCoveredByRevocationData),
        }
    }
}

pub trait Storage: fmt::Debug + Send + Sync {
    /// Iterate over crlite clubcard filters.
    fn filters(&self) -> Result<Vec<clubcard_crlite::CRLiteClubcard>, rustls::Error>;
}

#[derive(Debug)]
pub struct EmptyStorage;

impl Storage for EmptyStorage {
    fn filters(&self) -> Result<Vec<clubcard_crlite::CRLiteClubcard>, rustls::Error> {
        Ok(Vec::new())
    }
}

#[derive(Debug)]
pub struct StaticUnshippableStorage;

impl Storage for StaticUnshippableStorage {
    fn filters(&self) -> Result<Vec<clubcard_crlite::CRLiteClubcard>, rustls::Error> {
        let bytes = include_bytes!("../../latest_filter");
        let clubcard = clubcard_crlite::CRLiteClubcard::from_bytes(bytes).unwrap();

        Ok(vec![clubcard])
    }
}

/// WARNING: this does not track FS changes!
#[derive(Debug)]
pub struct UserCacheStorage(Vec<Vec<u8>>);

impl UserCacheStorage {
    pub fn new() -> Result<Self, std::io::Error> {
        let mut files = Vec::new();
        let mut location = std::env::home_dir().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no home directory".to_string(),
            )
        })?;
        location.push(".cache/rustls/crlite");
        for file in std::fs::read_dir(location)? {
            let file = file?;
            if file
                .file_name()
                .as_encoded_bytes()
                .ends_with(b".filter")
                || file
                    .file_name()
                    .as_encoded_bytes()
                    .ends_with(b".delta")
            {
                files.push(std::fs::read(file.path())?);
            }
        }
        Ok(UserCacheStorage(files))
    }
}

impl Storage for UserCacheStorage {
    fn filters(&self) -> Result<Vec<clubcard_crlite::CRLiteClubcard>, rustls::Error> {
        Ok(self
            .0
            .iter()
            .map(|data| clubcard_crlite::CRLiteClubcard::from_bytes(data).unwrap())
            .collect())
    }
}

fn webpki_error(error: webpki::Error) -> rustls::Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime | TrailingData(_) => CertificateError::BadEncoding.into(),
        CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName(InvalidNameContext {
            expected,
            presented,
        }) => CertificateError::NotValidForNameContext {
            expected,
            presented,
        }
        .into(),
        CertRevoked => CertificateError::Revoked.into(),
        UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        CrlExpired { time, next_update } => {
            CertificateError::ExpiredRevocationListContext { time, next_update }.into()
        }
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),

        InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        #[allow(deprecated)]
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
            CertificateError::UnsupportedSignatureAlgorithm.into()
        }
        UnsupportedSignatureAlgorithmContext(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
            .into()
        }
        UnsupportedSignatureAlgorithmForPublicKeyContext(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }

        InvalidCrlSignatureForPublicKey => CertRevocationListError::BadSignature.into(),
        #[allow(deprecated)]
        UnsupportedCrlSignatureAlgorithm | UnsupportedCrlSignatureAlgorithmForPublicKey => {
            CertRevocationListError::UnsupportedSignatureAlgorithm.into()
        }
        UnsupportedCrlSignatureAlgorithmContext(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
            .into()
        }
        UnsupportedCrlSignatureAlgorithmForPublicKeyContext(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }

        #[allow(deprecated)]
        RequiredEkuNotFound => CertificateError::InvalidPurpose.into(),
        RequiredEkuNotFoundContext(webpki::RequiredEkuNotFoundContext { required, present }) => {
            rustls::Error::from(CertificateError::InvalidPurposeContext {
                required: ekp_for_values(required.oid_values()),
                presented: present
                    .into_iter()
                    .map(|eku| ekp_for_values(eku.into_iter()))
                    .collect(),
            })
        }

        _ => CertificateError::Other(rustls::OtherError(Arc::new(error))).into(),
    }
}
pub(crate) fn ekp_for_values(values: impl Iterator<Item = usize>) -> ExtendedKeyPurpose {
    let values = values.collect::<Vec<_>>();
    match &*values {
        KeyUsage::CLIENT_AUTH_REPR => ExtendedKeyPurpose::ClientAuth,
        KeyUsage::SERVER_AUTH_REPR => ExtendedKeyPurpose::ServerAuth,
        _ => ExtendedKeyPurpose::Other(values),
    }
}
