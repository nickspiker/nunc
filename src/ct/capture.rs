/// A `rustls::ServerCertVerifier` wrapper that captures the end-entity cert
/// DER bytes during the TLS handshake so we can run SCT verification after
/// the connection completes.  All actual verification is delegated to the
/// inner verifier (WebPki), so security properties are preserved.
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct CertCapturingVerifier {
    inner:    Arc<dyn ServerCertVerifier>,
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CertCapturingVerifier {
    pub fn new(
        inner:    Arc<dyn ServerCertVerifier>,
        captured: Arc<Mutex<Option<Vec<u8>>>>,
    ) -> Self {
        Self { inner, captured }
    }
}

impl ServerCertVerifier for CertCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity:    &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name:   &ServerName<'_>,
        ocsp_response: &[u8],
        now:           UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        *self.captured.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        self.inner.verify_server_cert(
            end_entity, intermediates, server_name, ocsp_response, now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert:    &CertificateDer<'_>,
        dss:     &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert:    &CertificateDer<'_>,
        dss:     &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
