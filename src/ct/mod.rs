pub mod capture;
mod extract;

use std::sync::{Arc, Mutex};
use rustls::client::WebPkiServerVerifier;
use rustls::RootCertStore;

pub use capture::CertCapturingVerifier;

/// Build a `rustls::ClientConfig` that:
///   1. Performs normal WebPKI certificate verification.
///   2. Captures the end-entity cert DER into `captured` so the caller can
///      run SCT verification after the handshake.
pub fn capturing_tls_config(
    captured: Arc<Mutex<Option<Vec<u8>>>>,
) -> Option<rustls::ClientConfig> {
    // Install the ring provider if nothing has been installed yet.
    // The error case means another thread beat us to it — that's fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let inner = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .ok()?;

    let verifier = CertCapturingVerifier::new(inner, captured);

    Some(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth(),
    )
}

/// Verify that at least one SCT in `cert_der`'s SCT extension carries a valid
/// signature from a known CT log.  Returns false if no SCTs are present or
/// none verify.
///
/// We pass `u64::MAX` as the "current time" to the sct crate, disabling its
/// "SCT not in the future" check.  We record SCT validity as a stat on each
/// observation rather than filtering on it, so the temporal check is irrelevant
/// — we only care about cryptographic signature validity against known log keys.
pub fn verify_scts(cert_der: &[u8]) -> bool {
    let scts = extract::extract_scts(cert_der);
    if scts.is_empty() { return false; }

    // ct_logs::LOGS is &[&sct::Log<'static>] — pass directly
    for sct_bytes in &scts {
        if sct::verify_sct(cert_der, sct_bytes, u64::MAX, ct_logs::LOGS).is_ok() {
            return true;
        }
    }
    false
}
