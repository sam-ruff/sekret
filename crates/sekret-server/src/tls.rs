//! HTTPS and mutual TLS for running without a TLS-terminating proxy.

use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

use crate::config::TlsSettings;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("{0} holds no PEM certificates")]
    NoCertificates(&'static str),
    #[error("could not read {0}: {1}")]
    Pem(&'static str, String),
    #[error("TLS configuration: {0}")]
    Config(String),
}

fn certificates(pem: &[u8], what: &'static str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Pem(what, e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(what));
    }
    Ok(certs)
}

/// The rustls server configuration for `settings`, using the ring provider.
pub fn server_config(settings: &TlsSettings) -> Result<rustls::ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let chain = certificates(&settings.cert_pem, "the certificate file")?;
    let key =
        PrivateKeyDer::from_pem_slice(&settings.key_pem).map_err(|e| TlsError::Pem("the key file", e.to_string()))?;
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Config(e.to_string()))?;
    let builder = match &settings.client_ca_pem {
        None => builder.with_no_client_auth(),
        Some(ca_pem) => {
            let mut roots = RootCertStore::empty();
            for cert in certificates(ca_pem, "the client CA file")? {
                roots.add(cert).map_err(|e| TlsError::Config(e.to_string()))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
            let verifier = if settings.client_auth_required {
                verifier
            } else {
                verifier.allow_unauthenticated()
            };
            builder.with_client_cert_verifier(verifier.build().map_err(|e| TlsError::Config(e.to_string()))?)
        }
    };
    let mut config = builder
        .with_single_cert(chain, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(client_ca: Option<Vec<u8>>, required: bool) -> TlsSettings {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        TlsSettings {
            cert_pem: cert.pem().into_bytes(),
            key_pem: zeroize::Zeroizing::new(key.serialize_pem().into_bytes()),
            client_ca_pem: client_ca,
            client_auth_required: required,
        }
    }

    #[test]
    fn builds_with_and_without_client_authentication() {
        assert!(server_config(&settings(None, false)).is_ok());
        let ca = settings(None, false).cert_pem;
        assert!(server_config(&settings(Some(ca.clone()), true)).is_ok());
        assert!(server_config(&settings(Some(ca), false)).is_ok());
    }

    #[test]
    fn bad_inputs_are_reported() {
        let mut no_cert = settings(None, false);
        no_cert.cert_pem = b"not pem".to_vec();
        assert!(matches!(server_config(&no_cert), Err(TlsError::NoCertificates(_))));
        let mut no_key = settings(None, false);
        no_key.key_pem = zeroize::Zeroizing::new(b"nothing".to_vec());
        assert!(matches!(server_config(&no_key), Err(TlsError::Pem(..))));
        let empty_ca = settings(Some(Vec::new()), true);
        assert!(matches!(server_config(&empty_ca), Err(TlsError::NoCertificates(_))));
    }
}
