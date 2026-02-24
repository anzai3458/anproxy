use std::error::Error as StdError;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

pub fn load_certified_key(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<CertifiedKey, Box<dyn StdError + Send + Sync>> {
    let certs = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("no certificates found in cert file".into());
    }
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(certs, signing_key))
}

#[derive(Debug)]
pub struct DynamicCertResolver {
    pub certified_key: Arc<RwLock<Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.certified_key.read().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::test_helpers::write_test_cert_files;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_certified_key_valid() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        assert!(load_certified_key(&cert_path, &key_path).is_ok());
    }

    #[test]
    fn test_load_certified_key_missing_cert_file() {
        let (_, key_path, _kf, _) = write_test_cert_files();
        let bad_cert = PathBuf::from("/nonexistent/cert.pem");
        assert!(load_certified_key(&bad_cert, &key_path).is_err());
    }

    #[test]
    fn test_load_certified_key_missing_key_file() {
        let (cert_path, _, _cf, _) = write_test_cert_files();
        let bad_key = PathBuf::from("/nonexistent/key.pem");
        assert!(load_certified_key(&cert_path, &bad_key).is_err());
    }

    #[test]
    fn test_load_certified_key_invalid_key_content() {
        let (cert_path, _, _cf, _) = write_test_cert_files();
        let mut key_file = NamedTempFile::new().unwrap();
        key_file
            .write_all(
                b"-----BEGIN PRIVATE KEY-----\ndGhpcyBpcyBub3QgYSByZWFsIGtleQo=\n-----END PRIVATE KEY-----\n",
            )
            .unwrap();
        key_file.flush().unwrap();
        assert!(load_certified_key(&cert_path, &key_file.path().to_path_buf()).is_err());
    }

    #[test]
    fn test_dynamic_cert_resolver_holds_key() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&key)));
        let _resolver = DynamicCertResolver {
            certified_key: Arc::clone(&shared),
        };
        let read_key = shared.read().unwrap();
        assert_eq!(read_key.cert, key.cert);
    }

    #[test]
    fn test_dynamic_cert_resolver_key_swap() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let initial = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&initial)));

        let (cert_path2, key_path2, _cf2, _kf2) = write_test_cert_files();
        let replacement = Arc::new(load_certified_key(&cert_path2, &key_path2).unwrap());

        *shared.write().unwrap() = Arc::clone(&replacement);

        let current = shared.read().unwrap();
        assert_eq!(current.cert, replacement.cert);
        assert_ne!(current.cert, initial.cert);
    }
}
