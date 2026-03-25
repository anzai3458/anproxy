use std::path::Path;
use std::sync::{Arc, RwLock};

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Error, Response, StatusCode};
use rustls::sign::CertifiedKey;

use crate::admin::response::{json_err, json_ok};
use crate::tls::cert::load_certified_key;

pub fn get_cert_info(
    cert_path: &Path,
    key_path: &Path,
) -> Response<BoxBody<Bytes, Error>> {
    let cert_bytes = match std::fs::read(cert_path) {
        Ok(b) => b,
        Err(e) => {
            return json_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Cannot read cert: {}", e),
            )
        }
    };

    // Parse PEM and extract X509 certificate for expiry
    let pem_iter = x509_parser::pem::Pem::iter_from_buffer(&cert_bytes);
    let mut expiry_str = String::from("unknown");
    let mut days_until_expiry: i64 = -1;

    for pem_result in pem_iter {
        if let Ok(pem) = pem_result {
            if let Ok(cert) = pem.parse_x509() {
                let not_after = cert.validity().not_after;
                expiry_str = not_after.to_string();

                let expiry_ts = not_after.timestamp();
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                days_until_expiry = (expiry_ts - now_ts) / 86400;
                break; // Use first cert in chain
            }
        }
    }

    json_ok(&serde_json::json!({
        "cert_path": cert_path.display().to_string(),
        "key_path": key_path.display().to_string(),
        "expiry": expiry_str,
        "days_until_expiry": days_until_expiry,
    }))
}

pub fn reload_certs(
    cert_path: &Path,
    key_path: &Path,
    cert_key: &Arc<RwLock<Arc<CertifiedKey>>>,
) -> Response<BoxBody<Bytes, Error>> {
    match load_certified_key(&cert_path.to_path_buf(), &key_path.to_path_buf()) {
        Ok(new_key) => {
            *cert_key.write().unwrap() = Arc::new(new_key);
            tracing::info!("Certificates reloaded via admin API");
            json_ok(&serde_json::json!({"reloaded": true}))
        }
        Err(e) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to reload certs: {}", e),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cert_info_missing_file() {
        let resp = get_cert_info(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        );
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
