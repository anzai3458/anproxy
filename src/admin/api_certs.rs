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

    // Parse PEM and extract X509 certificate details
    let pem_iter = x509_parser::pem::Pem::iter_from_buffer(&cert_bytes);
    let mut expiry_str = String::from("unknown");
    let mut days_until_expiry: i64 = -1;
    let mut not_before_str = String::from("unknown");
    let mut subject = String::from("unknown");
    let mut issuer = String::from("unknown");
    let mut serial = String::from("unknown");
    let mut sig_alg = String::from("unknown");
    let mut san_dns_names: Vec<String> = Vec::new();

    for pem in pem_iter.flatten() {
        if let Ok(cert) = pem.parse_x509() {
            let validity = cert.validity();

            // Validity period
            let not_after = validity.not_after;
            expiry_str = not_after.to_string();
            not_before_str = validity.not_before.to_string();

            let expiry_ts = not_after.timestamp();
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            days_until_expiry = (expiry_ts - now_ts) / 86400;

            // Subject (certificate owner)
            subject = cert.subject().to_string();

            // Issuer (certificate authority)
            issuer = cert.issuer().to_string();

            // Serial number
            serial = cert.serial.to_string();

            // Signature algorithm
            sig_alg = cert.signature_algorithm.algorithm.to_string();

            // Subject Alternative Names (DNS names)
            if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
                for name in &san_ext.value.general_names {
                    if let x509_parser::prelude::GeneralName::DNSName(dns) = name {
                        san_dns_names.push(dns.to_string());
                    }
                }
            }

            break; // Use first cert in chain
        }
    }

    json_ok(&serde_json::json!({
        "cert_path": cert_path.display().to_string(),
        "key_path": key_path.display().to_string(),
        "expiry": expiry_str,
        "days_until_expiry": days_until_expiry,
        "not_before": not_before_str,
        "subject": subject,
        "issuer": issuer,
        "serial": serial,
        "signature_algorithm": sig_alg,
        "san_dns_names": san_dns_names,
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
