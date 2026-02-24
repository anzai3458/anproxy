use std::io::Write;
use std::path::PathBuf;

use tempfile::NamedTempFile;

pub fn write_test_cert_files() -> (PathBuf, PathBuf, NamedTempFile, NamedTempFile) {
    let rcgen_cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = rcgen_cert.cert.pem();
    let key_pem = rcgen_cert.key_pair.serialize_pem();

    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();
    cert_file.flush().unwrap();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();
    key_file.flush().unwrap();

    let cert_path = cert_file.path().to_path_buf();
    let key_path = key_file.path().to_path_buf();
    (cert_path, key_path, cert_file, key_file)
}
