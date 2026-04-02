use std::path::PathBuf;

use argh::FromArgs;

use crate::config::parse::parse_host_mapping;
use crate::config::Target;

/// Simple https reverse proxy
#[derive(FromArgs)]
pub struct Options {
    /// bind addr
    #[argh(positional)]
    pub addr: Option<String>,

    /// host backend mapping (host@http://ip:port or host@file:///path)
    #[argh(option, short = 't', from_str_fn(parse_host_mapping))]
    pub targets: Vec<Target>,

    /// cert file
    #[argh(option, short = 'c')]
    pub cert: Option<PathBuf>,

    /// key file
    #[argh(option, short = 'k')]
    pub key: Option<PathBuf>,

    /// TOML config file
    #[argh(option, long = "config-file")]
    pub config_file: Option<PathBuf>,

    /// log level: error, warn, info, debug, trace (default: info)
    #[argh(option, short = 'l', long = "log-level")]
    pub log_level: Option<String>,

    /// admin management bind addr
    #[argh(option, long = "admin-addr")]
    pub admin_addr: Option<String>,

    /// admin username
    #[argh(option, long = "admin-user")]
    pub admin_user: Option<String>,

    /// admin password
    #[argh(option, long = "admin-pass")]
    pub admin_pass: Option<String>,

    /// disable TLS (for local testing)
    #[argh(switch, long = "no-tls")]
    pub no_tls: bool,
}
