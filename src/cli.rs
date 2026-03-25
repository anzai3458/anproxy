use std::path::PathBuf;

use argh::FromArgs;

use crate::config::parse::{parse_host_mapping, parse_static_mapping};
use crate::config::{StaticDir, Target};

/// Simple https reverse proxy
#[derive(FromArgs)]
pub struct Options {
    /// bind addr
    #[argh(positional)]
    pub addr: Option<String>,

    /// host address mapping
    #[argh(option, short = 't', from_str_fn(parse_host_mapping))]
    pub targets: Vec<Target>,

    /// static file dir mapping (host@path)
    #[argh(option, short = 's', long = "static", from_str_fn(parse_static_mapping))]
    pub static_dirs: Vec<StaticDir>,

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
}
