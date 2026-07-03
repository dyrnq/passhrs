use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::types::{DynamicForwardSpec, ForwardSpec, ProxyJumpSpec};
const PKG_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Parser)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    trailing_var_arg = true,
    disable_help_flag = true
)]
pub(crate) struct Cli {
    #[arg(short = 'p', long = "port", default_value_t = 22)]
    pub(crate) ssh_port: u16,
    #[arg(short = 'l', long = "user")]
    pub(crate) user: Option<String>,
    #[arg(short = 'i', long = "key")]
    pub(crate) identity_file: Option<PathBuf>,
    #[arg(short = 'J', long = "proxy-jump")]
    pub(crate) proxy_jump: Option<String>,
    #[arg(short = '4', long = "ipv4")]
    pub(crate) ipv4: bool,
    #[arg(short = '6', long = "ipv6")]
    pub(crate) ipv6: bool,
    #[arg(short = 'A', long = "forward-agent")]
    pub(crate) forward_agent: bool,
    #[arg(short = 'a', long = "no-forward-agent")]
    pub(crate) no_forward_agent: bool,
    #[arg(short = 'C', long = "compress")]
    pub(crate) compress: bool,
    #[arg(short = 'D', long = "dynamic-forward", num_args = 1)]
    pub(crate) dynamic_forward: Vec<String>,
    #[arg(short = 'H', long = "http-proxy-connect", num_args = 1)]
    pub(crate) http_proxy_connect: Vec<String>,
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,
    #[arg(short = 'q', long = "quiet")]
    pub(crate) quiet: bool,
    #[arg(short = 'E', long = "log-file")]
    pub(crate) log_file: Option<String>,
    #[arg(short = 'o', long = "option", num_args = 1)]
    pub(crate) ssh_option: Vec<String>,
    #[arg(short = 'N', long = "no-command")]
    pub(crate) no_command: bool,
    #[arg(short = 't', long = "tty")]
    pub(crate) force_tty: bool,
    #[arg(short = 'L', long = "local-forward", num_args = 1)]
    pub(crate) local_forward: Vec<String>,
    #[arg(short = 'R', long = "remote-forward", num_args = 1)]
    pub(crate) remote_forward: Vec<String>,
    #[arg(long = "identity-passphrase")]
    pub(crate) passphrase: Option<String>,
    #[arg(long = "identity-passphrase-file")]
    pub(crate) passphrase_file: Option<String>,
    #[arg(long = "password")]
    pub(crate) password: Option<String>,
    #[arg(long = "password-file")]
    pub(crate) password_file: Option<String>,
    #[arg(short = 'S', long = "control-path")]
    pub(crate) control_path: Option<String>,
    #[arg(long = "connect-timeout", default_value_t = 0)]
    pub(crate) connect_timeout: u64,
    #[arg(long = "timeout", default_value_t = 0)]
    pub(crate) inactivity_timeout: u64,
    #[arg(short = 'n', long = "redirect-stdin")]
    pub(crate) redirect_stdin: bool,
    #[arg(short = 'f', long = "fork")]
    pub(crate) fork: bool,
    #[arg(long = "exec-env", num_args = 1)]
    pub(crate) exec_env: Vec<String>,
    #[arg(long = "help")]
    pub(crate) help: bool,
    pub(crate) destination: Option<String>,
    pub(crate) command: Vec<String>,
    #[arg(long = "push", num_args = 1)]
    pub(crate) push: Vec<String>,
    #[arg(long = "pull", num_args = 1)]
    pub(crate) pull: Vec<String>,
    #[arg(long = "rsync", num_args = 1)]
    pub(crate) rsync: Vec<String>,
    #[arg(long = "rsync-opt", num_args = 1)]
    pub(crate) rsync_opt: Vec<String>,
}

pub(crate) fn parse_destination(dest: &str) -> Result<(String, Option<String>, u16)> {
    let (user, rest) = if let Some(at_idx) = dest.rfind('@') {
        (Some(dest[..at_idx].to_string()), &dest[at_idx + 1..])
    } else {
        (None, dest)
    };
    // Handle IPv6: [host]:port or [host]
    let (host, port) = if let Some(rest_stripped) = rest.strip_prefix('[') {
        if let Some(bracket_end) = rest_stripped.find(']') {
            let h = rest_stripped[..bracket_end].to_string();
            let remaining = rest_stripped[bracket_end + 1..].trim_start_matches(':');
            let p = if remaining.is_empty() {
                None
            } else {
                Some(
                    remaining
                        .parse::<u16>()
                        .with_context(|| format!("invalid port in destination: {}", dest))?,
                )
            };
            (h, p)
        } else {
            bail!("unclosed bracket in destination: {}", dest)
        }
    } else if let Some(colon_idx) = rest.rfind(':') {
        let p: u16 = rest[colon_idx + 1..]
            .parse()
            .with_context(|| format!("invalid port in destination: {}", dest))?;
        (rest[..colon_idx].to_string(), Some(p))
    } else {
        (rest.to_string(), None)
    };
    Ok((host, user, port.unwrap_or(22)))
}

pub(crate) fn parse_ssh_options(options: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for opt in options {
        if let Some(eq_idx) = opt.find('=') {
            let key = opt[..eq_idx].to_lowercase();
            let value = opt[eq_idx + 1..].to_string();
            map.insert(key, value);
        }
    }
    map
}

pub(crate) fn parse_proxy_jump(spec: &str) -> Result<ProxyJumpSpec> {
    // Format: [user@]host[:port]
    let spec = spec.trim();
    let (user, rest) = if let Some(at_pos) = spec.rfind('@') {
        (Some(spec[..at_pos].to_string()), &spec[at_pos + 1..])
    } else {
        (None, spec)
    };
    let (host, port) = if let Some(colon_pos) = rest.rfind(':') {
        let host_part = &rest[..colon_pos];
        let port_str = &rest[colon_pos + 1..];
        // Skip IPv6 addresses like [::1]:port
        if host_part.starts_with('[') && host_part.ends_with(']') {
            let h = host_part.trim_start_matches('[').trim_end_matches(']');
            let p = port_str
                .parse::<u16>()
                .context("Invalid port in proxy jump")?;
            (h.to_string(), p)
        } else {
            let p = port_str
                .parse::<u16>()
                .context("Invalid port in proxy jump")?;
            (host_part.to_string(), p)
        }
    } else {
        (rest.to_string(), 22)
    };
    Ok(ProxyJumpSpec { user, host, port })
}

pub(crate) fn parse_forward_spec(spec: &str) -> Result<ForwardSpec> {
    let spec = spec.trim();

    // Determine the optional bind address and the remaining
    // "port:host:hostport" core. Supported forms:
    //   port:host:hostport                 -> bind defaults to 127.0.0.1
    //   bind_addr:port:host:hostport       -> plain bind address
    //   [bind_addr]:port:host:hostport     -> bracketed bind (e.g. IPv6)
    let (bind_addr, core) = if let Some(s) = spec.strip_prefix('[') {
        // Bracketed bind address, e.g. "[::1]:8080:localhost:80".
        let end = s
            .find(']')
            .with_context(|| format!("unclosed bracket in forward spec: {}", spec))?;
        (
            s[..end].to_string(),
            s[end + 1..].trim_start_matches(':').to_string(),
        )
    } else {
        // Ambiguous between "port:host:hostport" and
        // "bind_addr:port:host:hostport". Heuristic: if the first field is a
        // valid port number there is no explicit bind address; otherwise the
        // first field is a bind address.
        let first = spec.split(':').next().unwrap_or("");
        if first.parse::<u16>().is_ok() {
            ("127.0.0.1".to_string(), spec.to_string())
        } else {
            let (b, r) = spec
                .split_once(':')
                .with_context(|| format!("invalid forward spec: {}", spec))?;
            (b.to_string(), r.to_string())
        }
    };

    // core = "port:host:hostport". Peel off bind_port from the left FIRST, so
    // the bind port is never mistaken for part of the target host.
    let (bind_port_str, target) = core.split_once(':').with_context(|| {
        format!(
            "invalid forward spec: {}. Use port:host:port or [bind:]port:host:port",
            spec
        )
    })?;
    let bind_port: u16 = bind_port_str
        .parse()
        .with_context(|| format!("invalid bind port in forward spec: {}", spec))?;

    // target = "host:hostport". The host may be a bracketed IPv6 literal.
    let (target_host, target_port_str) = if let Some(t) = target.strip_prefix('[') {
        let end = t.find(']').with_context(|| {
            format!("unclosed bracket for target host in forward spec: {}", spec)
        })?;
        (t[..end].to_string(), t[end + 1..].trim_start_matches(':'))
    } else {
        let (h, p) = target.rsplit_once(':').with_context(|| {
            format!(
                "invalid forward spec: {}. Use port:host:port or [bind:]port:host:port",
                spec
            )
        })?;
        (h.to_string(), p)
    };
    let target_port: u16 = target_port_str
        .parse()
        .with_context(|| format!("invalid target port in forward spec: {}", spec))?;

    Ok(ForwardSpec {
        bind_addr,
        bind_port,
        target_host,
        target_port,
    })
}

pub(crate) fn parse_dynamic_spec(spec: &str) -> Result<DynamicForwardSpec> {
    if let Some(colon_idx) = spec.find(':') {
        Ok(DynamicForwardSpec {
            bind_addr: spec[..colon_idx].to_string(),
            bind_port: spec[colon_idx + 1..]
                .parse()
                .context("invalid SOCKS port")?,
        })
    } else {
        Ok(DynamicForwardSpec {
            bind_addr: "127.0.0.1".into(),
            bind_port: spec.parse().context("invalid SOCKS port")?,
        })
    }
}
// =======================================================
// SFTP recursive push/pull helpers
// ======================================================================

pub(crate) fn expand_path(path: &str) -> String {
    if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.display().to_string();
        }
    } else if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}/{}", home.display(), rest);
        }
    }
    path.to_string()
}

pub(crate) fn read_value_from_file(s: &str) -> Result<String> {
    // @file 显式指定
    if let Some(path) = s.strip_prefix('@') {
        let val = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read value from file: {}", path))?;
        return Ok(val.trim_end().to_string());
    }
    // 进程替换 /dev/fd/* (如 <(cmd)) 或直接文件路径
    if !s.is_empty() && s.len() < 256 && s != "-" {
        if let Ok(meta) = std::fs::metadata(s) {
            if meta.is_file() {
                let val = std::fs::read_to_string(s)
                    .with_context(|| format!("failed to read value from file: {}", s))?;
                return Ok(val.trim_end().to_string());
            }
        }
    }
    Ok(s.to_string())
}

pub(crate) fn parse_file_spec(spec: &str) -> Result<(String, String)> {
    if let Some(colon_idx) = spec.find(':') {
        Ok((
            spec[..colon_idx].to_string(),
            spec[colon_idx + 1..].to_string(),
        ))
    } else {
        bail!("invalid file spec: {}, expected local:remote", spec)
    }
}
// =======================================================
// SOCKS5 proxy
// ======================================================================

pub(crate) fn print_help() {
    println!(
        "{} - SSH automation tool (russh-based, SSH-compatible CLI)",
        PKG_NAME
    );
    println!();
    println!(
        "USAGE:  {} [OPTIONS] [user@]host[:port] [command...]",
        PKG_NAME
    );
    println!();
    println!("OPTIONS:");
    println!("  -4, -6           IPv4/IPv6 only");
    println!("  -A, -a           Agent forward on/off");
    println!("  -C               Compression");
    println!("  -D <spec>        SOCKS5 proxy (bind:port)");
    println!("  -H <spec>        HTTP CONNECT proxy (bind:port)");
    println!("  -E <file>        Log file");
    println!("  -f               Fork to background");
    println!("  -i <file>        Identity file");
    println!("  -J <jump>        Proxy jump");
    println!("  -L <spec>        Local forward ([bind:]port:host:port)");
    println!("  -l <user>        Login user");
    println!("  -N               No command (forward only)");
    println!("  -n               Redirect stdin from /dev/null");
    println!("  -o <k=v>         SSH option");
    println!("  -p <port>        SSH port");
    println!("  -q               Quiet");
    println!("  -R <spec>        Remote forward ([bind:]port:host:port)");
    println!("  -S <path>        Control socket path");
    println!("  -t               Force PTY");
    println!("  -v/-vv/-vvv      Verbose");
    println!("  -V/--version     Version");
    println!("  --connect-timeout <s>");
    println!("  --exec-env <VAR=val>  Set env on remote");
    println!("  --identity-passphrase   Key passphrase (or @file)");
    println!("  --identity-passphrase-file  Read passphrase from file");
    println!("  --password <pw>  SSH password (or @file)");
    println!("  --password-file   Read password from file");
    println!("  --timeout <s>    Inactivity timeout");
    println!("  --push <l>:<r>   Upload file/dir");
    println!("  --pull <r>:<l>   Download file/dir");
    println!("  --rsync <l>:<r>  Smart sync (mtime/size + copia delta)");
    println!();
    println!("EXAMPLE: {} -i ~/.ssh/id_ed25519 user@host cmd", PKG_NAME);
    println!(
        "         {} --push script.sh:/tmp/s.sh user@host bash /tmp/s.sh",
        PKG_NAME
    );
    println!(
        "         {} -N -f -L 8118:localhost:8118 user@host",
        PKG_NAME
    );
}

#[cfg(test)]
mod forward_spec_tests {
    use super::parse_forward_spec;

    #[test]
    fn plain_port_host_port() {
        let f = parse_forward_spec("9090:localhost:90").unwrap();
        assert_eq!(f.bind_addr, "127.0.0.1");
        assert_eq!(f.bind_port, 9090);
        assert_eq!(f.target_host, "localhost");
        assert_eq!(f.target_port, 90);
    }

    #[test]
    fn regression_target_host_not_polluted_by_bind_port() {
        // Previously parsed target_host as "34567:localhost" because the bind
        // port was not peeled off before extracting the host.
        let f = parse_forward_spec("34567:localhost:22222").unwrap();
        assert_eq!(f.bind_port, 34567);
        assert_eq!(f.target_host, "localhost");
        assert_eq!(f.target_port, 22222);
    }

    #[test]
    fn plain_bind_address() {
        let f = parse_forward_spec("0.0.0.0:8080:localhost:80").unwrap();
        assert_eq!(f.bind_addr, "0.0.0.0");
        assert_eq!(f.bind_port, 8080);
        assert_eq!(f.target_host, "localhost");
        assert_eq!(f.target_port, 80);
    }

    #[test]
    fn bracketed_ipv6_bind_address() {
        let f = parse_forward_spec("[::1]:8080:localhost:80").unwrap();
        assert_eq!(f.bind_addr, "::1");
        assert_eq!(f.bind_port, 8080);
        assert_eq!(f.target_host, "localhost");
        assert_eq!(f.target_port, 80);
    }

    #[test]
    fn bracketed_ipv6_target_host() {
        let f = parse_forward_spec("9090:[::1]:80").unwrap();
        assert_eq!(f.bind_addr, "127.0.0.1");
        assert_eq!(f.bind_port, 9090);
        assert_eq!(f.target_host, "::1");
        assert_eq!(f.target_port, 80);
    }

    #[test]
    fn invalid_specs_error() {
        // Missing target port.
        assert!(parse_forward_spec("9090:localhost").is_err());
        // Non-numeric bind port with no bind address.
        assert!(parse_forward_spec("9090:localhost:notaport").is_err());
    }
}
