use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::types::{DynamicForwardSpec, ForwardSpec, ProxyJumpSpec};
const PKG_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Parser, Clone)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    trailing_var_arg = true,
    disable_help_flag = true
)]
pub(crate) struct Cli {
    #[arg(short = 'p', long = "port", default_value_t = 22)]
    pub(crate) ssh_port: u16,
    /// Introspect supported algorithms for one of: cipher, mac,
    /// kex, compression, key, help. Multiple `-Q` flags print
    /// each list in turn. Mirrors OpenSSH `-Q <what>` (no SSH
    /// traffic involved — passhrs prints and exits 0).
    #[arg(short = 'Q', long = "query", value_name = "what")]
    pub(crate) query: Vec<String>,
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
    /// Disable pseudo-terminal allocation (overrides `-t`).
    /// Matches OpenSSH `-T`. By default passhrs allocates a PTY
    /// for any non-`-N` command; pass `-T` to suppress that even
    /// for interactive commands.
    #[arg(short = 'T', long = "no-pty")]
    pub(crate) disable_pty: bool,
    #[arg(short = 'L', long = "local-forward", num_args = 1)]
    pub(crate) local_forward: Vec<String>,
    /// Allow remote hosts to connect to locally-forwarded ports.
    /// Matches OpenSSH `-g` / `-o GatewayPorts=yes`. By default,
    /// `-L` and `-D` bind `127.0.0.1` only (loopback); with `-g`
    /// they bind `0.0.0.0` so a remote host can route traffic into
    /// the listener. Explicit bind addresses (`-L 1.2.3.4:...`)
    /// are unaffected.
    #[arg(short = 'g', long = "gateway-ports")]
    pub(crate) gateway_ports: bool,
    /// Use `<address>` as the **source** address for the outbound
    /// TCP connection to sshd. Matches OpenSSH `-b` / `-o
    /// BindAddress=<address>`. Useful on multi-homed hosts when
    /// you need the connection to leave via a specific interface
    /// (e.g. `-b 192.0.2.10` to make the kernel bind the source
    /// IP before SYN). Distinct from `-g` (which sets the bind of
    /// the local-forward listener, not the SSH connection) and
    /// from `-L <bind>:…` (listener side of `-L`, again not the
    /// SSH connection). Empty string (`-b ""`) is accepted and
    /// behaves as if `-b` was not passed — same as OpenSSH.
    #[arg(short = 'b', long = "bind", value_name = "address")]
    pub(crate) bind_address: Option<String>,
    /// Bind the outbound SSH TCP connection to a specific local
    /// network interface by name (OpenSSH `-B`). Implemented via
    /// Linux's `SO_BINDTODEVICE` setsockopt — packets emitted by
    /// the SSH socket are routed through the named interface
    /// regardless of the routing table. Useful on multi-homed
    /// Linux hosts that need outbound connections to leave via a
    /// specific NIC (replication NIC, management NIC, etc.) when
    /// the kernel's route table can't pick the right one. Distinct
    /// from `-b <address>` (which chooses the source *IP* —
    /// orthogonal: `-b 192.0.2.10 -B eth0` pins both). Linux-only;
    /// on other Unixes a startup warn is logged and the flag is a
    /// no-op (OpenSSH errors here; passhrs's existing "feature
    /// unavailable on this OS" pattern is warn-and-continue). On
    /// Windows the flag is accepted by clap and ignored. Empty
    /// string (`-B ""`) is accepted and behaves as if not passed.
    #[arg(short = 'B', long = "bind-interface", value_name = "interface")]
    pub(crate) bind_interface: Option<String>,
    /// Unconditionally accept any host key. Matches OpenSSH `-y`.
    /// Stricter than `-o StrictHostKeyChecking=no`: the latter
    /// silently appends *new* keys to `known_hosts` and rejects
    /// *mismatches*; `-y` accepts both without writing and without
    /// comparing. Use for one-shot connections to short-lived
    /// hosts (ephemeral CI containers, disposable VMs) where
    /// persisting or verifying the key is not useful. A `WARN`
    /// line is logged on every skip so the user knows verification
    /// was bypassed.
    #[arg(short = 'y', long = "accept-all-hosts")]
    pub(crate) accept_all_host_keys: bool,
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
    /// Passhrs-native Unix-domain control socket for master/resume
    /// (`-S <path>`). When set, this invocation either becomes the
    /// master (binds a UDS at `<path>`) or, if no fresh-auth flags
    /// are given, tries to resume through an existing master at
    /// `<path>`. Unix-only; wire format is passhrs-native (NOT
    /// OpenSSH-compatible).
    #[arg(short = 'S', long = "control-path", value_name = "path")]
    pub(crate) control_path: Option<String>,
    /// Send a control command to an existing master at `-S <path>`
    /// (`check` / `exit` / `stop`). Companion to `-S` (Issue #54).
    /// `-O check` connects to the master and prints
    /// "Master running" (exit 0) or "No master running" (exit 1).
    /// `-O exit` / `-O stop` asks the master to terminate cleanly.
    /// The master itself is bound by `-S`; both flags must be set.
    #[arg(short = 'O', long = "control-command", value_name = "cmd")]
    pub(crate) control_command: Option<String>,
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
    /// Select symmetric cipher algorithm(s) for the SSH
    /// transport. Comma-separated list in priority order.
    /// Defaults to russh's built-in order
    /// (chacha20-poly1305, aes256-gcm, aes256-ctr, …).
    ///
    /// Example: `-c chacha20-poly1305@openssh.com,aes256-gcm@openssh.com`
    #[arg(
        short = 'c',
        long = "cipher-spec",
        value_name = "spec",
        value_delimiter = ','
    )]
    pub(crate) cipher_spec: Vec<String>,
    /// Select MAC algorithm(s) for the SSH transport.
    /// Comma-separated list in priority order. Defaults to
    /// russh's built-in order (hmac-sha2-512-etm,
    /// hmac-sha2-256-etm, hmac-sha2-512, hmac-sha2-256).
    ///
    /// Example: `-m hmac-sha2-256,hmac-sha2-512`
    #[arg(
        short = 'm',
        long = "mac-spec",
        value_name = "spec",
        value_delimiter = ','
    )]
    pub(crate) mac_spec: Vec<String>,
    #[arg(
        long = "shell",
        value_parser = ["sh", "cmd"],
        default_value = "sh",
        value_name = "sh|cmd"
    )]
    /// Remote shell syntax for `--exec-env` and command-line variable
    /// references. `sh` (default) emits `export VAR=val` and treats
    /// `$VAR` in commands as POSIX; `cmd` emits `set "VAR=val"` (cmd.exe
    /// syntax) and rewrites `$VAR` references in the user-supplied
    /// command to `%VAR%`. Use `cmd` when the remote sshd serves
    /// Windows OpenSSH whose default shell is cmd.exe (e.g. Win32-OpenSSH
    /// 10.0p2). `sh` is the default for backward compatibility — the
    /// entire Unix e2e suite uses sh.
    pub(crate) shell: String,
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
    /// Force debug-level log output (overrides `-q`; equivalent to
    /// setting `RUST_LOG=debug`). Useful for triaging without
    /// exporting RUST_LOG in the calling shell.
    #[arg(long = "debug-all")]
    pub(crate) debug_all: bool,
    /// Set the escape character for interactive sessions
    /// (matches OpenSSH `-e <ch>`). The escape character is a
    /// single character (`~` by default, matching OpenSSH) that,
    /// when typed at the start of a line on the local pty,
    /// triggers session-level actions: `~.` disconnects cleanly,
    /// `~?` prints the help text. The literal value `none`
    /// disables the escape entirely (every byte is forwarded).
    /// Other characters can be specified as a single UTF-8
    /// character (e.g. `-e ~`, `-e ?`) or via the OpenSSH caret
    /// notation (`-e ^a` = Ctrl-A, `-e ^?` = DEL). Only honored
    /// when a PTY is allocated (`-t` or auto with a TTY);
    /// ignored otherwise. Issue #57.
    #[arg(short = 'e', long = "escape-char", value_name = "ch|none")]
    pub(crate) escape_char: Option<String>,
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

/// Resolve `-e <ch>` / `--escape-char <ch>` to the byte that
/// opens an escape sequence at the start of a line, or `None`
/// if escape handling is disabled.
///
/// OpenSSH accepts:
/// - `none` (literal, case-insensitive) — disable escape
/// - a single byte, e.g. `~`, `?`, `a`
/// - caret notation: `^a` → Ctrl-A (0x01), `^?` → DEL (0x7F),
///   `^^` → literal `^`, `^` followed by any other char error.
///
/// Default: `Some(b'~')` (the OpenSSH default). Issue #57.
pub(crate) fn parse_escape_char(spec: &str) -> Result<Option<u8>> {
    let s = spec.trim();
    if s.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    if s.is_empty() {
        bail!("-e: empty escape character (use 'none' to disable)");
    }
    // Caret notation.
    if let Some(rest) = s.strip_prefix('^') {
        let bytes = rest.as_bytes();
        if bytes.len() != 1 {
            bail!(
                "-e: '^' must be followed by exactly one character (got {:?})",
                s
            );
        }
        let c = bytes[0];
        let resolved = match c {
            b'?' => 0x7f,                // DEL
            b'^' => b'^',                // literal '^'
            b'a'..=b'z' => c - b'a' + 1, // ^A=0x01, ^Z=0x1A
            b'A'..=b'Z' => c - b'A' + 1,
            _ => bail!("-e: unsupported control character {:?}", s),
        };
        return Ok(Some(resolved));
    }
    // Plain literal — must be one character. OpenSSH takes the
    // first byte of the UTF-8 string, since terminal escape
    // chars are all ASCII in practice.
    let bytes = s.as_bytes();
    if bytes.len() != 1 {
        bail!("-e: escape character must be exactly one byte, got {:?}", s);
    }
    Ok(Some(bytes[0]))
}

/// Resolve the effective escape character: takes the user's
/// `-e` value if set, otherwise returns the OpenSSH default `~`.
pub(crate) fn effective_escape_char(cli: &Cli) -> Option<u8> {
    match cli.escape_char.as_deref() {
        None => Some(b'~'),
        Some(s) => match parse_escape_char(s) {
            Ok(v) => v,
            // An invalid `-e` should have been rejected at parse
            // time (we'd add a `validate` hook on the field). On
            // the off-chance it slipped through, fall back to
            // the OpenSSH default rather than crash.
            Err(e) => {
                eprintln!("-e: invalid value {:?}, falling back to default: {}", s, e);
                Some(b'~')
            }
        },
    }
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

pub(crate) fn parse_forward_spec(spec: &str, gateway_ports: bool) -> Result<ForwardSpec> {
    let spec = spec.trim();

    // Determine the optional bind address and the remaining
    // "port:host:hostport" core. Supported forms:
    //   port:host:hostport                 -> bind defaults to 127.0.0.1
    //                                      (or 0.0.0.0 when gateway_ports=true)
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
            (
                if gateway_ports {
                    "0.0.0.0".to_string()
                } else {
                    "127.0.0.1".to_string()
                },
                spec.to_string(),
            )
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

pub(crate) fn parse_dynamic_spec(spec: &str, gateway_ports: bool) -> Result<DynamicForwardSpec> {
    if let Some(colon_idx) = spec.find(':') {
        // Explicit bind address wins; gateway_ports does not override
        // a user-provided bind (same as parse_forward_spec).
        Ok(DynamicForwardSpec {
            bind_addr: spec[..colon_idx].to_string(),
            bind_port: spec[colon_idx + 1..]
                .parse()
                .context("invalid SOCKS port")?,
        })
    } else {
        Ok(DynamicForwardSpec {
            bind_addr: if gateway_ports {
                "0.0.0.0".into()
            } else {
                "127.0.0.1".into()
            },
            bind_port: spec.parse().context("invalid SOCKS port")?,
        })
    }
}
// =======================================================
// SFTP recursive push/pull helpers
// ======================================================================

pub(crate) fn expand_path(path: &str) -> String {
    let expanded = if path == "~" {
        if let Some(home) = dirs::home_dir() {
            home.display().to_string()
        } else {
            path.to_string()
        }
    } else if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            format!("{}/{}", home.display(), rest)
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    };
    // dirs::home_dir() on Windows returns a backslash-separated path
    // (e.g. "C:\Users\foo"); the format!() join above then mixes it
    // with a forward slash, producing "C:\Users\foo/rest". Pass the
    // result through normalize_slashes so every downstream consumer
    // (tokio::fs::*, sftp.*) sees a single separator convention.
    normalize_slashes(&expanded)
}

/// Replace backslashes with forward slashes. No-op for Unix paths
/// (which contain no backslash) and for already-normalized Windows
/// paths. Used at parse-time in `parse_file_spec` so that the local
/// half of a `--push`/`--pull`/`--rsync` spec round-trips cleanly
/// through the SFTP layer (which forwards the path string literally
/// to sshd) and through tokio::fs on Windows (which accepts either
/// separator but is sloppy with mixed forms).
fn normalize_slashes(s: &str) -> String {
    s.replace('\\', "/")
}

/// True if `s` starts with a Windows drive-letter absolute prefix
/// `[A-Za-z]:[\\/]` (e.g. `C:\…`, `D:/…`). UNC paths (`\\…` or
/// `//…`) intentionally return false here: they don't carry a
/// drive-letter colon, so their first `:` (if any) is correctly the
/// local/remote separator that `parse_file_spec` looks for.
fn starts_with_drive_letter(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
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
    // Windows drive-letter local paths (e.g. `C:\Users\foo:/remote/bar`)
    // carry their own colon in byte position 1, so a naive first-`:` split
    // breaks them. Detect the drive-letter prefix and skip past that colon,
    // finding the *next* `:` as the local/remote separator. UNC paths
    // (`\\server\share\file:/remote/bar`) have no drive-letter colon, so
    // they fall through to the naive first-`:` split naturally — which is
    // correct, since UNC's first `:` (if any) is the local/remote divider.
    let colon_idx = if starts_with_drive_letter(spec) {
        spec[3..]
            .find(':')
            .ok_or_else(|| anyhow::anyhow!("invalid file spec: {}, expected local:remote", spec))
            .map(|i| 3 + i)?
    } else {
        spec.find(':')
            .ok_or_else(|| anyhow::anyhow!("invalid file spec: {}, expected local:remote", spec))?
    };
    let local = normalize_slashes(&spec[..colon_idx]);
    let remote = normalize_slashes(&spec[colon_idx + 1..]);
    Ok((local, remote))
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
    println!("  -b <address>     Source bind address for SSH connection (or -o BindAddress=)");
    println!("  -c <list>        Cipher spec (comma-sep, priority order)");
    println!("  -m <list>        MAC spec (comma-sep, priority order)");
    println!("  -C               Compression");
    println!("  -D <spec>        SOCKS5 proxy (bind:port)");
    println!("  -H <spec>        HTTP CONNECT proxy (bind:port)");
    println!("  -E <file>        Log file");
    println!("  -Q <what>        List supported algorithms (cipher|mac|kex|compression|key|help)");
    println!("  -f               Fork to background");
    println!("  -g               Allow remote hosts to connect local forwards (0.0.0.0)");
    println!("  -i <file>        Identity file");
    println!("  -J <jump>        Proxy jump");
    println!("  -L <spec>        Local forward ([bind:]port:host:port)");
    println!("  -l <user>        Login user");
    println!("  -N               No command (forward only)");
    println!("  -n               Redirect stdin from /dev/null");
    println!("  -o <k=v>         SSH option");
    println!("  -O <cmd>         Control command on -S master (check|exit|stop)");
    println!("  -p <port>        SSH port");
    println!("  -q               Quiet");
    println!("  -R <spec>        Remote forward ([bind:]port:host:port)");
    println!("  -S <path>        Control socket path (master/resume; Unix only)");
    println!("  -T               Disable PTY allocation (overrides -t)");
    println!("  -t               Force PTY");
    println!("  -v/-vv/-vvv      Verbose");
    println!("  -V/--version     Version");
    println!("  -y               Accept any host key (no check, no persist)");
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
    use super::{parse_dynamic_spec, parse_forward_spec};

    #[test]
    fn plain_port_host_port() {
        let f = parse_forward_spec("9090:localhost:90", false).unwrap();
        assert_eq!(f.bind_addr, "127.0.0.1");
        assert_eq!(f.bind_port, 9090);
        assert_eq!(f.target_host, "localhost");
        assert_eq!(f.target_port, 90);
    }

    #[test]
    fn regression_target_host_not_polluted_by_bind_port() {
        // Previously parsed target_host as "34567:localhost" because the bind
        // port was not peeled off before extracting the host.
        let f = parse_forward_spec("34567:localhost:22222", false).unwrap();
        assert_eq!(f.bind_port, 34567);
        assert_eq!(f.target_host, "localhost");
        assert_eq!(f.target_port, 22222);
    }

    #[test]
    fn plain_bind_address() {
        let f = parse_forward_spec("0.0.0.0:8080:localhost:80", false).unwrap();
        assert_eq!(f.bind_addr, "0.0.0.0");
        assert_eq!(f.bind_port, 8080);
        assert_eq!(f.target_host, "localhost");
        assert_eq!(f.target_port, 80);
    }

    #[test]
    fn bracketed_ipv6_bind_address() {
        let f = parse_forward_spec("[::1]:8080:localhost:80", false).unwrap();
        assert_eq!(f.bind_addr, "::1");
        assert_eq!(f.bind_port, 8080);
        assert_eq!(f.target_host, "localhost");
        assert_eq!(f.target_port, 80);
    }

    #[test]
    fn bracketed_ipv6_target_host() {
        let f = parse_forward_spec("9090:[::1]:80", false).unwrap();
        assert_eq!(f.bind_addr, "127.0.0.1");
        assert_eq!(f.bind_port, 9090);
        assert_eq!(f.target_host, "::1");
        assert_eq!(f.target_port, 80);
    }

    #[test]
    fn invalid_specs_error() {
        // Missing target port.
        assert!(parse_forward_spec("9090:localhost", false).is_err());
        // Non-numeric bind port with no bind address.
        assert!(parse_forward_spec("9090:localhost:notaport", false).is_err());
    }

    // ---- -g / --gateway-ports: default-bind 0.0.0.0 ----
    //
    // When `gateway_ports=true` is threaded through the parser and the
    // user did NOT supply an explicit bind address, the default bind
    // address becomes 0.0.0.0 (the same default OpenSSH uses with
    // `-g` or `-o GatewayPorts=yes`). An explicit bind address from
    // the user always wins. Symmetric coverage for parse_dynamic_spec
    // (used by `-D` and `-H`).

    #[test]
    fn gateway_ports_default_wildcard_when_no_explicit_bind() {
        let f = parse_forward_spec("8118:localhost:80", true).unwrap();
        assert_eq!(
            f.bind_addr, "0.0.0.0",
            "gateway_ports=true must default to 0.0.0.0"
        );
        assert_eq!(f.bind_port, 8118);
    }

    #[test]
    fn gateway_ports_explicit_bind_wins() {
        let f = parse_forward_spec("192.168.1.5:8118:localhost:80", true).unwrap();
        assert_eq!(
            f.bind_addr, "192.168.1.5",
            "explicit bind must survive gateway_ports=true"
        );
    }

    #[test]
    fn gateway_ports_explicit_bracketed_ipv6_wins() {
        let f = parse_forward_spec("[::1]:8118:localhost:80", true).unwrap();
        assert_eq!(
            f.bind_addr, "::1",
            "explicit bracketed IPv6 bind must survive"
        );
    }

    #[test]
    fn no_gateway_ports_default_loopback() {
        // Regression guard for the existing default. The flag's
        // false branch must continue to produce 127.0.0.1 — i.e.
        // flipping to 0.0.0.0 requires an explicit opt-in.
        let f = parse_forward_spec("8118:localhost:80", false).unwrap();
        assert_eq!(f.bind_addr, "127.0.0.1");
    }

    #[test]
    fn dynamic_gateway_ports_default_wildcard_when_bare_port() {
        // `-D 1080` — bare SOCKS spec, no explicit bind.
        let d = parse_dynamic_spec("1080", true).unwrap();
        assert_eq!(d.bind_addr, "0.0.0.0");
        assert_eq!(d.bind_port, 1080);
    }

    #[test]
    fn dynamic_no_gateway_ports_default_loopback_when_bare_port() {
        let d = parse_dynamic_spec("1080", false).unwrap();
        assert_eq!(d.bind_addr, "127.0.0.1");
        assert_eq!(d.bind_port, 1080);
    }

    #[test]
    fn dynamic_explicit_bind_wins_regardless_of_gateway_ports() {
        let d = parse_dynamic_spec("0.0.0.0:1080", true).unwrap();
        assert_eq!(d.bind_addr, "0.0.0.0");
        let d = parse_dynamic_spec("127.0.0.1:1080", true).unwrap();
        assert_eq!(d.bind_addr, "127.0.0.1");
    }
}

#[cfg(test)]
mod escape_char_tests {
    //! Unit tests for `-e` / `--escape-char` (Issue #57). The
    //! cases here pin both the OpenSSH-compatible forms
    //! (`none`, single char, `^X` control-char notation) and the
    //! rejection paths (empty, multi-byte, malformed `^`).
    use super::parse_escape_char;

    #[test]
    fn none_disables() {
        assert_eq!(parse_escape_char("none").unwrap(), None);
        assert_eq!(parse_escape_char("NONE").unwrap(), None);
        assert_eq!(parse_escape_char("None").unwrap(), None);
    }

    #[test]
    fn single_literal_char() {
        assert_eq!(parse_escape_char("~").unwrap(), Some(b'~'));
        assert_eq!(parse_escape_char("?").unwrap(), Some(b'?'));
        assert_eq!(parse_escape_char("#").unwrap(), Some(b'#'));
    }

    #[test]
    fn caret_ctrl_a_through_z() {
        assert_eq!(parse_escape_char("^a").unwrap(), Some(0x01));
        assert_eq!(parse_escape_char("^z").unwrap(), Some(0x1a));
    }

    #[test]
    fn caret_uppercase_letters() {
        // OpenSSH accepts both cases; `^A` maps to the same byte
        // as `^a` (0x01).
        assert_eq!(parse_escape_char("^A").unwrap(), Some(0x01));
        assert_eq!(parse_escape_char("^Z").unwrap(), Some(0x1a));
    }

    #[test]
    fn caret_question_mark_is_del() {
        // `^?` is the OpenSSH convention for DEL (0x7F).
        assert_eq!(parse_escape_char("^?").unwrap(), Some(0x7f));
    }

    #[test]
    fn caret_double_caret_is_literal() {
        // `^^` escapes to a literal `^` so the user can pick `^`
        // as their escape char.
        assert_eq!(parse_escape_char("^^").unwrap(), Some(b'^'));
    }

    #[test]
    fn empty_string_is_error() {
        assert!(parse_escape_char("").is_err());
        assert!(parse_escape_char("   ").is_err());
    }

    #[test]
    fn multi_byte_is_error() {
        // `-e ab` is meaningless; reject.
        assert!(parse_escape_char("ab").is_err());
    }

    #[test]
    fn caret_with_no_following_char_is_error() {
        // `-e ^` is malformed.
        assert!(parse_escape_char("^").is_err());
    }

    #[test]
    fn caret_with_multi_char_following_is_error() {
        assert!(parse_escape_char("^ab").is_err());
    }

    #[test]
    fn caret_with_unsupported_char_is_error() {
        // `^1` has no canonical mapping in OpenSSH; reject.
        assert!(parse_escape_char("^1").is_err());
    }
}

#[cfg(test)]
mod file_spec_tests {
    //! Unit tests for `parse_file_spec` and `expand_path`. Most of
    //! these cover the Windows drive-letter colon collision fix
    //! (Issue #4) — without the fix, `parse_file_spec("C:\foo:/r")`
    //! returns local="C" / remote="\foo:/r" because the parser split
    //! on the first `:` (the drive-letter colon) instead of the
    //! second.

    use super::{expand_path, parse_file_spec};

    // ---- Drive-letter colon collision (Issue #4) ----

    #[test]
    fn drive_letter_backslash_split() {
        let (l, r) = parse_file_spec(r"C:\Users\foo:/remote/bar").unwrap();
        assert_eq!(l, "C:/Users/foo");
        assert_eq!(r, "/remote/bar");
    }

    #[test]
    fn drive_letter_forward_slash_split() {
        let (l, r) = parse_file_spec("C:/Users/foo:/remote/bar").unwrap();
        assert_eq!(l, "C:/Users/foo");
        assert_eq!(r, "/remote/bar");
    }

    #[test]
    fn drive_letter_lowercase() {
        let (l, r) = parse_file_spec(r"c:\users\foo:/remote/bar").unwrap();
        assert_eq!(l, "c:/users/foo");
        assert_eq!(r, "/remote/bar");
    }

    #[test]
    fn unc_backslash_split() {
        // UNC paths have no drive-letter colon, so they fall through
        // to the naive first-`:` split — the single `:` in the spec
        // is the local/remote separator, which is correct.
        let (l, r) = parse_file_spec(r"\\server\share\file:/remote/bar").unwrap();
        assert_eq!(l, "//server/share/file");
        assert_eq!(r, "/remote/bar");
    }

    #[test]
    fn unc_forward_slash_split() {
        let (l, r) = parse_file_spec("//server/share/file:/remote/bar").unwrap();
        assert_eq!(l, "//server/share/file");
        assert_eq!(r, "/remote/bar");
    }

    #[test]
    fn ntfs_stream_first_post_drive_colon_wins() {
        // With `C:\file:stream:/remote/bar`, the first `:` after the
        // drive-letter prefix is the NTFS alternate-data-stream
        // separator. The parser can't tell it apart from the
        // local/remote separator, so the documented behavior is
        // "first `:` after the drive letter wins" — i.e. the stream
        // colon is treated as the spec divider. Result: local="C:/file",
        // remote="stream:/remote/bar". This means NTFS streams in a
        // `--push` local arg are not unambiguously supported; users
        // with NTFS-stream requirements need a different escape
        // mechanism (a future feature, not handled here).
        let (l, r) = parse_file_spec(r"C:\file:stream:/remote/bar").unwrap();
        assert_eq!(l, "C:/file");
        assert_eq!(r, "stream:/remote/bar");
    }

    #[test]
    fn drive_relative_falls_through_naively() {
        // `C:foo` has no separator after the colon, so
        // `starts_with_drive_letter` returns false (it requires the byte
        // at position 2 to be `\` or `/`). The naive first-`:` split then
        // applies: local="C", remote="foo". Documented as not-supported.
        let (l, r) = parse_file_spec("C:foo").unwrap();
        assert_eq!(l, "C");
        assert_eq!(r, "foo");
    }

    // ---- Unix regression cases (must still pass) ----

    #[test]
    fn unix_paths_unchanged() {
        let (l, r) = parse_file_spec("/local/path:/remote/path").unwrap();
        assert_eq!(l, "/local/path");
        assert_eq!(r, "/remote/path");
    }

    #[test]
    fn unix_relative_local_unchanged() {
        let (l, r) = parse_file_spec("relative/file:/remote").unwrap();
        assert_eq!(l, "relative/file");
        assert_eq!(r, "/remote");
    }

    #[test]
    fn tilde_user_split_regression() {
        // Issue #3 regression case: `~user@host:/path:/extra` must still
        // split on the first `:`. The local half `~user@host` doesn't
        // match `starts_with_drive_letter` (the leading `~` isn't an
        // ASCII alphabetic), so the naive split applies.
        let (l, r) = parse_file_spec("~user@host:/path:/extra").unwrap();
        assert_eq!(l, "~user@host");
        assert_eq!(r, "/path:/extra");
    }

    // ---- Invalid specs ----

    #[test]
    fn no_colon_is_error() {
        assert!(parse_file_spec("nodivider").is_err());
    }

    #[test]
    fn drive_letter_with_no_remote_colon_is_error() {
        // `C:\foo` has a drive-letter colon but no further `:` to serve
        // as the local/remote separator.
        assert!(parse_file_spec(r"C:\foo").is_err());
    }

    #[test]
    fn empty_remote_preserved() {
        let (l, r) = parse_file_spec("/local/foo:").unwrap();
        assert_eq!(l, "/local/foo");
        assert_eq!(r, "");
    }

    // ---- expand_path normalization ----

    #[cfg(target_os = "windows")]
    #[test]
    fn expand_path_normalizes_windows_home() {
        // dirs::home_dir() returns something like `C:\Users\foo`. After
        // the fix, expand_path returns the home dir with forward slashes
        // so downstream SFTP calls receive clean paths.
        let p = expand_path("~/file");
        assert!(!p.contains('\\'), "backslash leaked: {}", p);
        assert!(
            p.starts_with("C:/Users/") || p.contains(":/"),
            "expected forward-slash absolute path, got {:?}",
            p
        );
    }

    #[cfg(unix)]
    #[test]
    fn expand_path_unix_unchanged() {
        // dirs::home_dir() returns an absolute path under the user's home
        // — /home/<user> on most Linuxes, /Users/<user> on macOS, etc.
        // Rather than hardcoding either prefix, just confirm the join
        // produced an absolute path that ends with "/file" and contains
        // no backslashes (the normalization invariant).
        let p = expand_path("~/file");
        assert!(p.starts_with('/'), "expected absolute path, got {:?}", p);
        assert!(p.ends_with("/file"), "expected trailing /file, got {:?}", p);
        assert!(!p.contains('\\'), "backslash leaked: {}", p);
    }
}
