mod cli;
mod forward;
mod proxy;
mod sftp;
mod ssh;
mod types;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use log::*;
use russh::client::{self};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use russh_sftp::client::SftpSession;

use crate::cli::*;
use crate::forward::{local_port_forward, spawn_forward_tasks};
use crate::proxy::*;
use crate::sftp::*;
use crate::ssh::*;
use crate::types::{DynamicForwardSpec, ForwardSpec};

/// True if `s` is an absolute filesystem path. Accepts both Unix
/// (`/…`) and Windows drive-letter (`[A-Za-z]:[\\/]…`) forms.
/// Strict superset of the previous `starts_with('/')` check — every
/// input it used to accept still returns true here.
fn is_absolute_path(s: &str) -> bool {
    if s.starts_with('/') {
        return true;
    }
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
}

/// Rewrite `$NAME` references in `cmd` to `%NAME%` for cmd.exe, where
/// `NAME` is drawn from `env_names` — the names that were just declared
/// via `--exec-env` so the substitution only fires for vars we know
/// were set, not for arbitrary `$FOO` text that happens to appear in the
/// user's command. A `$NAME` reference is recognised as `$` followed by
/// an ASCII alphabetic or `_` and then zero or more ASCII alphanumerics
/// or `_`. The replacement is whole-token: `$FOO` → `%FOO%`, `$FOO_BAR`
/// → `%FOO_BAR%`, but `$FOO123` → `%FOO123%` (no trailing-alphanum
/// boundary needed since `%` is unambiguous to cmd.exe). `$$` is left
/// alone (cmd.exe doesn't expand `$$` as an escape; pass it through).
fn rewrite_dollar_refs_for_cmd(cmd: &str, env_names: &[String]) -> String {
    if env_names.is_empty() {
        return cmd.to_string();
    }
    let mut out = String::with_capacity(cmd.len());
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && is_ident_start(bytes[i + 1]) {
            // Read identifier
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && is_ident_cont(bytes[end]) {
                end += 1;
            }
            let name = &cmd[start..end];
            if env_names.iter().any(|n| n == name) {
                out.push('%');
                out.push_str(name);
                out.push('%');
                i = end;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Build the env-var prefix that's prepended to the user-supplied
/// command. For each `--exec-env` spec we generated either
/// `set "NAME=val"` (cmd) or `export NAME=val` (sh) in `parts`; this
/// joins them with the right shell-specific separator and appends
/// the same separator before the command itself.
///
/// Separator choice: sh uses `;` (POSIX); cmd.exe uses `&`. cmd.exe
/// has no concept of `;` as a command separator — `;` is a literal
/// char, so `set "X=1"; echo Y` parses as ONE command line where
/// `set` receives `"X=1";`, `echo`, `Y` as args, the `echo` never
/// runs, and stdout comes out empty (this was the Issue #5 CI
/// failure on windows-2022 first attempt). `&` is cmd.exe's
/// unconditional sequence operator — the closest equivalent to `;`
/// in POSIX sh.
///
/// The user command itself (in cmd mode with non-empty parts) is
/// wrapped in a NESTED `cmd /c "…"` at the call site. The outer
/// cmd (started by sshd) parses the whole string upfront and
/// expands `%X%` BEFORE the preceding `set "X=v"` runs, so without
/// the inner wrap, `set "X=1" & echo %X%` echoes literal `%X%` (X
/// undefined at parse time). The inner `cmd /c "…"` gives the
/// user command its own parse context, AFTER the `set` has run,
/// so its parse of `%X%` sees X as inherited and populated.
fn build_exec_env_prefix(parts: &[String], shell: &str) -> String {
    if parts.is_empty() {
        return String::new();
    }
    if shell == "cmd" {
        format!("{} & ", parts.join(" & "))
    } else {
        let separator = "; ";
        format!("{}{}", parts.join(separator), separator)
    }
}

/// Classify an anyhow error into a one-line user-facing message.
///
/// The default anyhow Debug format (`{:#?}`) prints the full chain
/// with variant names, which is great for a developer reading the
/// source but reads as noise to a user triaging a failed CI run:
/// `Crypto(std::io::Error { kind: UnexpectedEof, message: "..." })`.
/// This walks the error chain looking for keywords that map to a
/// small set of user-meaningful buckets, and returns a one-line
/// message in each. If none match, returns the top-of-chain error
/// plus a hint to rerun with `-vv` for the full detail.
///
/// This is the **default-shape** error path: invoked only when the
/// user did NOT pass `-v`/`-vv`/`--debug-all`. The verbose ladder
/// keeps the original Debug dump — see `main()` below.
fn format_user_error(err: &anyhow::Error) -> String {
    // Walk the chain (cause -> source -> source ...) collecting
    // each layer's Display string. We match on the joined string
    // so a single error can match multiple keywords across layers
    // (e.g. the top says "Connection refused", the source says
    // "Connection timed out" — both connection-related).
    let chain: Vec<String> = err.chain().map(|c| c.to_string()).collect();
    let joined = chain.join(" | ").to_lowercase();

    // Auth failures: russh surfaces these via its `Error::Agent`
    // or as a plain "Permission denied" string from the server.
    // Common: "Permission denied (publickey,password)" after
    // exhausting auth methods.
    if joined.contains("authentication")
        || joined.contains("permission denied")
        || joined.contains("auth failed")
        || joined.contains("not authenticated")
    {
        return format!("passhrs: authentication failed ({})", chain[0]);
    }

    // Host key verification: the typical message is "Host key
    // verification failed" or "REMOTE HOST IDENTIFICATION HAS
    // CHANGED" depending on the source.
    if joined.contains("host key")
        || joined.contains("host identification")
        || joined.contains("knownhosts")
        || joined.contains("known_hosts")
    {
        return format!("passhrs: host key verification failed ({})", chain[0]);
    }

    // Connection failures: DNS, TCP refused, TCP timeout. These
    // are the "could not reach the server at all" class.
    if joined.contains("connection refused")
        || joined.contains("connection timed out")
        || joined.contains("failed to connect")
        || joined.contains("connection reset")
        || joined.contains("dns")
        || joined.contains("resolve")
        || joined.contains("no route to host")
        || joined.contains("network is unreachable")
    {
        return format!("passhrs: connection failed ({})", chain[0]);
    }

    // Channel / SFTP / forward failures: distinguish from connection
    // failures because the SSH handshake DID succeed — something
    // specific (a -L/-R spec, an SFTP push) died.
    if joined.contains("channel open")
        || joined.contains("forward")
        || joined.contains("sftp")
        || joined.contains("subsystem")
    {
        return format!("passhrs: forwarding/sftp failed ({})", chain[0]);
    }

    // ProxyJump-specific: the top-of-chain context will name the
    // jump host, which is what the user needs to act on.
    if joined.contains("proxyjump") || joined.contains("proxy jump") {
        return format!("passhrs: ProxyJump failed ({})", chain[0]);
    }

    // Unknown — fall back to a one-line summary + hint. The full
    // Debug chain is still available via -vv.
    format!(
        "passhrs: {} (rerun with -vv for details)",
        chain.first().map(String::as_str).unwrap_or("unknown")
    )
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if cli.help {
        print_help();
        return;
    }

    // Run the actual work. The verbose ladder preserves the
    // existing {:#?} Debug dump so -v / -vv / --debug-all
    // continues to show the full anyhow chain. Only the default
    // (warn) and -q (error) levels use the classified one-liner.
    if let Err(err) = run(cli.clone()).await {
        if cli.verbose > 0 || cli.debug_all {
            eprintln!("{:#?}", err);
        } else {
            eprintln!("{}", format_user_error(&err));
        }
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    if cli.fork {
        let args: Vec<String> = std::env::args()
            .filter(|a| a != "-f" && a != "--fork")
            .collect();
        let exe = std::env::current_exe()?;
        #[cfg(unix)]
        std::process::Command::new(&exe)
            .args(&args[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        #[cfg(windows)]
        std::process::Command::new(&exe)
            .args(&args[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(0x08000000)
            .spawn()?;
        std::process::exit(0);
    }

    let log_level = if cli.debug_all {
        "debug"
    } else if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level));
    builder.format_timestamp_millis();
    if let Some(ref f) = cli.log_file {
        if let Ok(file) = std::fs::File::create(f) {
            builder.target(env_logger::Target::Pipe(Box::new(file)));
        }
    }
    builder.init();

    let opts = parse_ssh_options(&cli.ssh_option);
    let dest_str = cli.destination.as_deref().unwrap_or("");
    if dest_str.is_empty()
        && cli.local_forward.is_empty()
        && cli.remote_forward.is_empty()
        && cli.dynamic_forward.is_empty()
    {
        // No destination and no forward flags means the user typed
        // `passhrs` with no args at all. Clap happily accepts that
        // (the destination field is `Option<String>`, not required),
        // but a bare "Error: no destination specified" leaves a
        // first-time user with no idea what to type next. Print the
        // same help text `--help` shows and exit 0 — i.e. behave
        // equivalently to `passhrs --help`. This matches the
        // convention most Unix tools follow (e.g. `git` with no
        // subcommand prints usage to stdout and exits 0) and lets
        // users who tab-complete `passhrs<Enter>` see the full
        // option list immediately.
        print_help();
        return Ok(());
    }

    let (host, user_from_dest, port_from_dest) = if dest_str.is_empty() {
        ("".into(), None, 22u16)
    } else {
        parse_destination(dest_str)?
    };
    let user = cli
        .user
        .as_deref()
        .or(user_from_dest.as_deref())
        .unwrap_or("root");
    let port = if cli.ssh_port != 22 {
        cli.ssh_port
    } else {
        port_from_dest
    };
    let port = opts
        .get("port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(port);
    let password = if let Some(ref f) = cli.password_file {
        let val = std::fs::read_to_string(f)
            .with_context(|| format!("failed to read --password-file: {}", f))?;
        Some(val.trim_end().to_string())
    } else {
        cli.password
            .as_deref()
            .map(read_value_from_file)
            .transpose()?
    };
    let passphrase = if let Some(ref f) = cli.passphrase_file {
        let val = std::fs::read_to_string(f)
            .with_context(|| format!("failed to read --identity-passphrase-file: {}", f))?;
        Some(val.trim_end().to_string())
    } else {
        cli.passphrase
            .as_deref()
            .map(read_value_from_file)
            .transpose()?
    };

    let local_forwards: Vec<ForwardSpec> = cli
        .local_forward
        .iter()
        .map(|s| parse_forward_spec(s))
        .collect::<Result<Vec<_>>>()?;
    let remote_forwards: Vec<ForwardSpec> = cli
        .remote_forward
        .iter()
        .map(|s| parse_forward_spec(s))
        .collect::<Result<Vec<_>>>()?;
    let mut remote_forward_map: HashMap<u16, ForwardSpec> = HashMap::new();
    for fw in &remote_forwards {
        remote_forward_map.insert(fw.bind_port, fw.clone());
    }
    let dynamic_forwards: Vec<DynamicForwardSpec> = cli
        .dynamic_forward
        .iter()
        .map(|s| parse_dynamic_spec(s))
        .collect::<Result<Vec<_>>>()?;
    let http_connects: Vec<DynamicForwardSpec> = cli
        .http_proxy_connect
        .iter()
        .map(|s| parse_dynamic_spec(s))
        .collect::<Result<Vec<_>>>()?;

    let user_known_hosts = std::sync::Arc::new(opts.get("userknownhostsfile").cloned());
    let strict_check = opts
        .get("stricthostkeychecking")
        .map(|v| v == "yes" || v == "accept-new")
        .unwrap_or(false);
    let keepalive_interval = opts
        .get("serveraliveinterval")
        .and_then(|v| v.parse::<u64>().ok());
    let keepalive_max = opts
        .get("serveralivecountmax")
        .and_then(|v| v.parse::<usize>().ok());
    let tcp_keepalive = opts
        .get("tcpkeepalive")
        .map(|v| v == "yes")
        .unwrap_or(false);
    let exit_on_fwd_failure = opts
        .get("exitonforwardfailure")
        .map(|v| v == "yes")
        .unwrap_or(false);
    let need_ssh = !host.is_empty();
    if need_ssh {
        info!("Connecting to {}:{} as {}", host, port, user);
        // DEBUG (caf58d8 follow-up): trace exactly which user is
        // bound into the russh userauth path. The DEBUG3 sshd log on
        // caf58d8 showed the first few passhrs tests sending
        // `for user runner method password` to sshd even though the
        // info!() above clearly said "as testuser". We need to know
        // (a) whether cli.user is being set somewhere we don't see
        // and (b) whether the OS-level $USER is leaking into the
        // auth path. Logging both at debug level so it only shows
        // when RUST_LOG=passhrs=debug (which CI sets).
        debug!(
            "auth ctx: cli.user={:?} user_from_dest={:?} resolved user={:?} \
             cli.identity_file={:?} OS_USER={:?}",
            cli.user,
            user_from_dest,
            user,
            cli.identity_file,
            std::env::var("USER").ok(),
        );
        let connect_timeout = cli.connect_timeout;
        let mut config = client::Config::default();
        if cli.inactivity_timeout > 0 {
            config.inactivity_timeout =
                Some(std::time::Duration::from_secs(cli.inactivity_timeout));
        }
        if let Some(interval) = keepalive_interval {
            config.keepalive_interval = Some(std::time::Duration::from_secs(interval));
        }
        if let Some(max_count) = keepalive_max {
            config.keepalive_max = max_count;
        }
        if cli.compress {
            use std::borrow::Cow;
            config.preferred.compression =
                Cow::Owned(vec![russh::compression::ZLIB, russh::compression::NONE]);
        }
        // Apply TCPKeepAlive default if requested without explicit ServerAliveInterval
        if tcp_keepalive && keepalive_interval.is_none() {
            config.keepalive_interval = Some(std::time::Duration::from_secs(60));
        }
        // ----- -A agent forwarding (Issue #23) -----
        //
        // Resolve the local agent socket path that the russh handler
        // will dial when sshd later opens an `auth-agent@openssh.com`
        // channel at us. Decision order (mirrors OpenSSH):
        //
        //   1. `-a` (no_forward_agent): explicit disable — pass None
        //      down so the handler treats every agent channel-open as
        //      a no-op (channel accepted, immediately drained).
        //   2. `-A` (forward_agent): forward IFF `$SSH_AUTH_SOCK` is
        //      set AND non-empty. If the var is missing or empty,
        //      log a warning and fall through with None — OpenSSH
        //      silently does the same.
        //   3. Neither `-A` nor `-a`: do not forward (None).
        let agent_sock_path: Option<std::path::PathBuf> = if cli.no_forward_agent {
            None
        } else if cli.forward_agent {
            match std::env::var("SSH_AUTH_SOCK") {
                Ok(sock_path) if !sock_path.is_empty() => {
                    info!("Agent forwarding: local socket {}", sock_path);
                    Some(std::path::PathBuf::from(sock_path))
                }
                Ok(_) | Err(_) => {
                    warn!(
                        "-A requested but $SSH_AUTH_SOCK is unset; \
                             agent forwarding disabled for this session"
                    );
                    None
                }
            }
        } else {
            None
        };

        let config = Arc::new(config);
        let mut handler = SshHandler::new(
            strict_check,
            host.clone(),
            port,
            (*user_known_hosts).clone(),
            agent_sock_path.clone(),
        );
        handler.remote_forwards = remote_forward_map.clone();

        let mut handle = if let Some(ref jump_spec) = cli.proxy_jump {
            // ProxyJump mode: connect through jump host
            let jump = parse_proxy_jump(jump_spec)
                .with_context(|| format!("Invalid proxy jump spec: {}", jump_spec))?;
            let jump_user = jump.user.as_deref().unwrap_or(user);
            let jump_addr = format!("{}:{}", jump.host, jump.port);
            info!(
                "ProxyJump: {}@{} -> {}:{}",
                jump_user, jump_addr, host, port
            );

            // Step 1: Connect to jump host TCP
            let jump_stream = tokio::net::TcpStream::connect(&jump_addr)
                .await
                .with_context(|| {
                    format!("ProxyJump: failed to connect to jump host {}", jump_addr)
                })?;

            // Step 2: SSH to jump host
            let jump_handler = SshHandler::new(
                strict_check,
                jump.host.clone(),
                jump.port,
                (*user_known_hosts).clone(),
                agent_sock_path.clone(),
            );
            let mut jump_handle = client::connect_stream(config.clone(), jump_stream, jump_handler)
                .await
                .context("ProxyJump: failed to establish SSH session to jump host")?;

            // Step 3: Authenticate to jump host
            authenticate(
                &mut jump_handle,
                jump_user,
                &cli,
                password.as_deref(),
                passphrase.as_deref(),
            )
            .await
            .with_context(|| {
                format!(
                    "ProxyJump: authentication to {}@{} failed",
                    jump_user, jump_addr
                )
            })?;

            // Step 4: Open direct-tcpip channel through jump to target
            info!("ProxyJump: opening tunnel to {}:{}", host, port);
            let tunnel_channel = jump_handle
                .channel_open_direct_tcpip(host.as_str(), port as u32, "127.0.0.1", 0)
                .await
                .context("ProxyJump: failed to open direct-tcpip channel through jump host")?;

            // Step 5: Convert channel to stream and establish SSH session to target
            let tunnel_stream = tunnel_channel.into_stream();
            let target_config = config.clone();
            let mut target_handler = SshHandler::new(
                strict_check,
                host.clone(),
                port,
                (*user_known_hosts).clone(),
                // The target session is a fresh SSH handshake
                // tunneled through sshd on the jump host. passhrs
                // owns the client side; the jump-host sshd relays
                // anything we send through the tunnel. For agent
                // forwarding we want THIS target session channel
                // (where passhrs opens the shell/command) to also
                // be -A-aware, so the jump handler and the target
                // handler both get the local agent path. Either
                // sshd in the chain can ask us to pump bytes; both
                // pump to the same local agent.
                agent_sock_path.clone(),
            );
            target_handler.remote_forwards = remote_forward_map.clone();

            let target_handle = if connect_timeout > 0 {
                tokio::time::timeout(
                    std::time::Duration::from_secs(connect_timeout),
                    client::connect_stream(target_config, tunnel_stream, target_handler),
                )
                .await
                .with_context(|| {
                    format!(
                        "ProxyJump: connection to target {}:{} timed out",
                        host, port
                    )
                })?
            } else {
                client::connect_stream(target_config, tunnel_stream, target_handler).await
            }
            .context("ProxyJump: failed to establish SSH session to target")?;

            target_handle
        } else {
            // Direct connection mode
            let connect_fut = client::connect(config, (host.as_str(), port), handler);
            let h = if connect_timeout > 0 {
                tokio::time::timeout(std::time::Duration::from_secs(connect_timeout), connect_fut)
                    .await
                    .with_context(|| format!("Connection timed out after {}s", connect_timeout))?
            } else {
                connect_fut.await
            }
            .context("Failed to connect to SSH server")?;
            h
        };

        authenticate(
            &mut handle,
            user,
            &cli,
            password.as_deref(),
            passphrase.as_deref(),
        )
        .await?;

        // --push / --pull / --rsync
        if !cli.push.is_empty() || !cli.pull.is_empty() || !cli.rsync.is_empty() {
            let channel = handle.channel_open_session().await?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .with_context(|| "failed to start SFTP subsystem")?;
            let stream = channel.into_stream();
            let sftp = SftpSession::new(stream)
                .await
                .context("failed to initialize SFTP session")?;
            for s in &cli.push {
                let (l, r) = parse_file_spec(s)?;
                let l = expand_path(&l);
                Box::pin(push_path(&sftp, &l, &r)).await?;
            }
            for s in &cli.pull {
                let (r, l) = parse_file_spec(s)?;
                let l = expand_path(&l);
                Box::pin(pull_path(&sftp, &r, &l)).await?;
            }
            for s in &cli.rsync {
                // --rsync format: /local/path:/remote/path  (always upload)
                // For download use: --pull /remote/path:/local/path
                let (left, right) = parse_file_spec(s)?;
                let left = expand_path(&left);
                let right = expand_path(&right);
                if !is_absolute_path(&right) || !is_absolute_path(&left) {
                    bail!("--rsync: both paths must be absolute. Format: --rsync /local/path:/remote/path");
                }
                info!("rsync upload: {} -> {}", left, right);
                Box::pin(rsync_upload(&sftp, &left, &right, &cli.rsync_opt)).await?;
            }
            if cli.command.is_empty() && !cli.no_command {
                return Ok(());
            }
        }

        // -H HTTP CONNECT forwarding
        spawn_forward_tasks(
            &http_connects,
            "HTTP CONNECT",
            &host,
            port,
            user,
            &password,
            &passphrase,
            &cli.identity_file,
            &user_known_hosts,
            strict_check,
            exit_on_fwd_failure,
            |c, s, e| Box::pin(http_connect_forward(c, s, e)),
        );

        // -D SOCKS forwarding
        spawn_forward_tasks(
            &dynamic_forwards,
            "SOCKS",
            &host,
            port,
            user,
            &password,
            &passphrase,
            &cli.identity_file,
            &user_known_hosts,
            strict_check,
            exit_on_fwd_failure,
            |c, s, e| Box::pin(socks_proxy_forward(c, s, e)),
        );

        // -R remote forwarding
        for fw in &remote_forwards {
            info!(
                "-R :{} -> {}:{}",
                fw.bind_port, fw.target_host, fw.target_port
            );
            match handle
                .tcpip_forward(&fw.bind_addr, fw.bind_port as u32)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    if exit_on_fwd_failure {
                        return Err(e.into());
                    }
                    warn!("-R :{} failed (ignored): {}", fw.bind_port, e);
                }
            }
        }

        // -L local forwarding
        spawn_forward_tasks(
            &local_forwards,
            "Local forward",
            &host,
            port,
            user,
            &password,
            &passphrase,
            &cli.identity_file,
            &user_known_hosts,
            strict_check,
            exit_on_fwd_failure,
            |c, s, e| Box::pin(local_port_forward(c, s, e)),
        );

        // Session channel for shell/command
        let pure_fwd = cli.no_command
            && (!remote_forwards.is_empty()
                || !dynamic_forwards.is_empty()
                || !http_connects.is_empty());
        if !pure_fwd {
            let channel = handle.channel_open_session().await?;
            // -A agent forwarding (Issue #23): tell sshd that we
            // accept `auth-agent@openssh.com` channel-opens on this
            // session. sshd then exposes a per-process
            // `$SSH_AUTH_SOCK` to the user's command and opens the
            // auth-agent channel back to passhrs the first time a
            // remote process contacts it. The actual byte pump lives
            // in `SshHandler::server_channel_open_agent_forward`
            // (src/ssh.rs) — this line only tells sshd it's OK to
            // open the channel.
            //
            // Mirroring OpenSSH semantics: skip the request when no
            // local agent is configured (None above), so we don't
            // burn a sshd feature for sessions where there's
            // nothing to forward.
            if cli.forward_agent && !cli.no_forward_agent && agent_sock_path.is_some() {
                info!("Agent forward: sending auth-agent-req@openssh.com");
                if let Err(e) = channel.agent_forward(true).await {
                    warn!("Agent forward: sshd rejected request: {}", e);
                }
            }
            let want_pty = cli.force_tty || !cli.no_command;
            if want_pty {
                let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
                channel
                    .request_pty(true, &term, 80, 24, 640, 480, &[])
                    .await?;
            }
            // Forward locale environment variables (like OpenSSH's default
            // `SendEnv LANG LC_*`) so remote locale-aware programs (vi/less/
            // nano/…) render UTF-8 correctly instead of garbling multibyte
            // (e.g. Chinese) text. want_reply=false: sshd may not AcceptEnv
            // these, in which case they are silently ignored (OpenSSH behavior).
            for (name, value) in std::env::vars() {
                if should_forward_locale_env(&name) {
                    let _ = channel.set_env(false, name, value).await;
                }
            }
            if !cli.command.is_empty() {
                let mut parts: Vec<String> = Vec::new();
                let mut exec_env_names: Vec<String> = Vec::new();
                for spec in &cli.exec_env {
                    if let Some(eq) = spec.find('=') {
                        let name = &spec[..eq];
                        let value = shell_escape::escape(spec[eq + 1..].into()).into_owned();
                        parts.push(match cli.shell.as_str() {
                            "cmd" => format!("set \"{}={}\"", name, value),
                            _ => format!("export {}={}", name, value),
                        });
                        exec_env_names.push(name.to_string());
                    } else if let Ok(v) = std::env::var(spec) {
                        let value = shell_escape::escape(v.into()).into_owned();
                        parts.push(match cli.shell.as_str() {
                            "cmd" => format!("set \"{}={}\"", spec, value),
                            _ => format!("export {}={}", spec, value),
                        });
                        exec_env_names.push(spec.clone());
                    }
                }
                let prefix = build_exec_env_prefix(&parts, &cli.shell);
                // For the cmd.exe shell, rewrite `$VAR` references in the
                // user-supplied command to `%VAR%` (cmd.exe has no concept
                // of `$VAR`). Only the names we just declared via
                // --exec-env are rewritten — leaving other `$FOO`
                // substrings untouched so we don't accidentally rewrite
                // arguments that happen to contain `$`. sh-mode skips the
                // rewrite entirely (its `$VAR` syntax is the existing path).
                //
                // After the `$`→`%` rewrite, we still hit cmd.exe's
                // `cmd /c "…"` parse-time-expansion bug: cmd.exe expands
                // `%VAR%` references in the entire command string BEFORE
                // any command runs, so `set "X=1" & echo %X%` always
                // echoes empty / literal `%X%` because X is undefined at
                // parse time. The second rewrite turns `%KNOWN_VAR%` into
                // `!KNOWN_VAR!`, and `build_exec_env_prefix` (cmd branch)
                // prepends `setlocal enabledelayedexpansion` so the
                // expansion fires at execution time — AFTER the `set` has
                // populated the variable. Built-in cmd vars (PATH,
                // COMPUTERNAME, …) are left as `%X%` because they're
                // always defined and the user expects immediate expansion.
                let cmd = cli.command.join(" ");
                let cmd = if cli.shell == "cmd" {
                    // sh-style `$VAR` references in the user command
                    // get converted to cmd-style `%VAR%` so users
                    // can write either form. The `%VAR%` references
                    // (whether from the user or from this rewrite)
                    // are then handled by the inner `cmd /c "…"`
                    // wrap below — the inner cmd's parse-time
                    // expansion sees `$VAR`/`%VAR%` and substitutes
                    // correctly because the preceding `set "VAR=v"`
                    // has already run in the outer cmd's env (the
                    // inner cmd inherits the parent's env).
                    rewrite_dollar_refs_for_cmd(&cmd, &exec_env_names)
                } else {
                    cmd
                };
                let full = format!("{}{}", prefix, cmd);
                // For cmd mode with exec_env to set, wrap the user
                // command in a NESTED `cmd /c "…"`. The outer cmd
                // (started by sshd) parses the whole string
                // upfront — its parse-time expansion of `%X%` would
                // see X as undefined and leave the reference as
                // literal (or empty), even though `set "X=1"`
                // appears earlier in the same string. The nested
                // `cmd /c "…"` gives the user command its OWN parse
                // context, AFTER the `set` has run, so the inner
                // cmd's parse of `%X%` sees X already populated.
                // Concretely: passhrs exec payload is
                //     set "X=1" & cmd /c "echo %X%"
                // sshd starts cmd.exe /c "<above>"; the outer cmd
                // parses, sees `cmd /c "echo %X%"` as a single
                // sub-command, and dispatches to the inner cmd with
                // the literal /c arg `echo %X%` (X undefined at
                // outer's parse time, so the outer leaves it as
                // literal `%X%`). The inner cmd then parses
                // `echo %X%` in its own context, where X is
                // inherited as set, and expands `%X%` correctly.
                // Any `"` in the user command is escaped as `\"` so
                // the outer cmd treats the inner string as a single
                // quoted arg of its `cmd` invocation.
                let full = if cli.shell == "cmd" && !parts.is_empty() {
                    let user = cmd.clone();
                    let user_escaped = user.replace('"', r#"\""#);
                    let set_block = build_exec_env_prefix(&parts, &cli.shell);
                    // set_block already ends with " & " for cmd
                    // mode. Append the wrapped user command.
                    format!(r#"{}cmd /c "{}""#, set_block, user_escaped)
                } else {
                    full
                };
                info!("Exec: {}", full);
                channel.exec(true, full.as_bytes()).await?;
                let code = run_session(channel, cli.redirect_stdin).await?;
                std::process::exit(code);
            } else if !cli.no_command {
                channel.request_shell(true).await?;
                info!("Starting shell");
                let code = run_session(channel, cli.redirect_stdin).await?;
                std::process::exit(code);
            } else {
                info!("-N mode, waiting...");
                tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
                Ok(())
            }
        } else if !local_forwards.is_empty() || !remote_forwards.is_empty() {
            info!("Forward mode active, waiting...");
            tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
            Ok(())
        } else {
            Ok(())
        }
    } else {
        bail!("no destination specified");
    }
}
// Local port forwarding (-L, separate SSH connection)
// ======================================================================

#[cfg(test)]
mod exec_env_shell_tests {
    //! Unit tests for the --shell sh/cmd prefix generation and the
    //! `$VAR` → `%VAR%` rewrite for cmd.exe. Pins the syntax that
    //! `passhrs --exec-env` emits on each remote shell so a future
    //! refactor doesn't accidentally break the Windows OpenSSH
    //! cmd.exe integration.

    use super::{
        build_exec_env_prefix, is_ident_cont, is_ident_start, rewrite_dollar_refs_for_cmd,
    };

    #[test]
    fn dollar_rewrite_substitutes_known_names() {
        let out = rewrite_dollar_refs_for_cmd(
            "echo $FOO and $BAR_BAZ then $UNRELATED",
            &["FOO".into(), "BAR_BAZ".into()],
        );
        assert_eq!(out, "echo %FOO% and %BAR_BAZ% then $UNRELATED");
    }

    #[test]
    fn dollar_rewrite_passthrough_when_no_env_names() {
        // No --exec-env was passed; nothing should be rewritten (avoids
        // accidentally rewriting `$HOME` etc. when --exec-env is unused).
        let out = rewrite_dollar_refs_for_cmd("echo $HOME stays as-is", &[]);
        assert_eq!(out, "echo $HOME stays as-is");
    }

    #[test]
    fn dollar_rewrite_handles_alphanumeric_and_underscore() {
        // `$FOO123` and `$_UNDERSCORE` are valid identifiers; the
        // rewrite must consume the whole token, not stop at the first
        // non-alpha.
        let out = rewrite_dollar_refs_for_cmd(
            "x=$FOO123 y=$_UNDERSCORE",
            &["FOO123".into(), "_UNDERSCORE".into()],
        );
        assert_eq!(out, "x=%FOO123% y=%_UNDERSCORE%");
    }

    #[test]
    fn dollar_rewrite_preserves_unknown_dollar_vars() {
        // `$1` (positional) and `${X}` (brace form) are not bare
        // `$IDENT`; pass through unchanged. `$X` with X not in
        // env_names also passes through (we only rewrite what we
        // know we set).
        let out = rewrite_dollar_refs_for_cmd("$1 ${X} $UNKNOWN", &["KNOWN".into()]);
        assert_eq!(out, "$1 ${X} $UNKNOWN");
    }

    #[test]
    fn dollar_rewrite_does_not_match_dollar_at_eof() {
        // Trailing `$` (no following identifier) is not a reference.
        let out = rewrite_dollar_refs_for_cmd("price: 5$", &["X".into()]);
        assert_eq!(out, "price: 5$");
    }

    #[test]
    fn ident_start_accepts_alpha_and_underscore_only() {
        assert!(is_ident_start(b'a'));
        assert!(is_ident_start(b'Z'));
        assert!(is_ident_start(b'_'));
        assert!(!is_ident_start(b'1'));
        assert!(!is_ident_start(b'$'));
    }

    #[test]
    fn ident_cont_accepts_alphanumeric_and_underscore() {
        assert!(is_ident_cont(b'a'));
        assert!(is_ident_cont(b'Z'));
        assert!(is_ident_cont(b'0'));
        assert!(is_ident_cont(b'9'));
        assert!(is_ident_cont(b'_'));
        assert!(!is_ident_cont(b'$'));
        assert!(!is_ident_cont(b' '));
        assert!(!is_ident_cont(b';'));
    }

    #[test]
    fn dollar_rewrite_handles_adjacent_refs() {
        // Two refs next to each other with no separator.
        let out = rewrite_dollar_refs_for_cmd("$A$B", &["A".into(), "B".into()]);
        assert_eq!(out, "%A%%B%");
    }

    // ---- build_exec_env_prefix: separator + nested cmd /c wrap (Issue #5) ----
    //
    // Two related bugs were caught on windows-2022:
    //   1. `;` is not a separator in cmd.exe — the original `;` join
    //      parsed the whole prelude as one command and the echo
    //      never ran. Fix: use `&` (cmd.exe's unconditional-sequence
    //      operator).
    //   2. Even with `&`, cmd.exe `cmd /c "…"` expands `%X%` at
    //      PARSE time of the whole string, BEFORE any command runs.
    //      So `set "X=1" & echo %X%` echoes literal `%X%` (X
    //      undefined at parse time). Fix: the call site wraps the
    //      user command in a nested `cmd /c "…"` so the inner
    //      cmd's parse-time expansion of `%X%` sees X as inherited
    //      and populated (the preceding `set "X=v"` has already run
    //      in the outer's env).

    #[test]
    fn prefix_sh_uses_semicolon_separator() {
        let parts = vec![
            r#"export FOO=bar"#.to_string(),
            r#"export BAZ=qux"#.to_string(),
        ];
        let p = build_exec_env_prefix(&parts, "sh");
        assert_eq!(p, r#"export FOO=bar; export BAZ=qux; "#);
    }

    #[test]
    fn prefix_cmd_uses_ampersand_separator() {
        // The nested `cmd /c "…"` wrap (assembled in main, not
        // here) is what re-parses the user command in a fresh
        // cmd.exe context, AFTER the `set "X=v"` lines have run
        // in the outer's env. The prefix's job is just to emit
        // the set lines joined with cmd.exe's `&` sequence
        // operator.
        let parts = vec![r#"set "PHR_TEST_VAR=hello_from_env""#.to_string()];
        let p = build_exec_env_prefix(&parts, "cmd");
        assert_eq!(p, r#"set "PHR_TEST_VAR=hello_from_env" & "#);
    }

    #[test]
    fn prefix_cmd_multi_part_ampersand_join() {
        let parts = vec![r#"set "A=1""#.to_string(), r#"set "B=2""#.to_string()];
        let p = build_exec_env_prefix(&parts, "cmd");
        assert_eq!(p, r#"set "A=1" & set "B=2" & "#);
    }

    #[test]
    fn prefix_empty_parts_returns_empty_string() {
        // No --exec-env supplied — no prefix, no leading separator,
        // and no `cmd /c "…"` wrap (nothing to re-parse in a fresh
        // cmd context).
        let p = build_exec_env_prefix(&[], "sh");
        assert_eq!(p, "");
        let p = build_exec_env_prefix(&[], "cmd");
        assert_eq!(p, "");
    }

    // ---- end of exec_env_shell_tests ----
}

#[cfg(test)]
mod format_user_error_tests {
    //! Pin the user-facing error classifier (Issue #32). A regression
    //! in `format_user_error` (e.g. dropping a keyword match, or
    //! changing the prefix from "error: " to "Error: ") would silently
    //! degrade the user experience; these tests catch that.
    use super::format_user_error;
    use anyhow::anyhow;

    #[test]
    fn classifies_authentication_failure() {
        let e = anyhow!("Authentication failed");
        let s = format_user_error(&e);
        assert!(
            s.starts_with("passhrs: authentication failed"),
            "expected 'error: authentication failed' prefix, got: {s}"
        );
    }

    #[test]
    fn classifies_permission_denied_as_auth() {
        // The OpenSSH-style "Permission denied (publickey,password)"
        // message comes back through the russh chain when all auth
        // methods are exhausted.
        let e = anyhow!("Permission denied (publickey,password)");
        let s = format_user_error(&e);
        assert!(
            s.starts_with("passhrs: authentication failed"),
            "expected auth classification, got: {s}"
        );
    }

    #[test]
    fn classifies_connection_refused() {
        let e = anyhow!("Failed to connect to SSH server").context("Connection refused");
        let s = format_user_error(&e);
        assert!(
            s.starts_with("passhrs: connection failed"),
            "expected connection classification, got: {s}"
        );
    }

    #[test]
    fn classifies_connection_timed_out() {
        let e = anyhow!("Connection timed out after 3s");
        let s = format_user_error(&e);
        assert!(
            s.starts_with("passhrs: connection failed"),
            "expected connection classification, got: {s}"
        );
    }

    #[test]
    fn classifies_host_key_mismatch() {
        let e = anyhow!("Host key verification failed");
        let s = format_user_error(&e);
        assert!(
            s.starts_with("passhrs: host key verification failed"),
            "expected host key classification, got: {s}"
        );
    }

    #[test]
    fn classifies_proxyjump() {
        let e = anyhow!("ProxyJump: failed to establish SSH session to jump host");
        let s = format_user_error(&e);
        assert!(
            s.starts_with("passhrs: ProxyJump failed"),
            "expected ProxyJump classification, got: {s}"
        );
    }

    #[test]
    fn classifies_forwarding_or_sftp_failure() {
        let e = anyhow!("SFTP subsystem initialization failed");
        let s = format_user_error(&e);
        assert!(
            s.starts_with("passhrs: forwarding/sftp failed"),
            "expected forwarding classification, got: {s}"
        );
    }

    #[test]
    fn unknown_error_falls_back_to_summary_with_hint() {
        let e = anyhow!("something completely unrelated to ssh");
        let s = format_user_error(&e);
        assert!(
            s.starts_with("passhrs: "),
            "unknown errors must still get the 'error: ' prefix, got: {s}"
        );
        assert!(
            s.contains("rerun with -vv"),
            "unknown errors must hint at -vv, got: {s}"
        );
    }
}
