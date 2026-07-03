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
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.help {
        print_help();
        return Ok(());
    }

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

    let log_level = if cli.quiet {
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
        bail!("no destination specified");
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
        let config = Arc::new(config);
        let mut handler = SshHandler::new(
            strict_check,
            host.clone(),
            port,
            (*user_known_hosts).clone(),
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
                if !right.starts_with('/') || !left.starts_with('/') {
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
                for spec in &cli.exec_env {
                    if let Some(eq) = spec.find('=') {
                        parts.push(format!(
                            "export {}={}",
                            &spec[..eq],
                            shell_escape::escape(spec[eq + 1..].into())
                        ));
                    } else if let Ok(v) = std::env::var(spec) {
                        parts.push(format!(
                            "export {}={}",
                            spec,
                            shell_escape::escape(v.into())
                        ));
                    }
                }
                let prefix = if parts.is_empty() {
                    String::new()
                } else {
                    format!("{}; ", parts.join("; "))
                };
                let cmd = cli.command.join(" ");
                let full = format!("{}{}", prefix, cmd);
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
