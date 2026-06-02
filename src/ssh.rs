use std::collections::HashMap;
use std::sync::Arc;


use anyhow::{bail, Result};
use log::*;
use russh::client::{Handle, Handler, Msg};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg};


use crate::cli::Cli;
use crate::types::ForwardSpec;
pub(crate) struct SshHandler {
    strict_check: bool,
    host: String,
    port: u16,
    known_hosts_path: Option<String>,
    pub(crate) remote_forwards: HashMap<u16, ForwardSpec>,
}

impl SshHandler {
    pub(crate) fn new(
        strict_check: bool,
        host: String,
        port: u16,
        known_hosts_path: Option<String>,
    ) -> Self {
        Self {
            strict_check,
            host,
            port,
            known_hosts_path,
            remote_forwards: HashMap::new(),
        }
    }
}

impl Handler for SshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        if let Some(ref path) = self.known_hosts_path {
            if path != "/dev/null" && path != "nul" {
                match russh::keys::known_hosts::check_known_hosts_path(
                    &self.host,
                    self.port,
                    server_public_key,
                    path,
                ) {
                    Ok(true) => return Ok(true),
                    Ok(false) => {
                        if self.strict_check {
                            warn!("Host key mismatch for {} in {}", self.host, path);
                            return Ok(false);
                        }
                        info!("New host key accepted for {}", self.host);
                        return Ok(true);
                    }
                    Err(e) => {
                        warn!("Known_hosts check failed: {}", e);
                        if self.strict_check {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        if self.strict_check {
            warn!("Host key verification failed for {}", self.host);
            Ok(false)
        } else {
            Ok(true)
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        let port = connected_port as u16;
        eprintln!(
            "DEBUG server_channel_open_forwarded_tcpip called: port={}",
            port
        );
        if let Some(spec) = self.remote_forwards.get(&port) {
            info!(
                "Remote forward: {}:{} -> {}:{} (via sshd)",
                originator_address, originator_port, spec.target_host, spec.target_port
            );
            let addr = format!("{}:{}", spec.target_host, spec.target_port);
            eprintln!(
                "DEBUG -R connecting to target: '{}' (from spec target_host='{}' target_port={})",
                addr, spec.target_host, spec.target_port
            );
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(target_stream) => {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let (mut trx, mut ttx) = tokio::io::split(target_stream);
                    let (mut crx, ctx) = channel.split();
                    let c2t = tokio::spawn(async move {
                        loop {
                            match crx.wait().await {
                                Some(ChannelMsg::Data { ref data }) => {
                                    eprintln!(
                                        "DEBUG c2t forwarding {} bytes to target",
                                        data.len()
                                    );
                                    if ttx.write_all(data).await.is_err() {
                                        eprintln!("DEBUG c2t write_all error");
                                        break;
                                    }
                                    let _ = ttx.flush().await;
                                }
                                Some(ChannelMsg::Eof) => {
                                    eprintln!("DEBUG c2t EOF");
                                    break;
                                }
                                Some(ChannelMsg::Close) => {
                                    eprintln!("DEBUG c2t Close");
                                    break;
                                }
                                None => {
                                    eprintln!("DEBUG c2t None");
                                    break;
                                }
                                Some(other) => {
                                    eprintln!("DEBUG c2t other msg: {:?}", other);
                                }
                            }
                        }
                    });
                    let t2c = tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            match trx.read(&mut buf).await {
                                Ok(0) => {
                                    eprintln!("DEBUG t2c EOF from target");
                                    let _ = ctx.eof().await;
                                    break;
                                }
                                Ok(n) => {
                                    eprintln!("DEBUG t2c forwarding {} bytes from target", n);
                                    if ctx.data(&buf[..n]).await.is_err() {
                                        eprintln!("DEBUG t2c ctx.data error");
                                        break;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("DEBUG t2c read error: {}", e);
                                    break;
                                }
                            }
                        }
                    });
                    let _ = tokio::join!(c2t, t2c);
                }
                Err(e) => {
                    eprintln!("DEBUG -R connect FAILED: {} - {}", addr, e);
                    warn!(
                        "Remote forward: failed to connect to target {}: {}",
                        addr, e
                    );
                }
            }
        } else {
            warn!("Remote forward: no mapping for port {}", port);
        }
        Ok(())
    }
}

// ======================================================================
// Parse helpers
// ======================================================================

pub(crate) async fn authenticate_fwd(
    handle: &mut Handle<SshHandler>,
    user: &str,
    password: Option<&str>,
    passphrase: Option<&str>,
    identity_file: Option<&std::path::Path>,
) -> Result<()> {
    let u = user.to_string();
    if let Some(k) = identity_file {
        if let Ok(pk) = load_secret_key(k, passphrase) {
            let key = PrivateKeyWithHashAlg::new(Arc::new(pk), None);
            if handle
                .authenticate_publickey(u.clone(), key)
                .await?
                .success()
            {
                return Ok(());
            }
        }
    }
    if handle.authenticate_none(&u).await?.success() {
        return Ok(());
    }
    if let Some(pw) = password {
        if handle.authenticate_password(u.clone(), pw).await?.success() {
            return Ok(());
        }
    }
    bail!("Auth (fwd) failed")
}

pub(crate) async fn authenticate(
    handle: &mut Handle<SshHandler>,
    user: &str,
    cli: &Cli,
    password: Option<&str>,
    passphrase: Option<&str>,
) -> Result<()> {
    let u = user.to_string();
    if let Some(ref k) = cli.identity_file {
        info!("Loading key: {:?}", k);
        match load_secret_key(k, passphrase) {
            Ok(pk) => {
                let key = PrivateKeyWithHashAlg::new(Arc::new(pk), None);
                if handle
                    .authenticate_publickey(u.clone(), key)
                    .await?
                    .success()
                {
                    info!("Public key auth succeeded");
                    return Ok(());
                }
            }
            Err(e) => {
                warn!("Failed to load key {:?}: {}", k, e);
            }
        }
    }
    if let Some(pw) = password {
        if handle.authenticate_password(u.clone(), pw).await?.success() {
            info!("Password auth succeeded");
            return Ok(());
        }
    }
    bail!("Authentication failed");
}

pub(crate) struct RawModeGuard;

impl RawModeGuard {
    pub(crate) fn new() -> Option<Self> {
        use crossterm::tty::IsTty;
        if !std::io::stdin().is_tty() {
            return None;
        }
        crossterm::terminal::enable_raw_mode().ok()?;
        Some(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

pub(crate) async fn run_session(channel: Channel<Msg>, redirect_stdin: bool) -> Result<i32> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    // Put local terminal in raw mode when running an interactive shell
    let _raw = if !redirect_stdin && atty::is(atty::Stream::Stdin) {
        RawModeGuard::new()
    } else {
        None
    };

    let (mut rx, tx) = channel.split();
    let (exit_tx, exit_rx) = oneshot::channel::<i32>();
    let reader = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        let mut code = 0;
        loop {
            match rx.wait().await {
                Some(ChannelMsg::Data { ref data }) => {
                    let _ = stdout.write_all(data).await;
                    let _ = stdout.flush().await;
                }
                Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                    let _ = stderr.write_all(data).await;
                    let _ = stderr.flush().await;
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    code = exit_status as i32;
                    break;
                }
                _ => {}
            }
        }
        let _ = exit_tx.send(code);
    });
    if redirect_stdin {
        tokio::spawn(async move {
            let _tx = tx;
            tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
        });
    } else {
        tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 65536];
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) => {
                        let _ = tx.eof().await;
                        break;
                    }
                    Ok(n) => {
                        if tx.data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
    let code = tokio::select! { c = exit_rx => c.unwrap_or(0), _ = reader => 0 };
    info!("Session exit code {}", code);
    Ok(code)
}
