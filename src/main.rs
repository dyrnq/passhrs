use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use copia::{Sync, SyncBuilder};
use log::*;
use russh::client::{self, Handle, Handler, Msg};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
// ======================================================================
// CLI
// ======================================================================

#[derive(Parser)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    trailing_var_arg = true,
    disable_help_flag = true
)]
struct Cli {
    #[arg(short = 'p', long = "port", default_value_t = 22)]
    ssh_port: u16,
    #[arg(short = 'l', long = "user")]
    user: Option<String>,
    #[arg(short = 'i', long = "key")]
    identity_file: Option<PathBuf>,
    #[arg(short = 'J', long = "proxy-jump")]
    proxy_jump: Option<String>,
    #[arg(short = '4', long = "ipv4")]
    ipv4: bool,
    #[arg(short = '6', long = "ipv6")]
    ipv6: bool,
    #[arg(short = 'A', long = "forward-agent")]
    forward_agent: bool,
    #[arg(short = 'a', long = "no-forward-agent")]
    no_forward_agent: bool,
    #[arg(short = 'C', long = "compress")]
    compress: bool,
    #[arg(short = 'D', long = "dynamic-forward", num_args = 1)]
    dynamic_forward: Vec<String>,
    #[arg(short = 'H', long = "http-proxy-connect", num_args = 1)]
    http_proxy_connect: Vec<String>,
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
    #[arg(short = 'E', long = "log-file")]
    log_file: Option<String>,
    #[arg(short = 'o', long = "option", num_args = 1)]
    ssh_option: Vec<String>,
    #[arg(short = 'N', long = "no-command")]
    no_command: bool,
    #[arg(short = 't', long = "tty")]
    force_tty: bool,
    #[arg(short = 'L', long = "local-forward", num_args = 1)]
    local_forward: Vec<String>,
    #[arg(short = 'R', long = "remote-forward", num_args = 1)]
    remote_forward: Vec<String>,
    #[arg(long = "identity-passphrase")]
    passphrase: Option<String>,
    #[arg(long = "password")]
    password: Option<String>,
    #[arg(short = 'S', long = "control-path")]
    control_path: Option<String>,
    #[arg(long = "connect-timeout", default_value_t = 0)]
    connect_timeout: u64,
    #[arg(long = "timeout", default_value_t = 0)]
    inactivity_timeout: u64,
    #[arg(short = 'n', long = "redirect-stdin")]
    redirect_stdin: bool,
    #[arg(short = 'f', long = "fork")]
    fork: bool,
    #[arg(long = "exec-env", num_args = 1)]
    exec_env: Vec<String>,
    #[arg(long = "help")]
    help: bool,
    destination: Option<String>,
    command: Vec<String>,
    #[arg(long = "push", num_args = 1)]
    push: Vec<String>,
    #[arg(long = "pull", num_args = 1)]
    pull: Vec<String>,
    #[arg(long = "rsync", num_args = 1)]
    rsync: Vec<String>,
    #[arg(long = "rsync-opt", num_args = 1)]
    rsync_opt: Vec<String>,
}

// ======================================================================
// Forward spec & SSH Handler
// ======================================================================

#[derive(Clone)]
struct ForwardSpec {
    bind_addr: String,
    bind_port: u16,
    target_host: String,
    target_port: u16,
}

#[derive(Clone)]
struct DynamicForwardSpec {
    bind_addr: String,
    bind_port: u16,
}

#[derive(Clone)]
struct SshHandler {
    strict_check: bool,
    host: String,
    port: u16,
    known_hosts_path: Option<String>,
    remote_forwards: HashMap<u16, ForwardSpec>,
}

impl SshHandler {
    fn new(strict_check: bool, host: String, port: u16, known_hosts_path: Option<String>) -> Self {
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

pub fn parse_destination(dest: &str) -> Result<(String, Option<String>, u16)> {
    let (user, rest) = if let Some(at_idx) = dest.rfind('@') {
        (Some(dest[..at_idx].to_string()), &dest[at_idx + 1..])
    } else {
        (None, dest)
    };
    let (host, port) = if let Some(colon_idx) = rest.rfind(':') {
        let p: u16 = rest[colon_idx + 1..]
            .parse()
            .with_context(|| format!("invalid port in destination: {}", dest))?;
        (rest[..colon_idx].to_string(), Some(p))
    } else {
        (rest.to_string(), None)
    };
    Ok((host, user, port.unwrap_or(22)))
}

pub fn parse_ssh_options(options: &[String]) -> HashMap<String, String> {
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

#[derive(Debug, Clone)]
pub struct ProxyJumpSpec {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
}

pub fn parse_proxy_jump(spec: &str) -> Result<ProxyJumpSpec> {
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
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() == 3 {
        Ok(ForwardSpec {
            bind_addr: "127.0.0.1".into(),
            bind_port: parts[0].parse().context("invalid bind port")?,
            target_host: parts[1].into(),
            target_port: parts[2].parse().context("invalid target port")?,
        })
    } else if parts.len() == 4 {
        Ok(ForwardSpec {
            bind_addr: parts[0].into(),
            bind_port: parts[1].parse().context("invalid bind port")?,
            target_host: parts[2].into(),
            target_port: parts[3].parse().context("invalid target port")?,
        })
    } else {
        bail!(
            "invalid forward spec: {}. Use port:host:port or bind:port:host:port",
            spec
        )
    }
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

async fn push_path(sftp: &SftpSession, local: &str, remote: &str) -> Result<()> {
    let metadata = tokio::fs::metadata(local)
        .await
        .with_context(|| format!("cannot stat local path: {}", local))?;
    if metadata.is_dir() {
        info!("SFTP push dir: {} -> {}", local, remote);
        let _ = sftp.create_dir(remote).await;
        let mut dir = tokio::fs::read_dir(local)
            .await
            .with_context(|| format!("cannot read local directory: {}", local))?;
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            Box::pin(push_path(
                sftp,
                &format!("{}/{}", local.trim_end_matches('/'), name),
                &format!("{}/{}", remote.trim_end_matches('/'), name),
            ))
            .await?;
        }
    } else {
        info!("SFTP push: {} -> {}", local, remote);
        let content = tokio::fs::read(local)
            .await
            .with_context(|| format!("cannot read local file: {}", local))?;
        let content_len = content.len();
        use tokio::io::AsyncWriteExt;
        let mut file = sftp
            .open_with_flags(
                remote,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .with_context(|| format!("failed to open remote file: {}", remote))?;
        file.write_all(&content)
            .await
            .with_context(|| format!("failed to write remote file: {}", remote))?;
        file.flush().await.ok();
        info!(
            "SFTP push complete: {} -> {} ({} bytes)",
            local, remote, content_len
        );
    }
    Ok(())
}

async fn pull_path(sftp: &SftpSession, remote: &str, local: &str) -> Result<()> {
    match sftp.metadata(remote).await {
        Ok(meta) => {
            if meta.is_dir() {
                info!("SFTP pull dir: {} -> {}", remote, local);
                tokio::fs::create_dir_all(local)
                    .await
                    .with_context(|| format!("cannot create local directory: {}", local))?;
                let entries = sftp
                    .read_dir(remote)
                    .await
                    .with_context(|| format!("cannot read remote directory: {}", remote))?;
                for entry in entries {
                    let name = entry.file_name();
                    Box::pin(pull_path(
                        sftp,
                        &format!("{}/{}", remote.trim_end_matches('/'), name),
                        &format!("{}/{}", local.trim_end_matches('/'), name),
                    ))
                    .await?;
                }
            } else {
                info!("SFTP pull: {} -> {}", remote, local);
                let data = sftp
                    .read(remote)
                    .await
                    .with_context(|| format!("failed to read remote file: {}", remote))?;
                if let Some(parent) = std::path::Path::new(local).parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .with_context(|| format!("cannot create parent directory: {:?}", parent))?;
                }
                tokio::fs::write(local, &data)
                    .await
                    .with_context(|| format!("failed to write local file: {}", local))?;
                info!(
                    "SFTP pull complete: {} -> {} ({} bytes)",
                    remote,
                    local,
                    data.len()
                );
            }
        }
        Err(e) => bail!("cannot access remote path {}: {}", remote, e),
    }
    Ok(())
}

fn expand_path(path: &str) -> String {
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

pub fn parse_file_spec(spec: &str) -> Result<(String, String)> {
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

pub fn socks5_response(bind_addr: &str, bind_port: u16, status: u8) -> Vec<u8> {
    let mut resp = vec![5, status, 0, 1];
    for octet in bind_addr.split('.') {
        resp.push(octet.parse::<u8>().unwrap_or(0));
    }
    resp.extend_from_slice(&bind_port.to_be_bytes());
    resp
}

async fn socks5_handshake(
    srx: &mut (impl tokio::io::AsyncRead + Unpin),
    stx: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(String, u16)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 2];
    srx.read_exact(&mut buf).await?;
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    srx.read_exact(&mut methods).await?;
    stx.write_all(&[5, 0]).await?;
    let mut buf = [0u8; 4];
    srx.read_exact(&mut buf).await?;
    match buf[3] {
        1 => {
            let mut ip = [0u8; 4];
            srx.read_exact(&mut ip).await?;
            let mut p = [0u8; 2];
            srx.read_exact(&mut p).await?;
            Ok((
                format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                u16::from_be_bytes(p),
            ))
        }
        3 => {
            let mut len_buf = [0u8; 1];
            srx.read_exact(&mut len_buf).await?;
            let mut domain = vec![0u8; len_buf[0] as usize];
            srx.read_exact(&mut domain).await?;
            let mut p = [0u8; 2];
            srx.read_exact(&mut p).await?;
            Ok((
                String::from_utf8_lossy(&domain).to_string(),
                u16::from_be_bytes(p),
            ))
        }
        _ => bail!("unsupported SOCKS5 address type: {}", buf[3]),
    }
}

async fn socks_proxy_forward(
    handle: Handle<SshHandler>,
    spec: DynamicForwardSpec,
    exit_on_failure: bool,
) -> Result<()> {
    let ba: SocketAddr = format!("{}:{}", spec.bind_addr, spec.bind_port).parse()?;
    let listener = match TcpListener::bind(ba).await {
        Ok(l) => l,
        Err(e) => {
            if exit_on_failure {
                return Err(e.into());
            }
            warn!(
                "-D bind {}:{} failed (ignored): {}",
                spec.bind_addr, spec.bind_port, e
            );
            return Ok(());
        }
    };
    info!("SOCKS proxy on {}:{}", spec.bind_addr, spec.bind_port);
    loop {
        let (stream, peer) = listener.accept().await?;
        info!("SOCKS5 from {}", peer);
        if let Err(e) = handle_socks_connection(&handle, stream).await {
            debug!("SOCKS {} error: {}", peer, e);
        }
    }
}

async fn handle_socks_connection(handle: &Handle<SshHandler>, stream: TcpStream) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut srx, mut stx) = tokio::io::split(stream);
    let (host, port) = socks5_handshake(&mut srx, &mut stx).await?;
    info!("SOCKS5 CONNECT {}:{}", host, port);
    match handle
        .channel_open_direct_tcpip(host.as_str(), port as u32, "127.0.0.1", 0u32)
        .await
    {
        Ok(channel) => {
            let resp = socks5_response("127.0.0.1", 0, 0);
            stx.write_all(&resp).await?;
            let (mut crx, ctx) = channel.split();
            let c2s = tokio::spawn(async move {
                loop {
                    match crx.wait().await {
                        Some(ChannelMsg::Data { ref data }) => {
                            if stx.write_all(data).await.is_err() {
                                break;
                            }
                            let _ = stx.flush().await;
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    }
                }
            });
            let s2c = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match srx.read(&mut buf).await {
                        Ok(0) => {
                            let _ = ctx.eof().await;
                            break;
                        }
                        Ok(n) => {
                            if ctx.data(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            let _ = tokio::join!(c2s, s2c);
            Ok(())
        }
        Err(e) => {
            let _ = stx.write_all(&socks5_response("0.0.0.0", 0, 1)).await;
            Err(anyhow::anyhow!("SOCKS channel open failed: {}", e))
        }
    }
}
// ======================================================================
// HTTP CONNECT proxy (-H)
// ======================================================================

async fn http_connect_forward(
    handle: Handle<SshHandler>,
    spec: DynamicForwardSpec,
    exit_on_failure: bool,
) -> Result<()> {
    let ba: SocketAddr = format!("{}:{}", spec.bind_addr, spec.bind_port).parse()?;
    let listener = match TcpListener::bind(ba).await {
        Ok(l) => l,
        Err(e) => {
            if exit_on_failure {
                return Err(e.into());
            }
            warn!(
                "-H bind {}:{} failed (ignored): {}",
                spec.bind_addr, spec.bind_port, e
            );
            return Ok(());
        }
    };
    info!(
        "HTTP CONNECT proxy on {}:{}",
        spec.bind_addr, spec.bind_port
    );
    loop {
        let (stream, peer) = listener.accept().await?;
        info!("HTTP CONNECT connection from {}", peer);
        // Use borrowed handle - http_connect_handle_one doesn't own the handle
        http_connect_handle_one(&handle, stream).await;
    }
}

async fn http_connect_handle_one(handle: &Handle<SshHandler>, mut stream: TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 4096];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => {
            let _ = stream.shutdown().await;
            return;
        }
    };
    let request = String::from_utf8_lossy(&buf[..n]);
    let parts: Vec<&str> = request.splitn(3, ' ').collect();
    if parts.len() < 2 || parts[0].to_uppercase() != "CONNECT" {
        warn!(
            "-H invalid HTTP CONNECT request: {}",
            request.lines().next().unwrap_or("?")
        );
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request

",
            )
            .await;
        return;
    }
    let host_port = parts[1];
    let hp: Vec<&str> = host_port.rsplitn(2, ':').collect();
    if hp.len() != 2 {
        warn!("-H invalid host:port: {}", host_port);
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request

",
            )
            .await;
        return;
    }
    let host = hp[1];
    let port: u16 = match hp[0].parse() {
        Ok(p) => p,
        Err(_) => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request

",
                )
                .await;
            return;
        }
    };
    match handle
        .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0u32)
        .await
    {
        Ok(channel) => {
            info!("-H CONNECT {}:{} via SSH", host, port);
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 Connection Established

",
                )
                .await;
            let (mut crx, ctx) = channel.split();
            let (mut srx, mut stx) = tokio::io::split(stream);
            let c2s = tokio::spawn(async move {
                loop {
                    match crx.wait().await {
                        Some(ChannelMsg::Data { ref data }) => {
                            if stx.write_all(data).await.is_err() {
                                break;
                            }
                            let _ = stx.flush().await;
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    }
                }
            });
            let s2c = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match srx.read(&mut buf).await {
                        Ok(0) => {
                            let _ = ctx.eof().await;
                            break;
                        }
                        Ok(n) => {
                            if ctx.data(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            let _ = tokio::join!(c2s, s2c);
        }
        Err(e) => {
            warn!("-H channel_open {}:{} failed: {}", host, port, e);
            let _ = stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway

",
                )
                .await;
        }
    }
}

// =====================================================
// Main
// ======================================================================

// ======================================================================
// --rsync: smart sync using mtime/size comparison + copia delta
// ======================================================================

#[derive(Clone)]
struct RemoteFileInfo {
    size: u64,
    mtime: u64,
}

async fn list_remote_files(
    sftp: &SftpSession,
    path: &str,
) -> Result<HashMap<String, RemoteFileInfo>> {
    let mut files = HashMap::new();
    let entries = sftp
        .read_dir(path)
        .await
        .with_context(|| format!("cannot read remote directory: {}", path))?;
    for entry in entries {
        let name = entry.file_name();
        let full_path = format!("{}/{}", path.trim_end_matches('/'), name);
        // Stat each entry to determine type and metadata
        let stat = sftp
            .metadata(&full_path)
            .await
            .with_context(|| format!("cannot stat remote: {}", full_path))?;
        if stat.is_dir() {
            let sub = Box::pin(list_remote_files(sftp, &full_path)).await?;
            files.extend(sub);
        } else {
            let size = stat.size.unwrap_or(0);
            let mtime = stat.mtime.unwrap_or(0) as u64;
            files.insert(full_path, RemoteFileInfo { size, mtime });
        }
    }
    Ok(files)
}

async fn list_local_files(path: &str) -> Result<HashMap<String, RemoteFileInfo>> {
    let mut files = HashMap::new();
    let mut stack = vec![path.to_string()];
    while let Some(dir) = stack.pop() {
        let mut rd = tokio::fs::read_dir(&dir)
            .await
            .with_context(|| format!("cannot read directory: {}", dir))?;
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let full = format!("{}/{}", dir.trim_end_matches('/'), name);
            if entry.file_type().await?.is_dir() {
                stack.push(full);
            } else {
                let meta = entry.metadata().await?;
                files.insert(
                    full,
                    RemoteFileInfo {
                        size: meta.len(),
                        mtime: meta
                            .modified()?
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    },
                );
            }
        }
    }
    Ok(files)
}

async fn rsync_upload(
    sftp: &SftpSession,
    local_root: &str,
    remote_root: &str,
    opts: &[String],
) -> Result<()> {
    let mut delete_extra = false;
    let mut dry_run = false;
    let mut use_checksum = false;
    let mut excludes: Vec<String> = Vec::new();
    for opt in opts {
        if opt == "delete" {
            delete_extra = true;
        } else if opt == "dry-run" || opt == "dry_run" {
            dry_run = true;
        } else if opt == "checksum" {
            use_checksum = true;
        } else if let Some(pat) = opt.strip_prefix("exclude=") {
            excludes.push(pat.to_string());
        } else {
            warn!("unknown --rsync-opt: {}", opt);
        }
    }
    // Ensure remote root directory exists
    let _ = sftp.create_dir(remote_root).await;

    let local_files = list_local_files(local_root).await?;
    let remote_files = list_remote_files(sftp, remote_root).await?;
    let local_prefix = local_root.trim_end_matches('/');
    let remote_prefix = remote_root.trim_end_matches('/');

    for (local_path, info) in &local_files {
        let rel_path = local_path.strip_prefix(local_prefix).unwrap_or(local_path);
        let rel_path = rel_path.strip_prefix('/').unwrap_or(rel_path);
        // --rsync-opt exclude
        if excludes.iter().any(|pat| {
            rel_path.contains(pat) || rel_path.ends_with(pat) || local_path.contains(pat)
        }) {
            info!("rsync skip (excluded): {}", rel_path);
            continue;
        }
        let remote_path = format!("{}/{}", remote_prefix, rel_path);

        match remote_files.get(&remote_path) {
            Some(ri) if ri.size == info.size && (!use_checksum && ri.mtime == info.mtime) => {
                info!("rsync skip (same): {}", rel_path);
                continue;
            }
            Some(ri) if ri.size == info.size => {
                info!("rsync delta check: {} (size={})", rel_path, info.size);
                let local_data = tokio::fs::read(local_path).await?;
                let remote_data = sftp.read(&remote_path).await?;
                if local_data == remote_data {
                    info!("rsync: content identical, skipping");
                    continue;
                }
                let sync = SyncBuilder::new().block_size(4096).build();
                let sig = sync.signature(std::io::Cursor::new(&remote_data))?;
                let delta = sync.delta(std::io::Cursor::new(&local_data), &sig)?;
                // Estimate savings: delta's total literal + copy data vs original size
                let delta_size = delta
                    .ops
                    .iter()
                    .map(|op| match op {
                        copia::DeltaOp::Literal(data) => data.len() as u64,
                        copia::DeltaOp::Copy { .. } => 13,
                    })
                    .sum::<u64>();
                if delta_size < local_data.len() as u64 {
                    info!(
                        "rsync delta: {} -> {} bytes (saved {}%)",
                        local_data.len(),
                        delta_size,
                        (1.0 - delta_size as f64 / local_data.len() as f64) * 100.0
                    );
                    let mut output = Vec::new();
                    sync.patch(std::io::Cursor::new(&remote_data), &delta, &mut output)?;
                    let mut file = sftp.create(&remote_path).await?;
                    file.write_all(&output).await?;
                    file.flush().await?;
                    continue;
                }
            }
            _ => {}
        }
        if dry_run {
            info!(
                "rsync dry-run: would upload {} -> {}",
                local_path, remote_path
            );
            continue;
        }
        info!("rsync upload: {} -> {}", local_path, remote_path);
        let data = tokio::fs::read(local_path).await?;
        let mut file = sftp.create(&remote_path).await?;
        file.write_all(&data).await?;
        file.flush().await?;
    }
    // --rsync-opt delete: remove remote files not in local
    if delete_extra {
        for remote_path in remote_files.keys() {
            let rel_path = remote_path
                .strip_prefix(remote_prefix)
                .unwrap_or(remote_path);
            let rel_path = rel_path.strip_prefix('/').unwrap_or(rel_path);
            // Check if this remote file has a matching local file
            let local_path = format!("{}/{}", local_prefix, rel_path);
            if !local_files.contains_key(&local_path) {
                if dry_run {
                    info!("rsync dry-run: would delete {}", remote_path);
                } else {
                    info!("rsync delete: {}", remote_path);
                    let _ = sftp.remove_file(remote_path).await;
                }
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
async fn rsync_download(sftp: &SftpSession, remote_root: &str, local_root: &str) -> Result<()> {
    let local_files = list_local_files(local_root).await?;
    let remote_files = list_remote_files(sftp, remote_root).await?;
    let local_prefix = local_root.trim_end_matches('/');
    let remote_prefix = remote_root.trim_end_matches('/');

    for (remote_path, info) in &remote_files {
        let rel_path = remote_path
            .strip_prefix(remote_prefix)
            .unwrap_or(remote_path);
        let rel_path = rel_path.strip_prefix('/').unwrap_or(rel_path);
        let local_path = format!("{}/{}", local_prefix, rel_path);

        match local_files.get(&local_path) {
            Some(li) if li.size == info.size && li.mtime == info.mtime => {
                info!("rsync skip (same): {}", rel_path);
                continue;
            }
            Some(li) if li.size == info.size => {
                info!("rsync delta check: {}", rel_path);
                let local_data = tokio::fs::read(&local_path).await?;
                let remote_data = sftp.read(remote_path).await?;
                if local_data == remote_data {
                    info!("rsync: content identical");
                    continue;
                }
            }
            _ => {}
        }
        info!("rsync download: {} -> {}", remote_path, local_path);
        let data = sftp.read(remote_path).await?;
        if let Some(parent) = std::path::Path::new(&local_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&local_path, &data).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.help {
        print_help();
        return Ok(());
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

    if cli.fork {
        let args: Vec<String> = std::env::args()
            .filter(|a| a != "-f" && a != "--fork")
            .collect();
        let exe = std::env::current_exe()?;
        #[cfg(unix)]
        let child = std::process::Command::new(&exe)
            .args(&args[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        #[cfg(windows)]
        let child = std::process::Command::new(&exe)
            .args(&args[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(0x08000000)
            .spawn()?;
        info!("Forked to background (pid: {})", child.id());
        std::process::exit(0);
    }

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
    let password = cli.password.as_deref().map(|s| s.to_string());
    let passphrase = cli.passphrase.as_deref().map(|s| s.to_string());

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

        // -A agent forwarding (placeholder)
        // -H HTTP CONNECT forwarding
        if !http_connects.is_empty() {
            let fw = http_connects.clone();
            let fwd_host = host.to_string();
            let fwd_port = port;
            let fwd_user = user.to_string();
            let fwd_pw = password.clone();
            let fwd_pp = passphrase.clone();
            let fwd_key = cli.identity_file.clone();
            let uk = user_known_hosts.clone();
            tokio::spawn(async move {
                for spec in fw {
                    let cfg = Arc::new(client::Config::default());
                    let h =
                        SshHandler::new(strict_check, fwd_host.clone(), fwd_port, (*uk).clone());
                    let mut c = match client::connect(cfg, (fwd_host.as_str(), fwd_port), h).await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("HTTP CONNECT connect failed: {}", e);
                            continue;
                        }
                    };
                    authenticate_fwd(
                        &mut c,
                        &fwd_user,
                        fwd_pw.as_deref(),
                        fwd_pp.as_deref(),
                        fwd_key.as_deref(),
                    )
                    .await
                    .ok();
                    let _ = http_connect_forward(c, spec, exit_on_fwd_failure).await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
            });
        }

        // -D SOCKS forwarding (separate connections)
        if !dynamic_forwards.is_empty() {
            let fw = dynamic_forwards.clone();
            let fwd_host = host.to_string();
            let fwd_port = port;
            let fwd_user = user.to_string();
            let fwd_pw = password.clone();
            let fwd_pp = passphrase.clone();
            let fwd_key = cli.identity_file.clone();
            let uk = user_known_hosts.clone();
            tokio::spawn(async move {
                for spec in fw {
                    let cfg = Arc::new(client::Config::default());
                    let h =
                        SshHandler::new(strict_check, fwd_host.clone(), fwd_port, (*uk).clone());
                    let mut c = match client::connect(cfg, (fwd_host.as_str(), fwd_port), h).await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("SOCKS connect failed: {}", e);
                            continue;
                        }
                    };
                    authenticate_fwd(
                        &mut c,
                        &fwd_user,
                        fwd_pw.as_deref(),
                        fwd_pp.as_deref(),
                        fwd_key.as_deref(),
                    )
                    .await
                    .ok();
                    let _ = socks_proxy_forward(c, spec, exit_on_fwd_failure).await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
            });
        }

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

        // -L local forwarding (separate connections)
        if !local_forwards.is_empty() {
            let fw = local_forwards.clone();
            let fwd_host = host.to_string();
            let fwd_port = port;
            let fwd_user = user.to_string();
            let fwd_pw = password.clone();
            let fwd_pp = passphrase.clone();
            let fwd_key = cli.identity_file.clone();
            let uk = user_known_hosts.clone();
            tokio::spawn(async move {
                for spec in fw {
                    let cfg = Arc::new(client::Config::default());
                    let h =
                        SshHandler::new(strict_check, fwd_host.clone(), fwd_port, (*uk).clone());
                    let mut c = match client::connect(cfg, (fwd_host.as_str(), fwd_port), h).await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("Local forward connect failed: {}", e);
                            continue;
                        }
                    };
                    authenticate_fwd(
                        &mut c,
                        &fwd_user,
                        fwd_pw.as_deref(),
                        fwd_pp.as_deref(),
                        fwd_key.as_deref(),
                    )
                    .await
                    .ok();
                    let _ = local_port_forward(c, spec, exit_on_fwd_failure).await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
            });
        }

        // Session channel for shell/command
        let pure_fwd = cli.no_command
            && (!remote_forwards.is_empty()
                || !dynamic_forwards.is_empty()
                || !http_connects.is_empty());
        if !pure_fwd {
            let channel = handle.channel_open_session().await?;
            let want_pty = cli.force_tty || (cli.command.is_empty() && !cli.no_command);
            if want_pty {
                let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
                channel
                    .request_pty(true, &term, 80, 24, 640, 480, &[])
                    .await?;
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

async fn local_port_forward(
    handle: Handle<SshHandler>,
    spec: ForwardSpec,
    exit_on_failure: bool,
) -> Result<()> {
    let ba: SocketAddr = format!("{}:{}", spec.bind_addr, spec.bind_port).parse()?;
    let listener = match TcpListener::bind(ba).await {
        Ok(l) => l,
        Err(e) => {
            if exit_on_failure {
                return Err(e.into());
            }
            warn!(
                "-L bind {}:{} failed (ignored): {}",
                spec.bind_addr, spec.bind_port, e
            );
            return Ok(());
        }
    };
    info!("-L listening on {}:{}", spec.bind_addr, spec.bind_port);
    loop {
        let (stream, peer) = listener.accept().await?;
        info!("-L connection from {}", peer);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut srx, mut stx) = tokio::io::split(stream);
        match handle
            .channel_open_direct_tcpip(
                spec.target_host.as_str(),
                spec.target_port as u32,
                spec.bind_addr.as_str(),
                spec.bind_port as u32,
            )
            .await
        {
            Ok(channel) => {
                let (mut crx, ctx) = channel.split();
                let c2s = tokio::spawn(async move {
                    loop {
                        match crx.wait().await {
                            Some(ChannelMsg::Data { ref data }) => {
                                if stx.write_all(data).await.is_err() {
                                    break;
                                }
                                let _ = stx.flush().await;
                            }
                            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                            _ => {}
                        }
                    }
                });
                let s2c = tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    loop {
                        match srx.read(&mut buf).await {
                            Ok(0) => {
                                let _ = ctx.eof().await;
                                break;
                            }
                            Ok(n) => {
                                if ctx.data(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
                let _ = tokio::join!(c2s, s2c);
            }
            Err(e) => error!("-L channel open: {}", e),
        }
    }
}

// ======================================================================
// Authentication
// ======================================================================

async fn authenticate_fwd(
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

async fn authenticate(
    handle: &mut Handle<SshHandler>,
    user: &str,
    cli: &Cli,
    password: Option<&str>,
    passphrase: Option<&str>,
) -> Result<()> {
    let u = user.to_string();
    if let Some(ref k) = cli.identity_file {
        info!("Loading key: {:?}", k);
        if let Ok(pk) = load_secret_key(k, passphrase) {
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
    }
    if let Some(pw) = password {
        if handle.authenticate_password(u.clone(), pw).await?.success() {
            info!("Password auth succeeded");
            return Ok(());
        }
    }
    bail!("Authentication failed");
}
// Session I/O
// ======================================================================

async fn run_session(channel: Channel<Msg>, redirect_stdin: bool) -> Result<i32> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

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

const PKG_NAME: &str = env!("CARGO_PKG_NAME");

fn print_help() {
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
    println!("  --identity-passphrase  Key passphrase");
    println!("  --password <pw>  SSH password");
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
