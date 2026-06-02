use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use log::*;
use russh::client::Handle;
use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::ssh::SshHandler;
use crate::types::DynamicForwardSpec;
pub(crate) fn socks5_response(bind_addr: &str, bind_port: u16, status: u8) -> Vec<u8> {
    // Try IPv4 dotted notation first
    if let Some(octets) = try_parse_ipv4(bind_addr) {
        let mut resp = vec![5, status, 0, 1];
        resp.extend_from_slice(&octets);
        resp.extend_from_slice(&bind_port.to_be_bytes());
        return resp;
    }
    // Fall back to IPv6
    if let Some(octets) = try_parse_ipv6(bind_addr) {
        let mut resp = vec![5, status, 0, 4];
        resp.extend_from_slice(&octets);
        resp.extend_from_slice(&bind_port.to_be_bytes());
        return resp;
    }
    // Domain name fallback (unlikely for bind address)
    let mut resp = vec![5, status, 0, 3];
    let bytes = bind_addr.as_bytes();
    resp.push(bytes.len() as u8);
    resp.extend_from_slice(bytes);
    resp.extend_from_slice(&bind_port.to_be_bytes());
    resp
}

fn try_parse_ipv4(addr: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        octets[i] = p.parse().ok()?;
    }
    Some(octets)
}

fn try_parse_ipv6(addr: &str) -> Option<[u8; 16]> {
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    match addr.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => Some(v6.octets()),
        Err(_) => None,
    }
}

pub(crate) async fn socks5_handshake(
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
        4 => {
            let mut ip = [0u8; 16];
            srx.read_exact(&mut ip).await?;
            let mut p = [0u8; 2];
            srx.read_exact(&mut p).await?;
            let v6 = std::net::Ipv6Addr::from(ip);
            Ok((v6.to_string(), u16::from_be_bytes(p)))
        }
        _ => bail!("unsupported SOCKS5 address type: {}", buf[3]),
    }
}

pub(crate) async fn socks_proxy_forward(
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

pub(crate) async fn handle_socks_connection(
    handle: &Handle<SshHandler>,
    stream: TcpStream,
) -> Result<()> {
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

pub(crate) async fn http_connect_forward(
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
        let _ = http_connect_handle_one(&handle, stream).await;
    }
}

/// Parse an HTTP CONNECT request, returning (host, port).
fn parse_connect_request(buf: &[u8]) -> Result<(String, u16)> {
    let request = String::from_utf8_lossy(buf);
    let parts: Vec<&str> = request.splitn(3, ' ').collect();
    if parts.len() < 2 || parts[0].to_uppercase() != "CONNECT" {
        bail!(
            "invalid HTTP CONNECT request: {}",
            request.lines().next().unwrap_or("?")
        );
    }
    let host_port = parts[1];
    let hp: Vec<&str> = host_port.rsplitn(2, ':').collect();
    if hp.len() != 2 {
        bail!("invalid host:port in CONNECT: {}", host_port);
    }
    let port: u16 = hp[0].parse().context("invalid port in CONNECT")?;
    Ok((hp[1].to_string(), port))
}

/// Write an HTTP response status line to the stream.
async fn write_http_response(stream: &mut TcpStream, status: u16, message: &str) {
    use tokio::io::AsyncWriteExt;
    let resp = format!("HTTP/1.1 {} {}\r\n\r\n", status, message);
    let _ = stream.write_all(resp.as_bytes()).await;
}

/// Bidirectional tunnel: SSH channel <-> TCP stream.
async fn tunnel_forward(channel: Channel<Msg>, stream: TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

pub(crate) async fn http_connect_handle_one(
    handle: &Handle<SshHandler>,
    mut stream: TcpStream,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 4096];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => {
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };
    let (host, port) = match parse_connect_request(&buf[..n]) {
        Ok(v) => v,
        Err(e) => {
            warn!("-H {}", e);
            write_http_response(&mut stream, 400, "Bad Request").await;
            return Ok(());
        }
    };
    match handle
        .channel_open_direct_tcpip(&host, port as u32, "127.0.0.1", 0u32)
        .await
    {
        Ok(channel) => {
            info!("-H CONNECT {}:{} via SSH", host, port);
            write_http_response(&mut stream, 200, "Connection Established").await;
            tunnel_forward(channel, stream).await;
        }
        Err(e) => {
            warn!("-H channel_open {}:{} failed: {}", host, port, e);
            write_http_response(&mut stream, 502, "Bad Gateway").await;
        }
    }
    Ok(())
}
