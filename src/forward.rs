use std::net::SocketAddr;

use anyhow::Result;
use log::*;
use russh::client::Handle;
use russh::ChannelMsg;
use tokio::net::TcpListener;

use crate::ssh::SshHandler;
use crate::types::ForwardSpec;
pub(crate) async fn local_port_forward(
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
