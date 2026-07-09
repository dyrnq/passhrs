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

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::Future;
use russh::client::{self};

use crate::ssh::authenticate_fwd;

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_forward_tasks<Spec, Fut>(
    specs: &[Spec],
    label: &'static str,
    host: &str,
    port: u16,
    user: &str,
    password: &Option<String>,
    passphrase: &Option<String>,
    identity_file: &Option<std::path::PathBuf>,
    user_known_hosts: &std::sync::Arc<Option<String>>,
    strict_check: bool,
    accept_all_host_keys: bool,
    exit_on_fwd_failure: bool,
    forward_fn: fn(Handle<SshHandler>, Spec, bool) -> Pin<Box<Fut>>,
) where
    Spec: Clone + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    if specs.is_empty() {
        return;
    }
    let fw = specs.to_vec();
    let fwd_host = host.to_string();
    let fwd_port = port;
    let fwd_user = user.to_string();
    let fwd_pw = password.clone();
    let fwd_pp = passphrase.clone();
    let fwd_key = identity_file.clone();
    let uk = user_known_hosts.clone();
    tokio::spawn(async move {
        for spec in fw {
            let cfg = Arc::new(client::Config::default());
            let h = SshHandler::new(
                strict_check,
                fwd_host.clone(),
                fwd_port,
                (*uk).clone(),
                // Forward-only sessions (-L/-D/-H) don't have an
                // interactive agent-forwarding relationship: the
                // user's SSH session is the one carrying the
                // forwarded agent, not the tunnel's data plane.
                None,
                // Forward tunnels ride on a pre-established SSH
                // session; the host key was already verified by
                // the parent session. `-y` was already honored
                // there, so the per-tunnel handler doesn't need
                // to override again — but we thread the flag
                // through anyway in case passhrs ever opens a
                // fresh handshake here.
                accept_all_host_keys,
            );
            let mut c = match client::connect(cfg, (fwd_host.as_str(), fwd_port), h).await {
                Ok(c) => c,
                Err(e) => {
                    warn!("{} connect failed: {}", label, e);
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
            let _ = forward_fn(c, spec, exit_on_fwd_failure).await;
        }
        tokio::time::sleep(Duration::from_secs(u64::MAX)).await;
    });
}
