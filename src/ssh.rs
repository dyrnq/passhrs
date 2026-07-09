use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use log::*;
use russh::client::{ChannelOpenHandle, Handle, Handler, Msg};
use russh::keys::{load_secret_key, HashAlg, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg};

use crate::cli::Cli;
use crate::types::ForwardSpec;
pub(crate) struct SshHandler {
    strict_check: bool,
    host: String,
    port: u16,
    known_hosts_path: Option<String>,
    pub(crate) remote_forwards: HashMap<u16, ForwardSpec>,
    /// Local SSH agent socket path set when -A is in effect. Used
    /// by `server_channel_open_agent_forward` to dial the local
    /// agent whenever sshd opens a forwarded-agent channel back
    /// at us. The remote-side socket (`$SSH_AUTH_SOCK` on the
    /// remote host) is wired up by sshd itself, independent of
    /// passhrs; passhrs only owns the client-side pump.
    ///
    /// `None` means forwarding is disabled (whether -a was passed,
    /// -A wasn't, $SSH_AUTH_SOCK was unset, or this is an
    /// intermediate session where forwarding shouldn't apply — e.g.
    /// a ProxyJump hop).
    agent_sock_path: Option<PathBuf>,
    /// Per-channel exit status captured from the server's
    /// `exit-status` channel request via the
    /// `Handler::exit_status` callback. Populated by russh's
    /// connection handler at `client/encrypted.rs:519-526`
    /// *before* the channel sender is dropped (which happens at
    /// `client/encrypted.rs:419` on CHANNEL_CLOSE).
    ///
    /// The channel mpsc (`Channel::wait()`) loses ExitStatus when
    /// sshd emits Close before exit-status — russh removes the
    /// channel at `encrypted.rs:419` and any subsequent
    /// channel-request message is silently dropped at
    /// `encrypted.rs:523` (`self.channels.get(...)` returns
    /// `None`). The `Handler::exit_status` hook, however, fires
    /// independently of the channel map and is the only path that
    /// reliably sees ExitStatus in the Close-then-exit-status
    /// ordering observed on ubuntu-24.04 runners. Issue #41.
    pub(crate) exit_statuses: Arc<Mutex<HashMap<russh::ChannelId, u32>>>,
}

impl SshHandler {
    pub(crate) fn new(
        strict_check: bool,
        host: String,
        port: u16,
        known_hosts_path: Option<String>,
        agent_sock_path: Option<PathBuf>,
    ) -> Self {
        Self {
            strict_check,
            host,
            port,
            known_hosts_path,
            remote_forwards: HashMap::new(),
            agent_sock_path,
            exit_statuses: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Capture the remote exit status into the shared map. This
    /// runs on russh's connection task whenever the server sends
    /// an `exit-status` channel-request frame, regardless of
    /// whether the channel's mpsc is still alive. `run_session`
    /// reads back from this map after seeing the channel close.
    pub(crate) fn record_exit_status(&self, channel: russh::ChannelId, status: u32) {
        if let Ok(mut map) = self.exit_statuses.lock() {
            map.insert(channel, status);
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
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        let port = connected_port as u16;
        debug!(
            "Remote forward channel open from {}:{} for port {}",
            originator_address, originator_port, port
        );
        if let Some(spec) = self.remote_forwards.get(&port) {
            info!(
                "Remote forward: {}:{} -> {}:{} (via sshd)",
                originator_address, originator_port, spec.target_host, spec.target_port
            );
            let addr = format!("{}:{}", spec.target_host, spec.target_port);
            debug!(
                "Remote forward: dialing target {} (target_host={}, target_port={})",
                addr, spec.target_host, spec.target_port
            );
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(target_stream) => {
                    // russh 0.62+: the forwarded channel must be explicitly
                    // accepted; dropping `reply` auto-rejects. Accept only once
                    // we have a live connection to the forward target.
                    //
                    // The callback `server_channel_open_forwarded_tcpip`
                    // runs synchronously inside the russh event loop's
                    // `process_packet` (encrypted.rs:763-775). Awaiting
                    // `reply.accept()` inline would park the callback —
                    // and therefore the event loop — on the mpsc-send that
                    // notifies the loop about the reply, so the receiver
                    // (`self.inbound_channel_receiver`) can never be
                    // polled to drain it, and the mpsc back-pressures
                    // forever. The loop stays stuck inside
                    // `process_packet`, `CHANNEL_OPEN_CONFIRMATION` never
                    // reaches the wire, sshd never sends `CHANNEL_DATA`,
                    // and the c2t/t2c forwarding tasks (which already
                    // need data the loop isn't delivering) hang.
                    //
                    // Detaching the accept into a `tokio::spawn` lets the
                    // callback return immediately so the event loop can
                    // poll `inbound_channel_receiver`, observe the
                    // `Msg::ServerChannelOpenReply`, emit the
                    // confirmation, and start forwarding data into the
                    // channel's mpsc for the c2t task. The spawn is
                    // fire-and-forget; the JoinHandle is dropped with
                    // `let _ =`. `reply.accept()` itself is just an
                    // mpsc-send (lib_inner.rs:584-588), so spawning it is
                    // essentially zero-cost.
                    //
                    // The c2t/t2c forwarding tasks must likewise be
                    // detached: awaiting their `JoinHandle`s via
                    // `tokio::join!` would re-introduce the same
                    // event-loop deadlock, because the JoinHandles only
                    // resolve when the channel closes (via
                    // `ChannelMsg::Eof`/`ChannelMsg::Close` or TCP
                    // EOF/error). Dropping the JoinHandles does NOT
                    // cancel the spawned tasks — they self-terminate on
                    // the same signals.
                    let accept_handle = tokio::spawn(async move {
                        reply.accept().await;
                    });
                    drop(accept_handle);
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let (mut trx, mut ttx) = tokio::io::split(target_stream);
                    let (mut crx, ctx) = channel.split();
                    let c2t = tokio::spawn(async move {
                        loop {
                            match crx.wait().await {
                                Some(ChannelMsg::Data { ref data }) => {
                                    debug!(
                                        "Remote forward c2t: forwarding {} bytes to target",
                                        data.len()
                                    );
                                    if ttx.write_all(data).await.is_err() {
                                        debug!("Remote forward c2t: write error, ending");
                                        break;
                                    }
                                    let _ = ttx.flush().await;
                                }
                                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                                Some(other) => {
                                    debug!("Remote forward c2t: ignoring {:?}", other);
                                }
                            }
                        }
                    });
                    let t2c = tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            match trx.read(&mut buf).await {
                                Ok(0) => {
                                    debug!("Remote forward t2c: target EOF");
                                    let _ = ctx.eof().await;
                                    break;
                                }
                                Ok(n) => {
                                    debug!(
                                        "Remote forward t2c: forwarding {} bytes from target",
                                        n
                                    );
                                    if ctx.data(&buf[..n]).await.is_err() {
                                        debug!("Remote forward t2c: channel write error");
                                        break;
                                    }
                                }
                                Err(e) => {
                                    debug!("Remote forward t2c: read error {}", e);
                                    break;
                                }
                            }
                        }
                    });
                    drop(c2t);
                    drop(t2c);
                }
                Err(e) => {
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

    /// Handle a server-initiated `auth-agent@openssh.com` channel-open.
    /// sshd opens one of these for every process on the remote that
    /// tries to talk to the forwarded agent socket (`$SSH_AUTH_SOCK`
    /// on the remote); our job is to relay every byte between sshd
    /// and the local agent at `self.agent_sock_path`.
    ///
    /// Must NOT await `reply.accept()` inline — same reason as the
    /// forwarded-tcpip handler above: the callback runs synchronously
    /// inside russh's `process_packet` event loop, and awaiting the
    /// mpsc-send that notifies the loop about the reply would
    /// deadlock. Spawn the accept, then drop the JoinHandle.
    ///
    /// `session` is unused here (we only need it for other hooks).
    fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let agent_sock = self.agent_sock_path.clone();
        async move {
            let accept_handle = tokio::spawn(async move {
                let _ = reply.accept().await;
            });
            drop(accept_handle);

            let Some(sock_path) = agent_sock else {
                // No local agent configured (forwarding was disabled
                // or $SSH_AUTH_SOCK was unset when the session
                // started). We already accepted — best-effort: drain
                // the channel so sshd doesn't sit on a half-open
                // channel forever. We can't really reject at this
                // point (we accepted), so close the channel
                // immediately.
                let (_rx, _tx) = channel.split();
                return Ok(());
            };

            let channel_id = channel.id();
            debug!(
                "Agent forward: sshd opened auth-agent channel {:?}, dialing local agent at {}",
                channel_id,
                sock_path.display()
            );
            // Detach the byte pump into a spawned task so the
            // callback returns immediately and the event loop can
            // keep draining. The pump is fire-and-forget — it
            // self-terminates when sshd closes the channel or the
            // local agent closes.
            tokio::spawn(pump_agent_socket(channel, sock_path));
            Ok(())
        }
    }

    /// Capture the remote process exit status as soon as sshd sends
    /// the `exit-status` channel-request frame.
    ///
    /// This is the **only** reliable path for the exit code when
    /// sshd sends CHANNEL_CLOSE before exit-status. russh's
    /// connection handler removes the channel from its map on
    /// CHANNEL_CLOSE (`client/encrypted.rs:419`) and drops the
    /// mpsc sender; any subsequent `exit-status` frame is then
    /// silently dropped at `encrypted.rs:523` because
    /// `self.channels.get(&channel_num)` returns `None`. The
    /// `Handler::exit_status` callback, however, fires
    /// independently of the channel map (it's invoked at
    /// `encrypted.rs:526` after the mpsc-send attempt). Issue #41.
    ///
    /// `run_session` reads this map back after the channel's
    /// mpsc-side Close arrives, so it can return the right exit
    /// code instead of falling back to 0.
    async fn exit_status(
        &mut self,
        channel: russh::ChannelId,
        exit_status: u32,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            "Handler::exit_status: channel={:?} status={}",
            channel, exit_status
        );
        self.record_exit_status(channel, exit_status);
        Ok(())
    }
}

// ======================================================================
// Agent forwarding pump (Issue #23).
//
// `pump_agent_socket` bridges a server-initiated
// `auth-agent@openssh.com` channel to a local SSH agent over a Unix
// socket (`$SSH_AUTH_SOCK`). On Unix that socket is a real Unix
// domain socket; on Windows it is a named pipe (ssh-agent and the
// Windows OpenSSH agent both expose a `\\.\pipe\…` path, and a few
// setups additionally fall back to a Unix-style path when Cygwin /
// MSYS / WSL is involved). The helper therefore resolves via
// `tokio::net::UnixStream` for plain paths and via
// `tokio::net::windows::named_pipe::ClientOptions::open` for the
// `\\.\pipe\` prefix; the resulting stream is then used identically
// for the read/write pump.
//
// Future-direction note: if someone later needs to support Windows
// ssh-agent's AF_UNIX shim (it's not currently common), this is the
// single point to extend.
// ======================================================================

#[cfg(unix)]
async fn connect_agent_stream(path: &Path) -> Result<tokio::net::UnixStream> {
    use anyhow::Context;
    tokio::net::UnixStream::connect(path)
        .await
        .with_context(|| {
            format!(
                "agent forward: failed to connect to local agent socket {}",
                path.display()
            )
        })
}

#[cfg(windows)]
async fn connect_agent_stream(path: &Path) -> Result<NamedPipeClientStream> {
    use anyhow::Context;
    let s = path.to_string_lossy();
    // `\\.\pipe\<name>` is the canonical named-pipe path on Windows.
    // The Windows OpenSSH agent and ssh-agent both register under
    // `\\.\pipe\openssh-ssh-agent` (or a per-user variant); Cygwin /
    // MSYS may surface them at /tmp/... paths, which tokio can't
    // open as named pipes — but passhrs doesn't currently claim to
    // support that mode.
    if !s.starts_with(r"\\.\pipe\") {
        return Err(anyhow::anyhow!(
            "agent forward: local agent socket {} is not a Windows named pipe \
             (must start with \\\\.\\pipe\\); passhrs does not currently \
             translate non-pipe paths",
            s
        ));
    }
    let pipe_name: &str = &s[r"\\.\pipe\".len()..];
    tokio::net::windows::named_pipe::ClientOptions::new()
        .open(pipe_name)
        .with_context(|| format!("agent forward: failed to open local agent named pipe {}", s))
}

#[cfg(windows)]
type NamedPipeClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

async fn pump_agent_socket(channel: Channel<Msg>, sock_path: PathBuf) {
    use anyhow::Context;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stream = match connect_agent_stream(&sock_path).await {
        Ok(s) => s,
        Err(e) => {
            warn!("{}", e);
            // Best-effort: close the channel so sshd doesn't sit on
            // a half-open channel. Whether the close reaches sshd
            // before sshd times out the forwarded agent request is
            // up to the transport, but closing never makes things
            // worse.
            let (_rx, _tx) = channel.split();
            return;
        }
    };

    let (mut crx, ctx) = channel.split();
    let (mut trx, mut ttx) = tokio::io::split(stream);

    let pump_c2a = tokio::spawn(async move {
        // channel -> local agent
        loop {
            match crx.wait().await {
                Some(ChannelMsg::Data { ref data }) => {
                    if let Err(e) = ttx.write_all(data).await {
                        debug!("Agent forward c2a: write to local agent failed: {}", e);
                        break;
                    }
                    let _ = ttx.flush().await;
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                Some(other) => {
                    debug!("Agent forward c2a: ignoring {:?}", other);
                }
            }
        }
    });

    let pump_a2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        // local agent -> channel
        loop {
            match trx.read(&mut buf).await {
                Ok(0) => {
                    let _ = ctx.eof().await;
                    break;
                }
                Ok(n) => {
                    if let Err(e) = ctx.data(&buf[..n]).await.with_context(|| {
                        format!(
                            "agent forward: failed to forward {} bytes from \
                             local agent to sshd",
                            n
                        )
                    }) {
                        debug!("Agent forward a2c: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    debug!("Agent forward a2c: read from local agent failed: {}", e);
                    break;
                }
            }
        }
    });

    // Drop both JoinHandles — they self-terminate on channel or
    // agent EOF / error. Awaiting them inside a `join!` would
    // re-introduce the same event-loop deadlock as the
    // forwarded-tcpip handler (they only complete on EOF).
    drop(pump_c2a);
    drop(pump_a2c);

    debug!(
        "Agent forward: pump started for local socket {}",
        sock_path.display()
    );
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
            let algos: &[Option<HashAlg>] = if pk.algorithm().is_rsa() {
                &[Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]
            } else {
                &[None]
            };
            for &algo in algos {
                let key = PrivateKeyWithHashAlg::new(Arc::new(pk.clone()), algo);
                let result = handle.authenticate_publickey(u.clone(), key).await?;
                if result.success() {
                    return Ok(());
                }
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
                let algos: &[Option<HashAlg>] = if pk.algorithm().is_rsa() {
                    &[Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]
                } else {
                    &[None]
                };
                let mut succeeded = false;
                for &algo in algos {
                    let key = PrivateKeyWithHashAlg::new(Arc::new(pk.clone()), algo);
                    let result = handle.authenticate_publickey(u.clone(), key).await?;
                    if result.success() {
                        info!("Public key auth succeeded");
                        succeeded = true;
                        break;
                    }
                }
                if succeeded {
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

pub(crate) async fn run_session(
    channel: Channel<Msg>,
    redirect_stdin: bool,
    exit_statuses: Arc<Mutex<HashMap<russh::ChannelId, u32>>>,
) -> Result<i32> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    // Channel id used to look up the captured exit status from the
    // `Handler::exit_status` callback. Computed once before the
    // channel is split so the reader thread can read it after the
    // channel's mpsc is closed. Issue #41.
    let channel_id = channel.id();

    // Put local terminal in raw mode when running an interactive shell
    let _raw = if !redirect_stdin && std::io::stdin().is_terminal() {
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
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => {
                    // Eof/Close can arrive BEFORE ExitStatus for non-PTY
                    // execs: sshd sends the channel close as soon as
                    // the remote shell's last fd is gone, and the
                    // `exit-status` SSH_MSG_CHANNEL_REQUEST is a
                    // separate frame that races the close. On
                    // ubuntu-24.04 runners the gap is large enough
                    // (multiple hundred ms) that a 200ms grace window
                    // (the previous value) reliably lost the
                    // ExitStatus, so the remote command's exit code
                    // was eaten and `passhrs` returned 0. Issue #41.
                    //
                    // The previous drain was also racy in a subtler
                    // way: it broke on the *first* trailing Eof/Close,
                    // but the russh mpsc is FIFO
                    // (russh-0.62.1/src/channels/mod.rs:144-158 wraps
                    // `tokio::sync::mpsc::Receiver<ChannelMsg>`),
                    // so if the channel carried Eof *then* ExitStatus
                    // (the order sshd emits when `-T` is in effect),
                    // the drain consumed Eof and broke before
                    // ExitStatus was ever polled.
                    //
                    // Fix: keep draining until the sender half has
                    // actually dropped (`rx.wait()` returns `None`),
                    // not until the next Eof/Close. Bound the wait
                    // with a generous timeout — 5 s — as a safety net
                    // for hung connections. Captured ExitStatus
                    // values stay in `code` even if a later Eof/Close
                    // arrives; the only signal that ends the drain is
                    // `None`, i.e. the channel has been fully closed
                    // by russh's connection handler.
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        loop {
                            match rx.wait().await {
                                Some(ChannelMsg::ExitStatus { exit_status }) => {
                                    code = exit_status as i32;
                                }
                                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => {
                                    // Keep draining: ExitStatus may
                                    // still be queued behind this
                                    // Eof/Close.
                                }
                                None => break, // sender dropped; channel fully closed
                                _ => {}        // drain any other trailing messages
                            }
                        }
                    })
                    .await;
                    break;
                }
                None => break,
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
    // The reader thread only sees ExitStatus if russh happened to
    // buffer it in the channel mpsc before the sender was dropped
    // on CHANNEL_CLOSE. When sshd emits Close *before* exit-status
    // — the ordering observed on ubuntu-24.04 — ExitStatus never
    // reaches the mpsc (russh drops the channel at
    // `client/encrypted.rs:419` and silently discards the
    // late-arriving frame at line 523). The
    // `Handler::exit_status` callback still fires for that late
    // frame though, so we use the captured map as the
    // authoritative source and only fall back to the mpsc-derived
    // `code` if the callback never ran (i.e. sshd didn't send
    // exit-status at all — happens for sessions aborted by signal).
    let captured = exit_statuses
        .lock()
        .ok()
        .and_then(|mut m| m.remove(&channel_id));
    let final_code = match captured {
        Some(c) if c as i32 != code => {
            debug!(
                "run_session: mpsc exit code ({}) overrode by Handler::exit_status ({}); \
                 sshd sent Close before exit-status (Issue #41)",
                code, c
            );
            c as i32
        }
        Some(c) => c as i32,
        None => code,
    };
    info!("Session exit code {}", final_code);
    Ok(final_code)
}

/// Decide whether a local environment variable should be forwarded to the
/// remote session (shell / exec).
///
/// Mirrors OpenSSH's default `SendEnv LANG LC_*` behavior: forward `LANG`,
/// `LANGUAGE` and every `LC_*` locale variable. This lets locale-aware remote
/// programs (vi/less/nano/…) render UTF-8 correctly and avoids garbled
/// multibyte (e.g. Chinese) text. Everything else is intentionally not
/// forwarded, to avoid leaking the local environment or overriding remote
/// configuration.
pub(crate) fn should_forward_locale_env(name: &str) -> bool {
    name == "LANG" || name == "LANGUAGE" || name.starts_with("LC_")
}

#[cfg(test)]
mod tests {
    use super::should_forward_locale_env;

    #[test]
    fn forwards_lang_and_language() {
        assert!(should_forward_locale_env("LANG"));
        assert!(should_forward_locale_env("LANGUAGE"));
    }

    #[test]
    fn forwards_all_lc_variants() {
        assert!(should_forward_locale_env("LC_ALL"));
        assert!(should_forward_locale_env("LC_CTYPE"));
        assert!(should_forward_locale_env("LC_MESSAGES"));
        assert!(should_forward_locale_env("LC_TIME"));
        // Prefix match covers any future LC_* variable.
        assert!(should_forward_locale_env("LC_SOMETHING_NEW"));
    }

    #[test]
    fn does_not_forward_unrelated_env() {
        // Avoid leaking local env or overriding remote configuration.
        assert!(!should_forward_locale_env("PATH"));
        assert!(!should_forward_locale_env("HOME"));
        assert!(!should_forward_locale_env("TERM"));
        assert!(!should_forward_locale_env("SSH_AUTH_SOCK"));
        // No substring matching: names that merely contain LANG/LC_ but are
        // not locale variables must not be forwarded.
        assert!(!should_forward_locale_env("MYLANG"));
        assert!(!should_forward_locale_env("XLC_FOO"));
        assert!(!should_forward_locale_env("LANGUAGES"));
    }
}
