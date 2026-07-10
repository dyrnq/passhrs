//! SSH master / resume over a Unix-domain control socket (Issue #29,
//! the positive implementation of OpenSSH-style `-S <path>`).
//!
//! Wire format (passhrs-native, not OpenSSH-wire-compatible).
//! Three separate conventions apply — one per direction — because
//! only the master-to-resume stream needs a tag byte (to distinguish
//! stdout vs stderr vs done); the resume-to-master and `-O`
//! client-to-master frames are just payloads, no tag needed.
//!
//! ```text
//! // resume -> master (single frame, command line)
//! cmd_frame := u32_be(length) | payload(length bytes, UTF-8 command)
//!
//! // -O client -> master (single frame, control command)
//! ctrl_frame := u32_be(length) | payload(length bytes, "check\n" | "exit\n")
//!
//! // master -> resume (multi-frame, tagged)
//! stdout_frame := u32_be(length) | 0x01 | payload
//! stderr_frame := u32_be(length) | 0x02 | payload
//! done_frame   := u32_be(1) | 0x00 | u8 exit_code  // length=1, not 0
//! ```
//!
//! The done frame uses `length=1` (not 0) so the reader's
//! "read `len` bytes after the header" loop picks up the exit
//! code byte as the payload, keeping the framing uniform with
//! stdout/stderr frames (no special-case read for the done tag).
//!
//! `-O` reuses the same resume-to-master framing — the only
//! difference is the payload is a control verb (`check\n` /
//! `exit\n`) instead of a command line. The master dispatches on
//! the first word of the payload before the existing exec path
//! runs, so Issue #29's `handle_resume` keeps working unchanged
//! for resume clients.
//!
//! Master side: an `Arc<Handle<SshHandler>>` is shared between the
//! outer master event loop and the accept loop. Every `Handle::*`
//! method we need on the master side is `&self` (russh 0.62
//! `src/client/mod.rs:688-949` verified), so the Arc needs no
//! `Mutex` — multiple accept tasks can race to call
//! `channel_open_session` without contention.
//!
//! Cleanup: bind-time `unlink(path)` removes stale files; on
//! shutdown the `ControlSocketGuard::drop` removes the path again.
//! When the master is killed (Ctrl-C / SIGTERM / RPC error), the
//! guard drops, removing the file before the process exits.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;

use anyhow::{bail, Context, Result};
use log::*;
use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};

use crate::cli::Cli;
use crate::ssh::SshHandler;

/// True if the user's argv has no fresh-auth flags. The plan's
/// predicate: with no identity file, no password, and no
/// password-file the resume client has nothing to authenticate
/// with, so it must reuse the master. passphrase / passphrase_file
/// are NOT part of the predicate — those refine an existing key
/// (which the resume doesn't supply) and would always be set only
/// when a master is also configured to decrypt that key.
pub(crate) fn has_no_fresh_auth(cli: &Cli) -> bool {
    cli.identity_file.is_none() && cli.password.is_none() && cli.password_file.is_none()
}

// ----- Binding + cleanup -----

/// Process-global "the master should exit" event. Set by the
/// `-O exit` / `-O stop` handler when a client asks the master
/// to terminate cleanly; observed by `run_master`'s accept loop
/// so the loop breaks immediately and the process returns
/// through the normal `Result<()>` path (with the
/// `ControlSocketGuard::drop` cleanup removing the UDS file).
///
/// `tokio::sync::Notify` is the right primitive here: the
/// accept loop is parked in `tokio::select!` on `listener.accept()`,
/// and an `AtomicBool` polled at the top of each loop iteration
/// would only fire when the next connection arrives (or never, if
/// the user sent `-O exit` and nothing follows). A `Notify`
/// wakeup the loop's select branch on every call to
/// `notify_one()` — even when the loop is currently idle in
/// `accept()`. Cheap (one syscall on wake), single-tenant (the
/// master process is the only writer/reader), and exactly the
/// "fire once" semantics we want.
///
/// `LazyLock` is required because `Notify::new()` is not
/// `const fn`, so we cannot put the value directly inside a
/// `static`. `LazyLock` evaluates the closure on first access
/// (which happens at most once per master process — `run_master`
/// is the only caller of `set_should_exit`).
static SHOULD_EXIT: std::sync::LazyLock<Notify> = std::sync::LazyLock::new(Notify::new);

/// Mark the master for clean shutdown. Called from
/// `handle_ctrl_exit` after the bye frame has been written.
/// Wakes the accept loop so it can break on its next poll
/// without waiting for another inbound connection.
fn set_should_exit() {
    SHOULD_EXIT.notify_one();
}

/// Bind the UDS at `path`, removing any stale file from a prior
/// aborted master first. Sets mode `0o600` so other local users
/// can't connect (the master is per-user). Returns the bound
/// tokio listener + a `ControlSocketGuard` that must be held for
/// the master's lifetime to ensure the path is cleaned up on exit.
fn bind_listener(path: &Path) -> Result<(UnixListener, ControlSocketGuard)> {
    use std::os::unix::net::UnixListener as StdUnixListener;
    // Best-effort cleanup of a stale file from a prior aborted
    // master. We swallow `ENOENT`; other errors bubble.
    match std::fs::remove_file(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "control socket: failed to unlink stale {}: {}",
                path.display(),
                e
            ));
        }
    }
    let std_listener = StdUnixListener::bind(path)
        .with_context(|| format!("control socket: failed to bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("control socket: chmod 0600 {} failed", path.display()))?;
    let listener = UnixListener::from_std(std_listener)
        .with_context(|| format!("control socket: tokio wrap of {} failed", path.display()))?;
    info!(
        "Control socket bound at {} (mode 0o600); accepting resume requests",
        path.display()
    );
    Ok((listener, ControlSocketGuard::new(path.to_path_buf())))
}

/// Drop-guard that removes the UDS path file when the master exits.
/// Mirror of `RawModeGuard` at `src/ssh.rs:510-527`. We hold it in
/// `run_master` for the master's lifetime; dropping it (whether
/// through normal return, Ctrl-C, or panic unwind) removes the
/// path so a follow-up `-S` isn't blocked by a stale file.
pub(crate) struct ControlSocketGuard {
    path: Option<PathBuf>,
}

impl ControlSocketGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Take the path out of the guard (e.g. for tests that want to
    /// inspect it), leaving the guard a no-op on Drop.
    #[allow(dead_code)]
    pub(crate) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

impl Drop for ControlSocketGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            match std::fs::remove_file(&p) {
                Ok(_) => info!("Control socket: removed {}", p.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!(
                    "Control socket: failed to remove {} on shutdown: {}",
                    p.display(),
                    e
                ),
            }
        }
    }
}

// ----- Master -----

/// Master: bind `-S <path>`, accept connections, proxy each request
/// as a fresh exec on the cached `Handle`. Blocks until ctrl-c /
/// shutdown. Returns `Ok(())` on clean shutdown, `Err` if the bind
/// fails or if any of the per-request helpers fail.
pub(crate) async fn run_master(handle: Arc<Handle<SshHandler>>, ctrl_path: &Path) -> Result<()> {
    let (listener, _guard) = bind_listener(ctrl_path)?;

    // SIGINT (Ctrl-C) and SIGTERM (`kill <pid>` without -9; also
    // what systemd / supervisord send on stop) both drive the
    // accept loop out of its `select!`. SIGKILL bypasses
    // everything — the kernel kills the process before any
    // handler runs, so the UDS file would be left on disk. That's
    // expected; `bind_listener`'s stale-file `remove_file` cleans
    // it on the next master invocation.
    //
    // SIGINT uses tokio's `ctrl_c` (high-level helper).
    // SIGTERM requires the lower-level `signal(SignalKind::terminate())`
    // — we wrap the `recv()` in an async block so both can share
    // the `select!` as pin boxes.
    let sigint = Box::pin(async move {
        let _ = tokio::signal::ctrl_c().await;
    }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
    let sigterm: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                let fut = async move {
                    let _ = s.recv().await;
                };
                Box::pin(fut)
            }
            Err(e) => {
                warn!("Control master: SIGTERM listener failed: {}", e);
                // No-op future so the select branch never fires.
                Box::pin(futures::future::pending::<()>())
            }
        };

    accept_loop(listener, handle, sigint, sigterm).await
}

/// Accept-loop body. Listens for incoming UDS connections, races
/// the listener against two signal futures so SIGINT / SIGTERM
/// cleanly break the loop and let `ControlSocketGuard::Drop`
/// remove the UDS file. SIGKILL is the only path that bypasses
/// this and leaves a stale file; bind-time `remove_file` in
/// `bind_listener` cleans it on the next master invocation.
async fn accept_loop(
    listener: UnixListener,
    handle: Arc<Handle<SshHandler>>,
    sigint: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    sigterm: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) -> Result<()> {
    tokio::pin!(sigint);
    tokio::pin!(sigterm);
    loop {
        // Race the listener's accept against the SHOULD_EXIT
        // notify, SIGINT, and SIGTERM. `biased;` ensures signals
        // are checked first (so a Ctrl-C during a slow accept
        // doesn't have to wait for it). The SHOULD_EXIT notify
        // is what `set_should_exit` (inside the `-O exit`
        // handler task) fires — without it the loop would only
        // re-check on the next accepted connection, which would
        // never come if `-O exit` was the last thing the user
        // asked the master to do. Poll a fresh `notified()`
        // each iteration: each call returns a future that
        // resolves on the next `notify_one()` after the call,
        // so a single fire-and-forget shutdown is exactly
        // observed once.
        tokio::select! {
            biased;
            _ = sigint.as_mut() => {
                info!("Control master: SIGINT received, closing.");
                return Ok(());
            }
            _ = sigterm.as_mut() => {
                info!("Control master: SIGTERM received, closing.");
                return Ok(());
            }
            _ = SHOULD_EXIT.notified() => {
                info!("Control master: -O exit observed, closing.");
                return Ok(());
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _peer)) => {
                        let handle = handle.clone();
                        // Each accepted connection is its own task —
                        // the master can serve concurrent resumes.
                        // Detach (drop the JoinHandle) so this loop
                        // doesn't block on slow clients. The task
                        // self-terminates when the client closes
                        // the UDS or the SSH channel EOFs.
                        tokio::spawn(async move {
                            if let Err(e) = handle_resume(handle, stream).await {
                                warn!("Control master: resume failed: {e:?}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Control master: accept failed: {}; continuing.", e);
                        // Don't break on transient accept errors; the
                        // next call may succeed.
                    }
                }
            }
        }
    }
}

/// Serve a single resume connection: read the command-line frame,
/// open a session channel, pump bytes back as stdout/stderr frames,
/// terminate with a done frame (exit code).
async fn handle_resume(handle: Arc<Handle<SshHandler>>, stream: UnixStream) -> Result<()> {
    let (mut rx, mut tx) = stream.into_split();
    // The first frame is the command line. We don't read more than
    // one Exec frame per connection; if the client wants to run
    // another command they reconnect.
    let cmd_line = match read_cmd_frame(&mut rx).await? {
        Some(b) => String::from_utf8(b).context("resume: command line is not UTF-8")?,
        None => {
            // EOF before any bytes: client closed early. Treat as
            // a benign no-op.
            return Ok(());
        }
    };
    let trimmed = cmd_line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();
    // `-O` control verbs share the resume-to-master framing, so
    // dispatch on the first whitespace-separated token before
    // falling through to the exec path. Issue #54. `check` and
    // `exit` / `stop` are the only verbs in v1; any unknown verb
    // gets treated as a (likely-empty) command line — the exec
    // path returns exit 0 for empty commands, which is what the
    // caller wants when they typo'd "checks" instead of "check".
    let verb = trimmed.split_whitespace().next().unwrap_or("");
    match verb {
        "check" => return handle_ctrl_check(&mut tx).await,
        "exit" | "stop" => {
            info!("Control master: -O exit received, shutting down");
            handle_ctrl_exit(&mut tx).await?;
            // Returning Ok(()) here drops the per-connection task
            // but the master's accept loop will exit on its next
            // iteration when it sees the UDS listener is no longer
            // accepting (we set a flag and break). The simpler path
            // is to just return; the master process is killed by
            // the caller of this function (which is itself, via
            // the `should_exit` static). Actually — we set a
            // process-level flag and the parent `run_master`
            // observes it. Issue #54 implementation note.
            set_should_exit();
            return Ok(());
        }
        _ => {}
    }
    let cmd = trimmed;
    if cmd.is_empty() {
        write_done(&mut tx, 0).await?;
        return Ok(());
    }

    info!("Control master: resume exec: {:?}", cmd);
    // Channel + relay. We DO pass `want_reply=true` so we get a
    // explicit acknowledgement that the exec was accepted.
    let channel = handle.channel_open_session().await?;
    channel.exec(true, cmd.as_bytes()).await?;

    let exit_code = pump_session_to_uds(channel, &mut tx).await?;
    write_done(&mut tx, exit_code).await?;
    tx.shutdown().await.ok();
    Ok(())
}

/// Forward every ChannelMsg from `channel` to `tx` as 1-frame
/// (stdout) / 2-frame (stderr) bytes; return the exit status.
async fn pump_session_to_uds(mut channel: Channel<Msg>, tx: &mut OwnedWriteHalf) -> Result<i32> {
    let mut exit_code: i32 = 0;
    // russh delivers messages from sshd in this order for an exec
    // with want_reply=true:
    //   1. ChannelMsg::Success   — reply to the exec request
    //   2. ChannelMsg::Data      — one or more, command stdout
    //   3. ChannelMsg::ExitStatus— shell's exit code
    //   4. ChannelMsg::Eof       — channel half-close
    // Earlier versions of this loop broke on `Success`/`None` and
    // never saw the Data frames — that was the source of the
    // empty-stdout bug in test_control_socket_resume_no_auth.
    // We now continue on Success/Failure (they're just protocol
    // ACKs) and break only on Eof/Close.
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                write_data_frame(tx, 1, &data).await?;
            }
            Some(ChannelMsg::ExtendedData { data, .. }) => {
                write_data_frame(tx, 2, &data).await?;
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = exit_status as i32;
                // Don't break here: drain any trailing Data the
                // shell may emit after the exit code (rare but
                // possible). Break on the next Eof.
            }
            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => {
                break;
            }
            Some(ChannelMsg::Success) | Some(ChannelMsg::Failure) => {
                // Reply to the exec request (when want_reply=true)
                // and any other channel-confirmation messages.
                // Ignore and continue.
            }
            None => break,
            // Other variants (X11, Signal, WindowAdjusted, …) — we
            // ignore them; passhrs's master doesn't need to
            // surface them to a resume client.
            _ => {}
        }
    }
    Ok(exit_code)
}

/// Reply to a `-O check` request. The client expects a
/// length-prefixed UTF-8 string of the form `ok <pid>\n`. We
/// intentionally do NOT use the existing stdout/stderr/done
/// frame tags (1/2/0) because the `-O` client (`send_ctrl_*`
/// below) reads a plain payload — the master side has no notion
/// of "stdout from this command" because no command was run.
///
/// Master-side response format (chosen to match OpenSSH's
/// "Master running (pid=...)" surface verbatim): payload is
/// `ok <pid>\n` on success. The client treats any other payload
/// (or any connection error) as "no master" and exits 1.
async fn handle_ctrl_check(tx: &mut OwnedWriteHalf) -> Result<()> {
    let pid = std::process::id();
    let payload = format!("ok {}\n", pid);
    write_cmd_frame(tx, payload.as_bytes()).await?;
    tx.shutdown().await.ok();
    Ok(())
}

/// Reply to a `-O exit` request and signal the master to
/// terminate. Sends `bye\n` so the client sees a clean ack
/// before the master closes the UDS; the
/// `ControlSocketGuard::drop` that follows removes the file
/// from disk. The accept-loop poll of `should_exit()` (above)
/// breaks the loop on its next iteration.
async fn handle_ctrl_exit(tx: &mut OwnedWriteHalf) -> Result<()> {
    write_cmd_frame(tx, b"bye\n").await?;
    tx.shutdown().await.ok();
    Ok(())
}

// ----- Framing -----

/// Write a u32 BE length + `tag` byte + payload. The `tag` is the
/// first byte after the length; for stdout it's 1, for stderr 2.
async fn write_data_frame(tx: &mut OwnedWriteHalf, tag: u8, payload: &[u8]) -> Result<()> {
    let mut header = [0u8; 5];
    header[0..4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    header[4] = tag;
    tx.write_all(&header).await?;
    tx.write_all(payload).await?;
    tx.flush().await?;
    Ok(())
}

/// Write the done frame: length=1, tag=0, payload=exit_code byte.
/// Length is 1 (not 0) so the reader's "read `len` bytes after the
/// header" loop sees the exit code as the payload, keeping the
/// framing consistent with stdout/stderr frames (no special case
/// in the reader for the done tag).
async fn write_done(tx: &mut OwnedWriteHalf, exit_code: i32) -> Result<()> {
    let mut header = [0u8; 5];
    header[0..4].copy_from_slice(&1u32.to_be_bytes());
    header[4] = 0;
    tx.write_all(&header).await?;
    tx.write_all(&[exit_code as u8]).await?;
    tx.flush().await?;
    Ok(())
}

/// Read a single length-prefixed frame from `rx`. Returns `Ok(None)`
/// on EOF (clean peer closure before any bytes). This is the
/// **resume → master** frame (command line) — no tag byte, just the
/// payload.
async fn read_cmd_frame(rx: &mut tokio::net::unix::OwnedReadHalf) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match rx.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; len];
    rx.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

/// Write a length-prefixed frame with no tag byte (resume → master).
async fn write_cmd_frame(tx: &mut OwnedWriteHalf, payload: &[u8]) -> Result<()> {
    let mut header = [0u8; 4];
    header.copy_from_slice(&(payload.len() as u32).to_be_bytes());
    tx.write_all(&header).await?;
    tx.write_all(payload).await?;
    tx.flush().await?;
    Ok(())
}

// ----- Resume client -----

/// Try the resume path: connect to the master's UDS, send the
/// exec'd command, proxy stdout/stderr back to the user's own
/// stdio (or suppress them if `quiet` / `-q`), then return the
/// exit code.
///
/// Returns `Ok(Some(code))` if the resume succeeded, `Ok(None)` if
/// the path is unreachable so the caller can fall back to a direct
/// sshd connection, and `Err(_)` only on protocol violations.
pub(crate) async fn try_resume(ctrl_path: &Path, cli: &Cli) -> Result<Option<i32>> {
    // Connect attempt: surface ENOENT / ECONNREFUSED as `None`
    // (no master / wrong path) so the caller can fall back. Other
    // errors propagate.
    let stream = match UnixStream::connect(ctrl_path).await {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            warn!(
                "-S {}: no master is listening ({}). Falling back to direct SSH.",
                ctrl_path.display(),
                e
            );
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };

    let (mut rx, mut tx) = stream.into_split();

    // Send the command line as a single payload (no args splitting
    // — passhrs only supports a single command line per resume
    // in v1; shell-style multi-command joins via `&&` work fine).
    let cmd_line = if cli.command.is_empty() {
        // No command means `true` — the resume just verifies the
        // master is alive and returns 0.
        "true".to_string()
    } else {
        cli.command.join(" ")
    };
    write_cmd_frame(&mut tx, cmd_line.as_bytes()).await?;

    // Read frames until the done tag (tag=0).
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    loop {
        let mut header = [0u8; 5];
        if rx.read_exact(&mut header).await.is_err() {
            bail!("resume: connection to master closed before exit code");
        }
        let len = u32::from_be_bytes(
            header[0..4]
                .try_into()
                .expect("5-byte header slice into 4-byte array is safe"),
        ) as usize;
        let tag = header[4];
        let mut payload = vec![0u8; len];
        rx.read_exact(&mut payload).await?;
        match tag {
            1 => {
                if !cli.quiet {
                    let _ = stdout.write_all(&payload).await;
                    let _ = stdout.flush().await;
                }
            }
            2 => {
                if !cli.quiet {
                    let _ = stderr.write_all(&payload).await;
                    let _ = stderr.flush().await;
                }
            }
            0 => {
                let code = payload.first().copied().unwrap_or(0) as i32;
                return Ok(Some(code));
            }
            other => bail!("resume: unknown tag {} from master", other),
        }
    }
}

// ----- -O control command client (Issue #54) -----

/// Outcome of a `-O` request, from the client's perspective.
pub(crate) enum CtrlReply {
    /// Master acknowledged and reported its PID. Used for `check`.
    Running(u32),
    /// Master acknowledged and asked to terminate. Used for
    /// `exit` / `stop`.
    Exiting,
    /// Master is unreachable at `ctrl_path` — socket doesn't exist,
    /// is hung, or refused the connection. Caller decides exit
    /// code (1 for `check`, 1 for `exit` — the latter with a
    /// different message because the user asked to exit a master
    /// that doesn't exist).
    NoMaster,
    /// Master replied with an unknown payload (protocol error).
    UnknownReply,
}

/// Send a `-O` control command to the master at `ctrl_path` and
/// return its reply. This is the early-exit branch that `run()`
/// uses when `cli.control_command` is `Some(_)`: it does NOT
/// establish an SSH session, it just talks to the existing
/// master (or fails to).
///
/// Wire format: a single length-prefixed payload frame from
/// client → master (the verb, e.g. `check\n`), then a single
/// length-prefixed payload frame from master → client (e.g.
/// `ok 12345\n` or `bye\n`). No tag bytes — `-O` payloads are
/// short UTF-8 strings, not byte streams.
///
/// On any connection failure (ENOENT, ECONNREFUSED, EOF before
/// reply) we return `CtrlReply::NoMaster` so the caller can
/// surface a friendly "No master running at <path>" message and
/// exit 1 without printing an anyhow chain.
pub(crate) async fn send_control_command(ctrl_path: &Path, cmd: &str) -> CtrlReply {
    let stream = match UnixStream::connect(ctrl_path).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "-O {}: connect to {} failed: {}",
                cmd,
                ctrl_path.display(),
                e
            );
            return CtrlReply::NoMaster;
        }
    };
    let (mut rx, mut tx) = stream.into_split();

    // Write the verb + newline so the master's existing frame
    // reader can parse the same way it parses a command line.
    let payload = format!("{}\n", cmd);
    if let Err(e) = write_cmd_frame(&mut tx, payload.as_bytes()).await {
        warn!("-O {}: write failed: {}", cmd, e);
        return CtrlReply::NoMaster;
    }

    // Read the master's reply frame.
    let reply = match read_cmd_frame(&mut rx).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            warn!("-O {}: master closed before reply", cmd);
            return CtrlReply::NoMaster;
        }
        Err(e) => {
            warn!("-O {}: read reply failed: {}", cmd, e);
            return CtrlReply::NoMaster;
        }
    };
    let reply_str = String::from_utf8_lossy(&reply);
    let reply_trim = reply_str.trim();
    if let Some(rest) = reply_trim.strip_prefix("ok ") {
        if let Ok(pid) = rest.trim().parse::<u32>() {
            return CtrlReply::Running(pid);
        }
    }
    if reply_trim == "bye" {
        return CtrlReply::Exiting;
    }
    warn!(
        "-O {}: master replied with unexpected payload: {:?}",
        cmd, reply_trim
    );
    CtrlReply::UnknownReply
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn has_no_fresh_auth_omits_passphrase() {
        // Passphrase flags refine an existing key, not a fresh
        // auth; they must NOT trigger the resume path. With only
        // passphrase / passphrase_file / control_path set, the
        // helper still returns true (no fresh auth -> resume is OK).
        let cli = Cli::parse_from([
            "passhrs",
            "--identity-passphrase",
            "anything",
            "-S",
            "/tmp/p.sock",
            "user@host",
            "true",
        ]);
        assert!(cli.passphrase.is_some());
        assert!(cli.passphrase_file.is_none());
        assert!(cli.identity_file.is_none());
        assert!(cli.password.is_none());
        assert!(cli.password_file.is_none());
        assert!(cli.control_path.is_some());
        assert!(has_no_fresh_auth(&cli));
    }

    #[test]
    fn has_no_fresh_auth_suppresses_when_identity_present() {
        let cli = Cli::parse_from(["passhrs", "-i", "/tmp/key", "user@host", "true"]);
        assert!(cli.identity_file.is_some());
        assert!(!has_no_fresh_auth(&cli));
    }

    #[test]
    fn has_no_fresh_auth_suppresses_when_password_present() {
        let cli = Cli::parse_from(["passhrs", "--password", "x", "user@host", "true"]);
        assert!(cli.password.is_some());
        assert!(!has_no_fresh_auth(&cli));
    }

    #[test]
    fn has_no_fresh_auth_suppresses_when_password_file_present() {
        let cli = Cli::parse_from(["passhrs", "--password-file", "/tmp/pw", "user@host", "true"]);
        assert!(cli.password_file.is_some());
        assert!(!has_no_fresh_auth(&cli));
    }

    #[test]
    fn has_no_fresh_auth_true_for_plain_invocation() {
        // Default `passhrs user@host echo hi` has no auth flags at
        // all. The resume predicate returns true so the client
        // tries the master UDS first.
        let cli = Cli::parse_from(["passhrs", "user@host", "echo", "hi"]);
        assert!(cli.identity_file.is_none());
        assert!(cli.password.is_none());
        assert!(cli.password_file.is_none());
        assert!(has_no_fresh_auth(&cli));
    }
}
