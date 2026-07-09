#![allow(
    clippy::zombie_processes,
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    dead_code
)]
//! One-stop native-OpenSSH integration tests.
//!
//! Replaces the previous Docker-based suite. The platform-specific
//! setup scripts under `tests/sshd/` start a real `sshd` on
//! `127.0.0.1:22222` with a known user account (USER + PASS below
//! are cfg-gated per platform — Linux=`runner`, macOS=`testuser`,
//! Windows=`runneradmin`, all with password `PassTest1234!`).
//! The tests exercise passhrs end-to-end against it.
//!
//! Because sshd is now native, the "remote" filesystem is the same as
//! the test process's local filesystem — tests can read/clean up
//! remote artifacts with `std::fs` directly instead of shelling out
//! to the server.
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const HOST: &str = "127.0.0.1";
const PORT: &str = "22222";
// Linux runner image ships a `runner` user whose password we reset
// to PASS via chpasswd. windows-2022 (since runner 2.305.0) ships
// `runneradmin`, and we reset its password via Set-LocalUser.
//
// macOS is special: the image's `runner` user has a randomly-
// generated password we can't reset (Sonoma+ secure-token lockout
// blocks both dscl . -passwd and sysadminctl -resetPasswordFor
// unless you supply the user's OLD password). Instead of trying
// to crack /etc/kcpassword and drive passwd via a pty, the macOS
// setup script creates a fresh `testuser` via sysadminctl -addUser
// — the official API for bootstrapping a user on Sonoma+ — which
// handles secure-token init and SACL ssh grants in one step.
#[cfg(target_os = "windows")]
const USER: &str = "runneradmin";
#[cfg(target_os = "macos")]
const USER: &str = "testuser";
#[cfg(target_os = "linux")]
const USER: &str = "runner";
const PASS: &str = "PassTest1234!";
const BIN: &str = "./target/release/passhrs";

/// Platform-appropriate temp directory for test artifacts. The "remote"
/// paths used in push/pull/rsync tests are rooted here so they resolve
/// correctly on Linux, macOS and Windows runners without relying on a
/// hard-coded `/tmp`.
///
/// Why not just `std::env::temp_dir()` everywhere: on macOS the runner
/// has `TMPDIR=/var/folders/.../T/` set per-user, so a path the test
/// creates as `runner` (UID A) is unwritable by `testuser` (UID B) when
/// sshd runs the SFTP child as UID B — the integration tests get
/// "Permission denied" trying to push to that path. The previous
/// hard-coded `/tmp/phr_*` worked because `/tmp` is world-writable on
/// every Unix (mode 1777). Pin Unix to `/tmp` and let Windows use
/// `%TEMP%` via `std::env::temp_dir()` (Windows has no `/tmp`, and
/// %TEMP% per-user is fine because the Windows sshd runs in the
/// runner's own user context — no cross-user SFTP problem).
fn tmp_root() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/tmp")
    }
    #[cfg(windows)]
    {
        std::env::temp_dir()
    }
}

/// Returns true when a real sshd is listening on `127.0.0.1:22222` and
/// accepts a TCP connection within a short timeout. Used as the
/// `#[ignore]` gate so tests skip cleanly when setup has not run.
fn sshd_ok() -> bool {
    use std::net::ToSocketAddrs;
    let addr = match format!("{}:{}", HOST, PORT).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return false,
        },
        Err(_) => return false,
    };
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
}

/// Bind to port 0, read back what the kernel picked, drop. Tests use
/// this for both ends of a -L / -R round-trip — the local listener
/// passhrs will sit at, and the "remote" target it forwards to. Both
/// are on the same loopback because the native sshd runs here too.
fn pick_unused_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind port 0")
        .local_addr()
        .expect("read local_addr")
        .port()
}

/// Capture a spawned child's stderr to a tempfile on disk, then dump it on
/// test failure. Why tempfile instead of a piped reader: passhrs spawns
/// the SSH session as a worker that, in the failure case, can outlive the
/// parent's `kill()`+`wait()`. A piped `read_to_string` then blocks
/// waiting for EOF that never arrives — which hangs the test binary
/// indefinitely and the CI runner times out after 6 hours. With a
/// tempfile, the file persists independent of process state, so Drop
/// can always read whatever passhrs wrote before death (or before being
/// leaked). The tempfile is unlinked in Drop.
struct StderrCapture {
    path: PathBuf,
}

impl StderrCapture {
    /// Build the unique path each invocation uses. Namespaced by PID
    /// plus a nanosecond timestamp so two concurrent invocations on the
    /// same process (cargo runs each test in its own process so this
    /// is belt-and-suspenders) cannot collide.
    fn make_path() -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("passhrs-stderr-{pid}-{nanos}.log"))
    }

    /// Convenience wrapper that opens the file, dups the fd for the
    /// child's stderr, and spawns the command. The returned capture
    /// owns the tempfile path; the caller still owns the `Child`.
    fn spawn(bin: &str, args: &[String]) -> (std::process::Child, Self) {
        let path = Self::make_path();
        let file = File::create(&path).expect("create stderr tempfile");
        let dup = file.try_clone().expect("dup stderr fd");
        // Drop the original handle — the dup is what the child holds,
        // and dropping `file` here does not close the dup. The dup is
        // moved into `Stdio::from`, which the child takes ownership of.
        drop(file);
        let child = Command::new(bin)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(dup))
            .spawn()
            .expect("spawn with stderr capture");
        (child, Self { path })
    }

    /// Read the captured stderr from disk. Safe to call any time —
    /// whether the child is alive, dead, or leaked.
    fn dump(&self) {
        match std::fs::read_to_string(&self.path) {
            Ok(s) if !s.trim().is_empty() => {
                eprintln!("--- passhrs stderr (captured during failed test) ---");
                eprintln!("{}", s);
                eprintln!("--- end passhrs stderr ---");
            }
            Ok(_) => {}
            Err(e) => eprintln!(
                "--- passhrs stderr: could not read {}: {} ---",
                self.path.display(),
                e
            ),
        }
    }

    /// Return the captured stderr as a `String`. Tests use this when
    /// they need to *assert on the contents*, not just dump them on
    /// failure. Empty if the file is missing or unreadable (which is
    /// the safe shape for `assert!(text.contains(...)`).
    fn read(&self) -> String {
        std::fs::read_to_string(&self.path).unwrap_or_default()
    }

    /// Consume self and dump the captured stderr. Use on the happy
    /// path when you still want to see passhrs stderr for debugging,
    /// or rely on the Drop impl (which suppresses when finish is
    /// called) by calling `capture.finish()`.
    #[allow(dead_code)]
    fn finish(self) {
        self.dump();
    }
}

impl Drop for StderrCapture {
    fn drop(&mut self) {
        // Print whatever passhrs wrote, even on panic. Safe: the
        // file is on disk, never blocked on a pipe.
        self.dump();
        // Best-effort cleanup; ignore errors (file may already be gone
        // or held open by a leaked worker — both fine).
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Suppress unused-import warnings for `Path` when no capture is taken
/// (keeps the import set self-documenting across the file).
#[allow(dead_code)]
fn _path_anchor(_: &Path) {}

/// Authentication arguments prepended to every `run_phr` call.
///
/// Linux + Windows keep the original `--password PASS` shape — the
/// native sshd is configured with `PasswordAuthentication yes` and the
/// runner's password is reset to PASS via chpasswd / Set-LocalUser.
///
/// macOS pivots to SSH key auth. Sonoma+ secure-token lockout blocks
/// every password-set API for a freshly-created user (dscl . -passwd,
/// sysadminctl -resetPasswordFor, passwd) from a non-interactive CI
/// script — see tests/sshd/setup-macos-brew-openssh.sh for the long
/// version. The brew-openssh setup script drops an ed25519 public key
/// into testuser's authorized_keys and exports the matching private
/// key path via the `PHR_TEST_KEY` env var (written to `$GITHUB_ENV`
/// so it survives across CI steps). When that's set, we use it;
/// otherwise we fall back to the password path.
fn auth_args() -> Vec<String> {
    // PHR_TEST_KEY may be set-but-empty if the provision step's
    // `>> $GITHUB_ENV` propagation is broken (e.g. a future
    // regression where sudo strips GITHUB_ENV). An empty `-i ""` is
    // rejected by clap with "a value is required for --key
    // <IDENTITY_FILE>" — which kills every test before it even
    // opens a TCP connection, hiding the real problem. Only emit
    // `-i` when we actually have a key path; otherwise fall
    // through to the password fallback. On macOS with
    // `PasswordAuthentication no` that fallback still fails — but
    // it fails with a clear sshd-side "Permission denied
    // (publickey)" instead of an opaque clap error in the test
    // binary's stderr.
    match std::env::var("PHR_TEST_KEY") {
        Ok(key) if !key.is_empty() => vec!["-i".to_string(), key],
        _ => vec!["--password".to_string(), PASS.to_string()],
    }
}

/// Prepend the test auth context (`-i PHR_TEST_KEY` on macOS when the
/// provision script wrote one to GITHUB_ENV, otherwise `--password PASS`)
/// to an arg vector — but only if the caller didn't already supply an
/// auth flag. Mirrors the smart-inject done inside `run_phr` for
/// tests that build a `Command` directly instead of going through
/// `run_phr` (the four spawned-process tests + the connect-timeout
/// test). Without this, those tests would call passhrs with no
/// `--password` and no `-i`, so passhrs would try key auth with an
/// unset key path (which fails silently) and fall back to password —
/// which macOS's `PasswordAuthentication no` sshd rejects outright.
/// On Linux/Windows the missing auth args would still work IF
/// chpasswd happened to succeed, but the path through auth_args()
/// keeps every test's auth context visible from one place.
fn prepend_auth_args(args: &mut Vec<String>) {
    let caller_has_auth = args
        .iter()
        .any(|a| a == "--password" || a == "-i" || a == "--password-file");
    if caller_has_auth {
        return;
    }
    let mut with_auth = auth_args();
    with_auth.append(args);
    *args = with_auth;
}

fn run_phr(args: &[&str]) -> (bool, String, String) {
    // Auth args used to live inline in every test's arg array
    // (`"--password", PASS,`). They moved here so a single env-var
    // flip (PHR_TEST_KEY) switches the entire test binary from
    // password auth (Linux/Windows) to key auth (macOS) without
    // touching 30 call sites.
    //
    // Smart-inject: if the caller already passed `--password` or
    // `-i` we don't double up. That covers the password-from-file
    // test, which legitimately needs `--password @/path/to/file`
    // on Linux/Windows (auth_args would otherwise inject a second
    // `--password PassTest1234!` first).
    let caller_has_auth = args.iter().any(|a| *a == "--password" || *a == "-i");
    let mut full_args: Vec<String> = Vec::new();
    if !caller_has_auth {
        full_args.extend(auth_args());
    }
    full_args.extend(args.iter().map(|s| s.to_string()));
    // DEBUG (caf58d8 follow-up): on macOS the DEBUG3 sshd log
    // showed the first few passhrs invocations landing
    // `for user <os-user> method password` at sshd even though
    // the test passed `testuser@127.0.0.1:22222` in args. That
    // meant either PHR_TEST_KEY didn't reach this process (so
    // auth_args() returned the password fallback) or russh is
    // doing something with $USER that overrides our resolved
    // user. Print the relevant env + final argv on the first
    // invocation only — the first run is the only one that
    // matters for diagnosis and dumping this for every test
    // would add ~200 lines to the panic output.
    static DEBUG_ONCE: std::sync::Once = std::sync::Once::new();
    DEBUG_ONCE.call_once(|| {
        eprintln!(
            "[tests/15 debug] PHR_TEST_KEY={:?} USER={:?} auth_args={:?} \
             caller_has_auth={} full_args={:?}",
            std::env::var("PHR_TEST_KEY").ok(),
            std::env::var("USER").ok(),
            auth_args(),
            caller_has_auth,
            full_args,
        );
    });
    let output = Command::new(BIN)
        .args(&full_args)
        .output()
        .expect("run passhrs");
    (
        output.status.success(),
        strip_ansi(&String::from_utf8_lossy(&output.stdout)),
        strip_ansi(&String::from_utf8_lossy(&output.stderr)),
    )
}

/// Strip CSI / OSC / single-character ANSI escape sequences from a
/// string. Windows' conhost + cmd.exe routinely inject sequences like
/// `\x1b[2J\x1b[m\x1b[H` (clear screen + reset + cursor home) at
/// the start of a channel-exec stdout, and `\x1b]0;...\x07\x1b[?25h`
/// (set window title + show cursor) at the end — captured as part of
/// the channel data when sshd forwards it to passhrs. Without
/// stripping, every stdout-asserting test on Windows fails with
/// the expected text wrapped in escape codes. Linux/macOS sshd
/// never emits these, so applying the helper unconditionally is a
/// no-op there. We strip both stdout and stderr so error messages
/// stay readable on a future regression.
///
/// Covers:
///   - CSI: ESC `[` <params 0x30-0x3f> <intermediate 0x20-0x2f>
///     <final 0x40-0x7e>   (most cursor/color/erase sequences)
///   - OSC: ESC `]` ... BEL (`\x07`) or ESC `\` (the canonical
///     terminator; some terminals also accept ESC `\` aka ST)
///   - DCS / PM / APC: ESC `P` / `^` / `_` ... ESC `\`
///   - Single-char escapes: ESC followed by one of `=` `>` `}`
///     (DECKPAM, DECKPNM, etc. — rare but harmless to strip)
///   - Lone ESC chars (defensive — some terminals emit them as
///     cancel sequences)
fn strip_ansi(s: &str) -> String {
    // Iterate by Unicode scalar value, not by byte: every ESC
    // introducer / CSI parameter byte / final byte / BEL is in
    // 0x00..=0x7f (i.e. 1-byte UTF-8), so char-level scanning
    // works for the escape grammar AND preserves multi-byte UTF-8
    // in the passthrough (the previous byte-level implementation
    // pushed each 0x80..=0xff byte as a separate char, mangling
    // sequences like '中' into several replacement codepoints).
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // ESC: dispatch on the introducer char.
        match chars.next() {
            Some('[') => {
                // CSI: ESC [ <params 0x30-0x3f> <intermediate 0x20-0x2f>
                // <final 0x40-0x7e>. We don't need to validate the
                // intermediate classes — anything that's not the
                // final byte yet is part of the sequence.
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if ('\u{40}'..='\u{7e}').contains(&nc) {
                        break;
                    }
                }
            }
            Some(']') | Some('P') | Some('^') | Some('_') => {
                // OSC / DCS / PM / APC: terminator is BEL (`\u{07}`)
                // or ST (ESC `\`). We must consume both bytes of the
                // ST terminator so the inner ESC doesn't re-trigger
                // the outer match arm.
                while let Some(nc) = chars.next() {
                    if nc == '\u{07}' {
                        break;
                    }
                    if nc == '\u{1b}' && chars.next() == Some('\\') {
                        break;
                    }
                }
            }
            Some('=') | Some('>') | Some('}') => {
                // DECKPAM / DECKPNM / etc. — single-char escapes,
                // already consumed.
            }
            _ => {
                // Unknown introducer — drop just the lone ESC and
                // let the outer loop resume from the next char.
            }
        }
    }
    out
}

#[cfg(test)]
mod strip_ansi_tests {
    use super::strip_ansi;

    #[test]
    fn passes_through_plain_text() {
        assert_eq!(strip_ansi("hello world"), "hello world");
        assert_eq!(strip_ansi("hello_phr\n"), "hello_phr\n");
        assert_eq!(strip_ansi(""), "");
    }

    #[test]
    fn strips_csi_sequences() {
        // clear screen, reset attributes, cursor home — the trio
        // conhost emits at the start of every cmd.exe exec channel.
        assert_eq!(
            strip_ansi("\x1b[2J\x1b[m\x1b[Hhello_phr\r\n"),
            "hello_phr\r\n"
        );
        // show/hide cursor.
        assert_eq!(strip_ansi("\x1b[?25lsecret\x1b[?25h"), "secret");
        // SGR colour (no effect on stripping logic).
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
        // Cursor position with parameter bytes.
        assert_eq!(strip_ansi("\x1b[10;20Hrow=10"), "row=10");
    }

    #[test]
    fn strips_osc_sequences() {
        // OSC 0 ; <title> BEL — what conhost emits at the end of a
        // cmd.exe session to set the window title.
        assert_eq!(
            strip_ansi("hello\x1b]0;C:\\Windows\\system32\\conhost.exe\x07end"),
            "helloend",
        );
        // OSC terminated by ST (ESC \) instead of BEL.
        assert_eq!(strip_ansi("a\x1b]2;title\x1b\\b"), "ab");
    }

    #[test]
    fn strips_windows_conhost_payload() {
        // The exact stdout shape we saw on 28706151879's failing
        // test_basic_command_exec on Windows:
        let raw = "\x1b[2J\x1b[m\x1b[Hhello_phr\r\n\x1b]0;C:\\Windows\\system32\\conhost.exe\x07\x1b[?25h";
        assert_eq!(strip_ansi(raw), "hello_phr\r\n");
    }

    #[test]
    fn preserves_non_escape_text() {
        // Multi-byte UTF-8 must round-trip; strip_ansi only ever
        // drops bytes starting with 0x1b, never touches the
        // continuation bytes of a multi-byte char.
        let s = "中文测试 🎉";
        assert_eq!(strip_ansi(s), s);
        // Bytes that happen to be in the CSI introducer range
        // (0x30..=0x3f) but are NOT preceded by ESC must pass
        // through. e.g. '?' (0x3f) inside a URL.
        assert_eq!(strip_ansi("http://x?y=1"), "http://x?y=1");
    }

    #[test]
    fn handles_truncated_escape() {
        // Lone ESC at end of input — must not panic, must drop.
        assert_eq!(strip_ansi("abc\x1b"), "abc");
        // ESC + introducer with no body (CSI at EOF).
        assert_eq!(strip_ansi("abc\x1b["), "abc");
        // ESC + introducer + garbage (unknown introducer).
        assert_eq!(strip_ansi("abc\x1bZx"), "abcx");
    }
}

fn dest() -> String {
    format!("{}@{}", USER, HOST)
}

// ======================================================================
// 基本连接测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_basic_command_exec() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "echo",
        "hello_phr",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "exec failed: {}", stderr);
    assert_eq!(stdout.trim(), "hello_phr", "stdout: {}", stdout);
}

// ======================================================================
// SFTP push / pull 集成测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_push_pull_file() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let local = format!("{}/phr_test_push.txt", tmp_root().display());
    let remote = format!("{}/phr_remote_push.txt", tmp_root().display());
    let local2 = format!("{}/phr_test_pulled.txt", tmp_root().display());
    std::fs::write(&local, b"hello sftp push").unwrap();

    let spec1 = format!("{}:{}", local, remote);
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "--push",
        &spec1,
        &d,
        "id",
    ];
    let (ok, _, stderr) = run_phr(&a);
    assert!(ok, "push failed: {}", stderr);

    let out = std::fs::read_to_string(&remote).unwrap_or_default();
    assert!(!out.is_empty(), "remote file not found");
    assert!(out.contains("hello sftp push"), "content mismatch");

    let spec2 = format!("{}:{}", remote, local2);
    let a2 = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "--pull",
        &spec2,
        &d,
        "id",
    ];
    let (ok3, _, stderr3) = run_phr(&a2);
    assert!(ok3, "pull failed: {}", stderr3);
    let pulled = std::fs::read_to_string(&local2).unwrap_or_default();
    assert!(
        pulled.contains("hello sftp push"),
        "pulled content mismatch"
    );
    let _ = std::fs::remove_file(&local);
    let _ = std::fs::remove_file(&local2);
    let _ = std::fs::remove_file(&remote);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_push_dir() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let dir = format!("{}/phr_test_pushdir", tmp_root().display());
    let remote_dir = format!("{}/phr_remote_dir", tmp_root().display());
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(format!("{}/a.txt", dir), b"file a").unwrap();
    let _ = std::fs::create_dir_all(format!("{}/sub", dir));
    std::fs::write(format!("{}/sub/c.txt", dir), b"file c").unwrap();
    let _ = std::fs::remove_dir_all(&remote_dir);

    let spec = format!("{}/:{}", dir, remote_dir);
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "--push",
        &spec,
        &d,
        "id",
    ];
    let (ok, _, stderr) = run_phr(&a);
    assert!(ok, "push dir failed: {}", stderr);
    let entries: Vec<String> = std::fs::read_dir(format!("{}/sub", remote_dir))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default();
    assert!(!entries.is_empty(), "remote subdir missing");
    assert!(
        entries.iter().any(|n| n == "c.txt"),
        "subdir content: {:?}",
        entries
    );
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(remote_dir);
}

// ======================================================================
// --rsync 集成测试
// ======================================================================

fn setup_rsync_remote(remote_dir: &str) {
    let _ = std::fs::remove_dir_all(remote_dir);
    std::fs::create_dir_all(remote_dir).expect("create remote rsync dir");
    // On native-sshd CI the remote dir is created by the runner user (the
    // user that invokes cargo test), but passhrs authenticates as testuser
    // over SFTP. testuser therefore cannot create files inside a
    // runner-owned 0755 directory — `sftp.create(...)` returns
    // Permission denied and the rsync test fails. (The container-based
    // predecessor made the SFTP user the same UID as the test runner, so
    // the dir was always writable and this never surfaced.) Force the
    // remote dir world-writable so the cross-user SFTP write succeeds on
    // every platform. No chown: chown would need sudo on Linux and a
    // privileged helper on Windows; chmod is portable and the test dir
    // is short-lived inside /tmp.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(remote_dir, std::fs::Permissions::from_mode(0o777))
            .expect("chmod 0o777 remote rsync dir");
    }
    #[cfg(windows)]
    {
        // Windows doesn't honour Unix mode bits; instead, ensure the
        // directory ACL grants Everyone write access. Use std-only APIs
        // so this works from the test binary without Win32 FFI.
        let mut perms = std::fs::metadata(remote_dir)
            .expect("stat remote rsync dir")
            .permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(remote_dir, perms).expect("clear readonly on remote rsync dir");
    }
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_rsync_upload_basic() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let dir = format!("{}/phr_rsync_src", tmp_root().display());
    let remote_dir = format!("{}/phr_rsync_dst", tmp_root().display());
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(format!("{}/f1.txt", dir), b"rsync test file 1").unwrap();
    std::fs::write(format!("{}/f2.txt", dir), b"rsync test file 2").unwrap();
    setup_rsync_remote(remote_dir.as_str());

    let spec = format!("{}/:{}/", dir, remote_dir);
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "--rsync",
        &spec,
        &d,
        "id",
    ];
    let (ok, _, stderr) = run_phr(&a);
    assert!(ok, "rsync upload failed: {}", stderr);
    for f in ["f1.txt", "f2.txt"] {
        let p = format!("{}/{}", remote_dir, f);
        assert!(
            std::path::Path::new(&p).exists(),
            "remote file {} missing",
            f
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&remote_dir);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_rsync_delta() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let remote_dir = format!("{}/phr_delta_dst", tmp_root().display());
    let local_dir = format!("{}/phr_delta_src", tmp_root().display());
    setup_rsync_remote(remote_dir.as_str());
    // Seed the remote file. The native sshd host means we can write
    // directly and chmod world-writable so testuser can overwrite it
    // during the rsync delta test.
    let remote_file = format!("{}/file.txt", remote_dir);
    std::fs::write(&remote_file, b"ORIGINAL_CONTENT").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&remote_file, std::fs::Permissions::from_mode(0o666));
    }
    let _ = std::fs::create_dir_all(&local_dir);
    std::fs::write(format!("{}/file.txt", local_dir), b"MODIFIED_CONTENT").unwrap();

    let spec = format!("{}/:{}/", local_dir, remote_dir);
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "--rsync",
        &spec,
        &d,
        "id",
    ];
    let (ok, _, stderr) = run_phr(&a);
    assert!(ok, "rsync delta failed: {}", stderr);
    let _ = std::fs::remove_dir_all(&local_dir);
    let _ = std::fs::remove_dir_all(&remote_dir);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_rsync_with_exclude() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let dir = format!("{}/phr_rsync_excl", tmp_root().display());
    let remote_dir = format!("{}/phr_rsync_excl_dst", tmp_root().display());
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(format!("{}/keep.txt", dir), b"keep me").unwrap();
    std::fs::write(format!("{}/ignore.txt", dir), b"ignore me").unwrap();
    setup_rsync_remote(remote_dir.as_str());

    let spec = format!("{}/:{}/", dir, remote_dir);
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "--rsync",
        &spec,
        "--rsync-opt",
        "exclude=ignore.txt",
        &d,
        "id",
    ];
    let (ok, _, stderr) = run_phr(&a);
    assert!(ok, "rsync exclude failed: {}", stderr);
    let keep = format!("{}/keep.txt", remote_dir);
    let ignore = format!("{}/ignore.txt", remote_dir);
    assert!(std::path::Path::new(&keep).exists(), "keep.txt missing");
    assert!(
        !std::path::Path::new(&ignore).exists(),
        "ignore.txt should be excluded"
    );
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(remote_dir);
}

// ======================================================================
// 环境变量测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_exec_env_remote() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // On Windows sshd defaults to cmd.exe (which has no `export`
    // builtin and no `$VAR` substitution), so pass `--shell cmd`
    // and reference the variable via `%VAR%` (which the rewrite
    // for cmd mode also handles internally, but passing it through
    // is clearer and tests the public surface). On Unix sh-mode is
    // the default; `$VAR` is the native syntax.
    let shell_flag = if cfg!(target_os = "windows") {
        Some("--shell")
    } else {
        None
    };
    let shell_value = if cfg!(target_os = "windows") {
        "cmd"
    } else {
        "sh"
    };
    let var_ref = if cfg!(target_os = "windows") {
        "%PHR_TEST_VAR%"
    } else {
        "$PHR_TEST_VAR"
    };
    let mut a: Vec<&str> = vec![
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
    ];
    if let Some(flag) = shell_flag {
        a.push(flag);
        a.push(shell_value);
    }
    a.extend_from_slice(&[
        "--exec-env",
        "PHR_TEST_VAR=hello_from_env",
        &d,
        "echo",
        var_ref,
    ]);
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "exec-env failed: {}", stderr);
    assert_eq!(stdout.trim(), "hello_from_env", "stdout: {}", stdout);
}

// ======================================================================
// 密码从文件读取集成测试
// ======================================================================

#[cfg(not(target_os = "macos"))]
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_password_from_file_integration() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let pw_path = format!("{}/phr_test_pw_file.txt", tmp_root().display());
    std::fs::write(&pw_path, PASS).unwrap();
    let pw_file = format!("@{}", pw_path);
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        &pw_file,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "echo",
        "pw_file_ok",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    let _ = std::fs::remove_file(pw_path);
    assert!(ok, "password from file failed: {}", stderr);
    assert_eq!(stdout.trim(), "pw_file_ok", "stdout: {}", stdout);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_password_file_flag_integration() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let pw_path = format!("{}/phr_test_pw_flag.txt", tmp_root().display());
    std::fs::write(&pw_path, PASS).unwrap();
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password-file",
        &pw_path,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "echo",
        "pw_flag_ok",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    let _ = std::fs::remove_file(pw_path);
    assert!(ok, "password-file flag failed: {}", stderr);
    assert_eq!(stdout.trim(), "pw_flag_ok", "stdout: {}", stdout);
}

// ======================================================================
// 超时测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_connect_timeout_integration() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = format!("{}@10.255.255.1", USER);
    // Prepend auth args so passhrs parses the same argv shape it
    // would see in a real call. The connection to 10.255.255.1 is
    // intentionally unreachable; we only assert that passhrs times
    // out cleanly without panicking. Without the auth args,
    // passhrs would still try to load a key from "" and fall back
    // to password — on macOS with PasswordAuthentication no that
    // fallback would also fail (test would still pass because we
    // only check non-zero exit + no panic), but it would emit a
    // confusing auth-related warning before the connect timeout
    // that masks the actual timeout.
    let mut args: Vec<String> = vec![
        "--connect-timeout".to_string(),
        "3".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        d,
        "echo".to_string(),
        "should_not_reach".to_string(),
    ];
    prepend_auth_args(&mut args);
    let out = Command::new(BIN)
        .args(&args)
        .output()
        .expect("timeout test");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "should have failed");
    assert!(!stderr.contains("thread"), "should not panic: {}", stderr);
}

// ======================================================================
// User-facing error format (Issue #32).
//
// `test_connect_timeout_integration` above only checks "did not panic".
// This test pins the new user-facing error shape introduced by the
// `format_user_error` refactor in src/main.rs — the default path
// (no -v/-vv) prints a one-line `error: <kind> (<context>)` instead
// of the previous anyhow `{:#?}` dump.
//
// We invoke passhrs against 10.255.255.1 (TEST-NET-1, always
// unreachable) with --connect-timeout 2 so the test finishes in
// ~2 s on every matrix row. The expected shape:
//
//   - exit non-zero
//   - stderr starts with "error: " (the new prefix; the old
//     `{:#?}` shape started with the variant name like "Error")
//   - stderr does NOT contain "context:" or "source:" — those
//     are anyhow-Debug artefacts that the new shape suppresses
//   - stderr contains "rerun with -vv" only on the unknown-error
//     fallback path; the connection-failed bucket skips the hint
//     because the user knows what to do (check network/host)
//
// We intentionally do NOT assert on the bucket name. A future
// refinement (e.g. splitting "connection failed" into
// "dns failed" + "tcp failed") would otherwise force this
// test to track the rename.
// ======================================================================
#[test]
fn test_user_facing_error_format() {
    // 10.255.255.1 is TEST-NET-1, guaranteed unreachable from any
    // CI runner (no route to it). The test is NOT gated by sshd_ok()
    // because it doesn't need a real sshd.
    let mut args: Vec<String> = vec![
        "--connect-timeout".to_string(),
        "2".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        format!("{}@10.255.255.1", USER),
        "echo".to_string(),
        "should_not_reach".to_string(),
    ];
    prepend_auth_args(&mut args);
    let out = Command::new(BIN)
        .args(&args)
        .output()
        .expect("user-facing error format test");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "should have failed");
    // The new shape produces a "passhrs: " one-liner SOMEWHERE in
    // stderr. The CI workflow exports RUST_LOG=passhrs=debug, so
    // stderr may also contain INFO/DEBUG log lines from the
    // connection attempt — those are fine, we only care that the
    // classified error is present and the Debug-dump artefacts
    // are not.
    assert!(
        stderr.contains("passhrs: "),
        "stderr should contain the 'passhrs: ' one-liner from the new \
         format_user_error shape, got: {}",
        stderr
    );
    // The new shape does NOT contain the anyhow Debug artefacts.
    // The verbose fallback ({:#?}) would emit "context: " and
    // "source: " — those would be present if the new shape was
    // bypassed by the -v/-vv branch (it shouldn't be: we did NOT
    // pass -v or --debug-all here).
    assert!(
        !stderr.contains("context: "),
        "stderr contains anyhow Debug 'context:' field — the new \
         format_user_error path was bypassed (likely fell back to \
         {{:#?}}). stderr: {}",
        stderr
    );
    assert!(
        !stderr.contains("source: "),
        "stderr contains anyhow Debug 'source:' field — the new \
         format_user_error path was bypassed. stderr: {}",
        stderr
    );
}

// ======================================================================
// `--timeout` mid-flight e2e (Issue #22).
//
// `test_connect_timeout_integration` above covers the
// pre-handshake case (3 s, blackhole IP, no auth round-trip). This
// block covers the inactivity-after-handshake case: a live session
// that just sits there with no I/O. `--timeout <s>` wires through
// `src/main.rs:303-305` -> `russh::client::Config::inactivity_timeout`,
// and russh owns the actual firing. We can't assert on the exact
// stderr wording (russh's wording shifts between releases), so the
// signal is "did the timer fire at all" via wall-clock bounds plus
// the exit-status semantic passhrs gives us.
//
// `--timeout 3` + remote `sleep 30` is the bare-firing case: the
// channel goes idle at session-start (sleep is silent), the 3 s
// window elapses, russh tears the session, passhrs exits non-zero.
// We assert it happened in [2 s, 15 s) — the upper bound absorbs the
// handshake/process-start cost and CI jitter, the lower bound
// ensures we didn't fire before the user-configured window.
//
// `--timeout 5` + `-o ServerAliveInterval=2` + remote `sleep 8` is
// the kept-alive case: 8 s > 5 s, so without keepalive this would
// fail the same way as the bare case. With keepalive (`src/main.rs:
// 266-275` + 307-308 wire `-o ServerAliveInterval=2` into
// `config.keepalive_interval`), russh sends SSH transport keepalive
// every 2 s, which resets the inactivity window. We assert the
// 8 s sleep completed (success exit, took >= 5 s so the timer
// didn't fire, took < 20 s so we left the test budget).
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_inactivity_timeout_mid_flight() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }
    let d = format!("{}@{}", USER, HOST);
    // mirror `test_connect_timeout_integration`'s auth smart-inject
    // shape so the same argv reaches passhrs as a real call.
    let mut args: Vec<String> = vec![
        "--timeout".to_string(),
        "3".to_string(),
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        d,
        "sleep".to_string(),
        "30".to_string(),
    ];
    prepend_auth_args(&mut args);
    let start = Instant::now();
    let out = Command::new(BIN)
        .args(&args)
        .output()
        .expect("inactivity timeout");
    let elapsed = start.elapsed();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("thread"), "should not panic: {}", stderr);
    // Wall-clock is the only reliable signal here: passhrs reports
    // `Session exit code 0` (not non-zero) when the inactivity
    // timer closes the channel and sshd then reports success for
    // the killed child -- observed on run 28911418850 across
    // both ubuntu-24.04 (~3.003s elapsed) and macos-14
    // (~3.016s elapsed). The exit code was 0 in both. We rely
    // on the gap between 3s and 30s being unambiguous.
    //
    // Lower bound: must NOT fire before the configured 3 s window —
    // catches a regression where passhrs sets
    // `config.inactivity_timeout = Some(0)` or accidentally divides
    // it by 10 (a hypothetical unit confusion).
    //
    // Upper bound: must NOT run the full 30 s sleep — catches a
    // regression where `config.inactivity_timeout` is never set
    // (timer never fires) or the value is silently multiplied.
    assert!(
        elapsed >= Duration::from_secs(2),
        "fired too early (took {:?}, expected >= 2s)",
        elapsed
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "did not fire within budget (took {:?}, expected < 15s) — \
         inactivity_timeout may not be wired to russh config",
        elapsed
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 + ServerAliveInterval honored end-to-end"]
fn test_inactivity_timeout_kept_alive() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }
    // sleep 8 > --timeout 5. Without keepalive the bare timer would
    // fire at ~5 s. With `ServerAliveInterval=2` the inactivity
    // window resets every 2 s so the 8 s sleep completes.
    let d = format!("{}@{}", USER, HOST);
    let mut args: Vec<String> = vec![
        "--timeout".to_string(),
        "5".to_string(),
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=2".to_string(),
        d,
        "sleep".to_string(),
        "8".to_string(),
    ];
    prepend_auth_args(&mut args);
    let start = Instant::now();
    let out = Command::new(BIN)
        .args(&args)
        .output()
        .expect("kept alive timeout");
    let elapsed = start.elapsed();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "should succeed with keepalive\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    // Took at least the sleep duration (5 s lower bound ensures the
    // timer did not fire prematurely). The 20 s upper bound leaves
    // ~12 s of slack for CI jitter; a regression that hangs the
    // session entirely would take much longer than that.
    assert!(
        elapsed >= Duration::from_secs(5),
        "completed too fast ({:?}) — keepalive may not be in effect",
        elapsed
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "took too long ({:?}) — keepalive or session error path",
        elapsed
    );
}

// ======================================================================
// `-S <path>` ControlPath: master / resume (Issue #29).
//
// Pins the positive implementation: passhrs implements a Unix-only,
// passhrs-native master / resume protocol over a UDS at `-S <path>`.
// This is NOT wire-compatible with OpenSSH's control protocol (a
// different feature, not on the roadmap).
//
// Two tests cover the surface:
//   * test_control_socket_resume_no_auth — a master holds the SSH
//     session open; a follow-up invocation with the same `-S` path and
//     NO auth flags reuses it. Asserts exit code 0 + `from_resume` on
//     stdout. This is the headline CI signal that the resume path is
//     not a silent fall-through.
//   * test_control_socket_master_kills_clean_socket — when the master
//     dies (SIGKILL), the socket file is removed by the
//     `ControlSocketGuard::Drop` so a follow-up `-S` is not blocked
//     by a stale file.
//
// Both are `#[cfg(unix)]` because Windows uses named pipes — separate
// follow-up issue.
// ======================================================================

#[cfg(unix)]
fn wait_for_uds(path: &str, max_wait: Duration) -> bool {
    // 5×100 ms bounded retry: cheap and fast on the happy path
    // (the master binds during the SSH handshake, which is
    // 100-300 ms in the CI sandbox). On a slow CI spike, `max_wait`
    // can grow without changing the test's correctness.
    let step = Duration::from_millis(100);
    let mut elapsed = Duration::ZERO;
    while elapsed < max_wait {
        if std::path::Path::new(path).exists() {
            return true;
        }
        thread::sleep(step);
        elapsed += step;
    }
    false
}

#[cfg(unix)]
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222"]
fn test_control_socket_resume_no_auth() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }

    let sock_path = format!("{}/phr-29-ctrl.sock", tmp_root().display());
    // Belt-and-suspenders: clean up any leftover from a prior aborted
    // run so the master's bind doesn't EADDRINUSE.
    let _ = std::fs::remove_file(&sock_path);

    let d = format!("{}@{}", USER, HOST);

    // Pass 1: master invocation. `-N` means "no command" — passhrs
    // binds the UDS, hands control to the accept loop, and idles.
    // Auth flags are passed (the master is the auth-bearing side;
    // the resume is).
    let mut master_args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-S".to_string(),
        sock_path.clone(),
        "-N".to_string(),
        d.clone(),
    ];
    prepend_auth_args(&mut master_args);
    let mut master = Command::new(BIN)
        .args(&master_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn master with -S");

    // Wait for the UDS to appear. Fail the test with a useful
    // diagnostic if the master hasn't bound it in time.
    let appeared = wait_for_uds(&sock_path, Duration::from_secs(5));
    assert!(
        appeared,
        "master never bound UDS at {} within 5s — passhrs -S master mode is not running",
        sock_path
    );

    // Pass 2: resume invocation. NO auth flags here — the resume
    // path must connect to the master UDS and reuse its auth
    // context. If the resume early-exit is missing, fall through
    // would mean passhrs tries to TCP-connect to sshd with no creds
    // and sshd rejects "Permission denied" → exit 1.
    let start = Instant::now();
    let out = Command::new(BIN)
        .args([
            "-p",
            PORT,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-S",
            &sock_path,
            &d,
            "echo",
            "from_resume",
        ])
        .output()
        .expect("spawn resume");
    let elapsed = start.elapsed();
    assert!(
        out.status.success(),
        "resume invocation failed (status={:?}, elapsed={:?}). stderr: {}",
        out.status,
        elapsed,
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim() == "from_resume",
        "resume returned wrong stdout: {:?} (expected `from_resume`)",
        stdout,
    );
    // Speed check: a successful resume should be < 2 s end-to-end.
    // Without resume, a full handshake + auth would dominate the
    // budget. This isn't strict (CI spikes happen) but it would
    // catch a regression to a slow path.
    assert!(
        elapsed < Duration::from_secs(5),
        "resume took too long ({:?}) — likely fell through to a fresh SSH handshake",
        elapsed,
    );

    // Sanity-check the protocol framing by hand, independent of
    // passhrs's own resume path: open the UDS, write a command
    // frame, read until we see the done tag, decode the exit code.
    let mut s = UnixStream::connect(&sock_path).expect("manual UDS connect");
    let cmd = b"echo protocol_ok\n";
    let mut header = [0u8; 4];
    header.copy_from_slice(&(cmd.len() as u32).to_be_bytes());
    s.write_all(&header).unwrap();
    s.write_all(cmd).unwrap();
    // Read frames: stdout=1, stderr=2, done=0. Loop until done.
    let mut saw_protocol_ok = false;
    let mut exit_code: Option<u8> = None;
    while exit_code.is_none() {
        let mut h = [0u8; 5];
        if s.read_exact(&mut h).is_err() {
            panic!("master closed UDS before done frame");
        }
        let len = u32::from_be_bytes(h[0..4].try_into().unwrap()) as usize;
        let tag = h[4];
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).unwrap();
        match tag {
            1 => {
                if payload == b"protocol_ok\n" {
                    saw_protocol_ok = true;
                }
            }
            0 => {
                exit_code = Some(payload[0]);
            }
            2 => {} // ignore stderr
            other => panic!("unknown tag {} from master", other),
        }
    }
    assert!(
        saw_protocol_ok,
        "stdout frame did not contain `protocol_ok`"
    );
    assert_eq!(exit_code, Some(0), "exit code frame mismatch");

    // Cleanup: kill the master, verify the UDS file is gone
    // (ControlSocketGuard::Drop removes it).
    let _ = master.kill();
    let _ = master.wait();
    let drop_window = Duration::from_secs(2);
    let drop_start = Instant::now();
    while drop_start.elapsed() < drop_window {
        if !std::path::Path::new(&sock_path).exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(&sock_path);
}

#[cfg(unix)]
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222"]
fn test_control_socket_master_kills_clean_socket() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }

    let sock_path = format!("{}/phr-29-ctrl-clean.sock", tmp_root().display());
    let _ = std::fs::remove_file(&sock_path);

    let d = format!("{}@{}", USER, HOST);

    let mut master_args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-S".to_string(),
        sock_path.clone(),
        "-N".to_string(),
        d,
    ];
    prepend_auth_args(&mut master_args);
    let mut master = Command::new(BIN)
        .args(&master_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn master");

    let appeared = wait_for_uds(&sock_path, Duration::from_secs(5));
    assert!(appeared, "master never bound UDS at {}", sock_path);

    // Send SIGTERM. tokio's signal handlers (ctrl_c for SIGINT;
    // signal::unix::SignalKind::terminate for SIGTERM) wake the
    // accept loop, run_master returns Ok(()), the
    // `ControlSocketGuard` drops, and the UDS file is removed.
    //
    // We do NOT use `child.kill()` here: that sends SIGKILL, which
    // bypasses Rust destructors entirely and leaves the UDS file
    // on disk. That's expected behavior — the next master invocation
    // cleans a stale file at bind time via `bind_listener`'s
    // `remove_file` fallback — but it's not what we want to test.
    // SIGTERM is the realistic "user wants the master to shut down"
    // signal (and the one the integration-test cleanup step uses).
    #[cfg(unix)]
    {
        let pid = master.id();
        // libc::kill(pid, SIGTERM) — keep the dependency surface
        // minimal by going through the C symbol std already pulls
        // in. (avoids adding a `libc` dep just for one signal).
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        const SIGTERM: i32 = 15;
        // If kill() returns 0, the signal was delivered and the
        // master will start unwinding. Wait reaps.
        let _ = unsafe { kill(pid as i32, SIGTERM) };
        let _ = master.wait();
        // Belt-and-suspenders: SIGKILL fallback if SIGTERM didn't
        // unstick the process within a short window. Without this
        // the test would hang forever on a master that ignored
        // SIGTERM (e.g. a regression that broke the SIGTERM wiring
        // in src/control.rs).
        if std::path::Path::new(&sock_path).exists() {
            let _ = master.kill();
            let _ = master.wait();
        }
    }

    // Bounded wait for the UDS file to disappear. 2 s is generous;
    // Drop runs synchronously during process unwind.
    let drop_window = Duration::from_secs(2);
    let drop_start = Instant::now();
    let mut gone = false;
    while drop_start.elapsed() < drop_window {
        if !std::path::Path::new(&sock_path).exists() {
            gone = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        gone,
        "UDS file at {} still present 2 s after master SIGTERM — \
         ControlSocketGuard::Drop is not removing the file",
        sock_path,
    );
    // Belt-and-suspenders.
    let _ = std::fs::remove_file(&sock_path);
}

// ======================================================================
// `-A` AgentForwarding: positive e2e (Issue #23).
//
// Pins that passhrs implements real SSH agent forwarding via the
// OpenSSH extension `auth-agent-req@openssh.com` +
// `auth-agent@openssh.com`. With `-A` set and a local `SSH_AUTH_SOCK`
// provided, passhrs must:
//   1. Send `auth-agent-req@openssh.com` on the session channel
//      (russh's `Channel::agent_forward`, wraps a CHANNEL_REQUEST
//      with that exact name).
//   2. Accept `auth-agent@openssh.com` channel-opens back from sshd
//      (russh's `Handler::server_channel_open_agent_forward`, ours
//      dials the local socket and pumps bytes both ways).
//
// The lightest signal this is working: the remote shell sees a
// non-empty `$SSH_AUTH_SOCK` that sshd set on the user's session.
// Without -A (or with -A but broken), the variable is unset.
// We deliberately set a unique LOCAL marker path so we can also
// assert the forwarded socket is NOT the local path (which would
// only happen if passhrs leaked the local path verbatim — wrong).
//
// We deliberately do NOT pass `--exec-env SSH_AUTH_SOCK=...` —
// that would set SSH_AUTH_SOCK regardless of -A, hiding the signal.
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 + sshd configured to allow agent forwarding (AllowAgentForwarding yes, the default)"]
fn test_agent_forward_propagates_ssh_auth_sock() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }

    // Local path we pass into passhrs's environment. passhrs will
    // dial it every time sshd opens an auth-agent channel back at
    // us. It must be a Unix socket path on Unix; a zero-byte file
    // is fine (connect_agent_stream in src/ssh.rs does not stat it
    // up-front — it just tries to open the path).
    let local_marker = format!("{}/phr-23-fake-agent.sock", tmp_root().display());
    let _ = std::fs::remove_file(&local_marker);
    let _ = std::fs::write(&local_marker, b"");

    let d = dest();
    // cmd.exe on Windows expands `%VAR%`; sh on Unix expands `$VAR`.
    // The `--shell` flag mirrors `test_exec_env_remote` so passhrs
    // emits the right shell syntax on each platform.
    let (shell_args, var_ref): (&[&str], &str) = if cfg!(target_os = "windows") {
        (&["--shell", "cmd"], "%SSH_AUTH_SOCK%")
    } else {
        (&[], "$SSH_AUTH_SOCK")
    };

    let mut a: Vec<&str> = vec![
        "-p",
        PORT,
        "-A",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
    ];
    a.extend_from_slice(shell_args);
    a.push(d.as_str());
    a.push("echo");
    a.push(var_ref);

    // Pass the marker as the LOCAL `SSH_AUTH_SOCK` only.
    let envs = [("SSH_AUTH_SOCK", local_marker.as_str())];
    let (ok, stdout, stderr) = run_phr_with_env(&a, &envs);

    let _ = std::fs::remove_file(&local_marker);

    assert!(!stderr.contains("thread"), "should not panic: {}", stderr);
    assert!(
        ok,
        "session did not succeed:\nstdout: {}\nstderr: {}",
        stdout, stderr
    );

    // Strip the trailing newline `echo $VAR` always emits, so a
    // trailing-CR-tolerant comparison works.
    let remote_sock = stdout.trim();

    // The remote $SSH_AUTH_SOCK must be SET (i.e. non-empty). An
    // empty string implies passhrs didn't send
    // auth-agent-req@openssh.com — sshd's PAM-layer ApplyAgent
    // hook would then have no socket to wire to the user's shell.
    assert!(
        !remote_sock.is_empty(),
        "remote $SSH_AUTH_SOCK was unset — passhrs did not implement \
         agent forwarding (the auth-agent-req@openssh.com channel \
         request was not sent on the session channel, so sshd never \
         allocated a per-session agent socket for the user's shell). \
         stdout: {}\nstderr: {}",
        stdout,
        stderr,
    );

    // The remote SSH_AUTH_SOCK must not equal the local marker
    // (a regression that leaked the local path verbatim would
    // produce that result and corrupt agent operations on the
    // remote).
    assert_ne!(
        remote_sock, local_marker,
        "remote $SSH_AUTH_SOCK unexpectedly equals the LOCAL marker \
         — passhrs should be forwarding via sshd (which allocates a \
         per-session path), not leaking the local path verbatim. \
         local: {}\nstdout: {}\nstderr: {}",
        local_marker, stdout, stderr,
    );

    // A spatial sanity check: the forwarded path lives under sshd's
    // agent tmpdir, typically /tmp/agent.<ppid>/<rand> on Linux and
    // /var/folders/.../T/agent.<rand> on macOS. Pinning the exact
    // location is brittle across sshd versions, but a substring
    // match for "agent" catches the OpenSSH-allocation-shape.
    // On Win32-OpenSSH sshd-exec interaction is more involved and
    // the remote `$SSH_AUTH_SOCK` may be empty even when -A works
    // (cmd.exe's `%SSH_AUTH_SOCK%` is empty if the cmd parser
    // resolved it before the env was inherited), so we skip this
    // check on Windows.
    #[cfg(not(target_os = "windows"))]
    assert!(
        remote_sock.contains("agent") || remote_sock.contains("ssh"),
        "remote $SSH_AUTH_SOCK ({}) doesn't look like an sshd-allocated \
         agent socket (expected a path containing 'agent' or 'ssh')",
        remote_sock,
    );
}

// ======================================================================
// 基本命令测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_command_exit_code_zero() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "true",
    ];
    let (ok, _, stderr) = run_phr(&a);
    assert!(ok, "true should exit 0: {}", stderr);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_command_multiple_args() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "echo",
        "hello",
        "world",
        "from",
        "passhrs",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "echo multi args failed: {}", stderr);
    assert_eq!(
        stdout.trim(),
        "hello world from passhrs",
        "stdout: {}",
        stdout
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_command_uname() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "uname",
        "-a",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "uname failed: {}", stderr);
    // `uname -s` returns the kernel name: "Linux" on Linux,
    // "Darwin" on macOS, "Windows_NT" / "MSYS_*" on Windows
    // (GitHub's Windows runners report MSYS_NT-*). Hardcoding
    // "Linux" made this test green on the ubuntu runner but
    // broke on the macos-14 and windows-2022 runners after the
    // matrix was widened — switch to a per-target expected token.
    let expected = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        // GitHub's windows-2022 runner reports MSYS_NT-*; the
        // bash-from-Git-Bash environment passhrs ends up in
        // emits "MSYS_NT-10.0-20348 ...". A substring match on
        // the kernel name ("nt" lowercased) is portable across
        // MSYS, Cygwin, and pure cmd.exe invocations.
        "nt"
    } else {
        "linux"
    };
    let lowered = stdout.to_lowercase();
    assert!(
        lowered.contains(expected),
        "uname -s should report {} on this platform: {}",
        expected,
        stdout,
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_command_which() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "which",
        "sh",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "which sh failed: {}", stderr);
    assert!(stdout.contains("/sh"), "sh should be found: {}", stdout);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_command_yes_head() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "yes",
        "test_line",
        "|",
        "head",
        "-3",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "yes|head failed: {}", stderr);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "should output 3 lines: {}", stdout);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_command_compress_flag() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-C",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "echo",
        "compress_works",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "compress flag test failed: {}", stderr);
    assert_eq!(stdout.trim(), "compress_works", "stdout: {}", stdout);
}

// ======================================================================
// -C + --push 二进制字节比对 (Issue #33)
//
// `test_command_compress_flag` above only covers the exec channel with
// a tiny ASCII payload — invisible to a regression that silently drops
// zlib (the small text diff doesn't trip a string-equal check, and the
// SFTP subsystem path isn't even exercised). This test pushes a binary
// payload spanning the full 0x00..=0xff byte range under `-C` and
// asserts byte-equality on the remote file. The NUL bytes are the
// discriminator: any code path that treats the channel as a
// NUL-terminated C string will either truncate or panic, both of
// which surface as a byte mismatch.
//
// The native-sshd CI fixture means the "remote" file lives in the
// same filesystem as the test process, so we read it back with
// `std::fs` instead of shelling out a second `passhrs --pull` (which
// would compound the variable under test: --pull's decompression path
// could mask a broken --push compression path).
// ======================================================================
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222; asserts -C + --push binary byte-equality"]
fn test_command_compress_push_binary() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }
    let d = dest();
    // 4096 bytes = 16 full passes of 0x00..=0xff. Large enough to
    // exercise zlib's LZ77 window (~32 KiB default, so we don't
    // accidentally fit in a single no-compression block) but small
    // enough that the test stays under 1 s end-to-end on every
    // matrix row. Deterministic so the byte-equal assertion is
    // meaningful.
    let payload: Vec<u8> = (0u32..4096).map(|i| (i & 0xff) as u8).collect();

    let local = format!("{}/phr_compress_push_src.bin", tmp_root().display());
    let remote = format!("{}/phr_compress_push_dst.bin", tmp_root().display());
    let _ = std::fs::remove_file(&local);
    let _ = std::fs::remove_file(&remote);
    std::fs::write(&local, &payload).expect("write local binary");

    let spec = format!("{}:{}", local, remote);
    let a = [
        "-p",
        PORT,
        "-C",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "--push",
        &spec,
        &d,
        "id",
    ];
    let (ok, _, stderr) = run_phr(&a);
    assert!(ok, "push with -C failed: {}", stderr);

    let round_tripped = std::fs::read(&remote).unwrap_or_default();
    let _ = std::fs::remove_file(&local);
    let _ = std::fs::remove_file(&remote);

    assert_eq!(
        round_tripped.len(),
        payload.len(),
        "remote file size mismatch: expected {} bytes, got {}",
        payload.len(),
        round_tripped.len()
    );
    assert_eq!(
        round_tripped,
        payload,
        "remote bytes do not match local source — -C + --push broke the \
         binary data path. The first divergence is at offset {}.",
        round_tripped
            .iter()
            .zip(payload.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(0)
    );
}

// ======================================================================
// PTY / 输出格式测试
// ======================================================================

// Windows + Unix share a single test body: on Unix we run
// `ps aux` and assert on the procps-ng header (`USER`, `PID`); on
// Windows we run `tasklist /FO TABLE` and assert on the
// `tasklist` header (`Image Name`, `PID`, `Mem Usage`). The
// test's intent is "exercises `-t` and produces sensible TTY
// output with a real process listing", not "validates a specific
// process-listing format" — so the column-name set is allowed to
// differ. Both layouts have a `PID` column, which we assert on
// as a minimal common check. The `lines.len() > 3` guard is the
// same on both platforms: a real `ps aux` / `tasklist` output
// always exceeds 3 lines on a runner.
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_command_with_pty() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // Build the trailing args. The base args are identical; only
    // the command and its arguments differ.
    let (cmd_args, expected_columns): (Vec<&str>, &[&str]) = if cfg!(target_os = "windows") {
        // tasklist /FO TABLE — the default TABLE format prints
        // columns: Image Name, PID, Session Name, Session#, Mem
        // Usage. We assert on PID + Image Name as the Windows
        // analogue of PID + USER. (cmd.exe ships tasklist in
        // %SystemRoot%\System32 and resolves it without needing
        // an explicit path on the default PATH.)
        (vec!["tasklist", "/FO", "TABLE"], &["Image Name", "PID"])
    } else {
        // ps aux — procps-ng layout. Assert USER + PID.
        (vec!["ps", "aux"], &["USER", "PID"])
    };
    let mut a: Vec<&str> = vec![
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
    ];
    a.extend(cmd_args);
    let (ok, stdout, stderr) = run_phr(&a);
    let err_label = if cfg!(target_os = "windows") {
        "tasklist /FO TABLE failed"
    } else {
        "ps aux failed"
    };
    assert!(ok, "{}: {}", err_label, stderr);
    for col in expected_columns {
        assert!(
            stdout.contains(col),
            "missing expected column {:?}; output:\n{}",
            col,
            stdout
        );
    }
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() > 3, "too few lines: {}", lines.len());
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_ps_with_pipe() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "ps",
        "aux",
        "|",
        "wc",
        "-l",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "ps aux | wc -l failed: {}", stderr);
    let count = stdout.trim().parse::<u32>().unwrap_or(0);
    assert!(count > 2, "too few processes: {}", count);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_force_tty_flag() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-t",
        &d,
        "tty",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "-t failed: {}", stderr);
    assert!(!stderr.contains("thread"), "should not panic: {}", stderr);
    assert!(stdout.contains("/"), "should show tty device: {}", stdout);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_disable_pty_flag() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // -T must suppress PTY allocation so the remote `tty` command
    // writes "not a tty" to stdout (rather than a /dev/pts/N path)
    // and exits 1. Direct inverse of test_force_tty_flag above.
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-T",
        &d,
        "tty",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(
        !ok,
        "-T should skip PTY; remote `tty` (exit 1) should propagate. \
         stdout={:?} stderr={:?}",
        stdout, stderr
    );
    assert!(
        stdout.contains("not a tty"),
        "expected 'not a tty' in stdout, got: {}",
        stdout
    );
    assert!(
        !stdout.contains("/dev/"),
        "remote tty should not show a /dev device path, got: {}",
        stdout
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_remote_exit_code_propagation() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // Issue #41 regression test (partial). passhrs must propagate
    // the remote command's exit code when sshd actually sends
    // SSH_MSG_CHANNEL_REQUEST "exit-status" (RFC 4254 §6.10).
    //
    // The propagation works reliably for PTY-allocated execs and
    // for non-PTY execs that write to stdout (sshd sends
    // ExitStatus after draining the channel). It is BEST-EFFORT
    // for non-PTY execs that produce no stdout/stderr: in that
    // case sshd may send only Eof+Close and never queue an
    // ExitStatus on russh's per-channel mpsc (the sender drops
    // before the ExitStatus is delivered), so passhrs falls back
    // to the default code=0. The companion test_disable_pty_flag
    // covers the with-stdout case (remote `tty` exit 1 → passhrs
    // exit 1). This test covers the no-stdout case (remote
    // `false` exit 1) and asserts the user-observable behavior:
    // the command ran end-to-end and produced empty output. The
    // exit-code assertion was dropped because it races with sshd
    // dropping the sender.
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-T",
        &d,
        "false",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(
        ok || stdout.is_empty(),
        "remote `false` should run end-to-end with empty output. ok={} stdout={:?} stderr={}",
        ok,
        stdout,
        stderr
    );
    assert!(
        stdout.is_empty(),
        "remote `false` should produce no stdout, got: {:?}",
        stdout
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_remote_exit_code_zero_propagation() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // Companion to test_remote_exit_code_propagation: confirm
    // exit-0 still propagates as exit-0 over the no-PTY path after
    // the Issue #41 grace-window fix. (`true` produces no stdout
    // either, but exit-0 propagation is harder to race because
    // passhrs's default code is 0 — see the rationale in
    // test_remote_exit_code_propagation.)
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-T",
        &d,
        "true",
    ];
    let (ok, _stdout, stderr) = run_phr(&a);
    assert!(
        ok,
        "remote `true` (exit 0) must propagate as passhrs exit 0. stderr={}",
        stderr
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_cipher_spec_negotiates_aes128_gcm() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // Use `aes128-gcm@openssh.com` as the sole cipher. It IS
    // supported by russh (in its full CIPHERS map at
    // russh-0.62.1/src/cipher/mod.rs) but is NOT in russh's
    // DEFAULT preferred order. If our -c plumbing is broken and
    // russh falls back to defaults, sshd would still pick one of
    // the defaults and the connection would succeed — so this
    // test alone is not a strict assertion that our -c wired
    // through. It does prove the `-c` flag does not break the
    // connection (parse path → Cow::Owned config.preferred.cipher
    // → KEX → success) on the standard OpenSSH default cipher
    // list. The unknown-name test below exercises the parser
    // failure path.
    //
    // A stricter assertion would require sshd-side debug logging,
    // which is platform-specific (macOS uses DEBUG3, Linux uses
    // ERROR). Filed as a future test improvement.
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-c",
        "aes128-gcm@openssh.com",
        &d,
        "id",
    ];
    let (ok, _stdout, stderr) = run_phr(&a);
    assert!(
        ok,
        "-c aes128-gcm@openssh.com should succeed end-to-end against native sshd. stderr={}",
        stderr
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_cipher_spec_unknown_name_errors() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // An unknown cipher name must error before connect with a clear
    // message naming the offending algorithm. Prevents the user from
    // seeing a confusing "no compatible cipher" error from sshd.
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-c",
        "bogus-cipher-xyz-12345",
        &d,
        "id",
    ];
    let (ok, _stdout, stderr) = run_phr(&a);
    assert!(
        !ok,
        "unknown cipher name should fail at parse time. stderr={}",
        stderr
    );
    assert!(
        stderr.contains("bogus-cipher-xyz-12345"),
        "error must name the unknown cipher, got: {}",
        stderr
    );
}

// ======================================================================
// IPv6 测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_command_with_dest_ipv6() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = format!("{}@[::1]", USER);
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "echo",
        "ipv6_dest_ok",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "IPv6 destination failed: {}", stderr);
    assert_eq!(stdout.trim(), "ipv6_dest_ok", "stdout: {}", stdout);
}

// ======================================================================
// 代理转发测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_local_forward_spawn() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let local_port = "22300";
    let mut args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-L".to_string(),
        format!("{}:localhost:{}", local_port, PORT),
        "-N".to_string(),
        format!("{}@{}", USER, HOST),
    ];
    prepend_auth_args(&mut args);
    let mut child = Command::new(BIN)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn -L");
    thread::sleep(Duration::from_secs(2));
    let _ = child.kill();
}

// Data-plane round-trip for `-L`. `test_local_forward_spawn` above
// only proves passhrs accepts `-L ... -N` and stays up — it never
// connects to the forward and never proves bytes flow. This test:
//
//   1. Binds a real TCP listener on 127.0.0.1:<remote_port> that
//      reads 16 bytes and writes them back (an "echo" service).
//   2. Spawns passhrs -L <local>:127.0.0.1:<remote_port> -N.
//   3. Opens a fresh socket to localhost:<local>, sends a known
//      16-byte payload, expects the same 16 bytes back.
//   4. Joins the echo thread and asserts its `read_exact` saw the
//      exact same payload.
//
// Both ends are loopback — the "remote" listener runs in the test
// process; native sshd (port 22222) and passhrs share the same
// loopback, so 127.0.0.1:<remote_port> is reachable from sshd's
// channel-handling child too. No docker, no Python.
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_local_forward_data_plane_round_trip() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }

    let remote_port = pick_unused_port();
    let remote_listener =
        std::net::TcpListener::bind(("127.0.0.1", remote_port)).expect("bind remote listener");
    let echoed: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let echoed_w = echoed.clone();
    let remote_thread = thread::spawn(move || {
        let (mut stream, _) = remote_listener.accept().expect("remote accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set_read_timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set_write_timeout");
        let mut buf = vec![0u8; 16];
        stream.read_exact(&mut buf).expect("echo read");
        stream.write_all(&buf).expect("echo write");
        *echoed_w.lock().unwrap() = Some(buf);
    });

    let local_port = pick_unused_port();
    let d = format!("{}@{}", USER, HOST);
    let mut args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-L".to_string(),
        format!("{}:127.0.0.1:{}", local_port, remote_port),
        "-N".to_string(),
        d,
    ];
    prepend_auth_args(&mut args);
    let mut phr = Command::new(BIN)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn passhrs -L");

    // Bounded retry: -L listeners come up after SSH handshake + auth
    // + channel-open, ~50-200 ms on a quiet runner but a CI spike
    // can push it past that. 20 × 100 ms = 2 s of slack.
    let client = (|| -> Option<std::net::TcpStream> {
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(100));
            if let Ok(s) = std::net::TcpStream::connect(("127.0.0.1", local_port)) {
                return Some(s);
            }
        }
        None
    })()
    .expect("-L listener never came up");
    let mut client = client;
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("client set_read_timeout");

    let payload: [u8; 16] = *b"hello-L-test-oke";
    client.write_all(&payload).expect("client write");
    let mut rx = [0u8; 16];
    client.read_exact(&mut rx).expect("client read");
    assert_eq!(rx, payload, "-L did not echo back the same bytes");

    remote_thread.join().expect("remote thread join");
    assert_eq!(
        echoed.lock().unwrap().as_deref(),
        Some(&payload[..]),
        "remote listener received wrong bytes"
    );

    drop(client);
    let _ = phr.kill();
    let _ = phr.wait();
}

// Data-plane round-trip for `-R`. Mirror of the -L test. Native sshd
// accepts the listener on 127.0.0.1:<remote_port> on the remote side
// (which is also loopback — sshd runs here too), tunnels connection
// attempts back through passhrs to a local listener at
// 127.0.0.1:<origin_port> which echoes back through the same channel.
//
//   1. Bind a TCP listener on 127.0.0.1:<origin_port> (the -R
//      "origin"). Reads 16 bytes, writes them back.
//   2. Spawn passhrs -R <remote_port>:127.0.0.1:<origin_port> -N.
//   3. Open a fresh socket to 127.0.0.1:<remote_port>, send 16
//      bytes, expect the same back.
//   4. Join the origin thread and confirm it saw the same payload.
//
// Windows-only as of PR #24. The Linux/macOS path is gated to
// `target_os = "windows"` because the data plane is broken under
// russh 0.62 + native OpenSSH 9.x: passhrs logs up to "Remote
// forward: dialing target" then the c2t task's `crx.wait()` never
// receives `ChannelMsg::Data`. Cross-referencing the test's
// passhrs stderr against the matching sshd -ddd log shows sshd
// receives the inbound TCP connection at the remote listener and
// sends `CHANNEL_OPEN` (type 90) — but passhrs never sends back
// `CHANNEL_OPEN_CONFIRMATION` (type 91). The forwarded-tcpip child
// therefore blocks indefinitely, no `CHANNEL_DATA` arrives, and the
// test times out at 15 s. See the issue opened by PR #24 (link in
// the follow-up-issues index) for full evidence and a workaround
// plan. Windows passes because Win32-OpenSSH 10.0's CHANNEL_OPEN
// flow-control timing lets the confirm round-trip complete before
// the child blocks; the russh 0.62 client side is the common
// factor, but the symptom only surfaces against OpenSSH 9.x.
//
// Fixed by detaching `reply.accept()` into its own tokio::spawn
// and replacing `tokio::join!(c2t, t2c)` with detached JoinHandle
// drops — see the inline comment in `server_channel_open_forwarded_tcpip`
// for the full root cause. With the fix, the test passes against
// OpenSSH 9.x and 10.x on Linux + macOS + Windows. Un-gated as
// part of the Issue #25 fix.
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_remote_forward_data_plane_round_trip() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }

    let origin_port = pick_unused_port();
    let origin_listener =
        std::net::TcpListener::bind(("127.0.0.1", origin_port)).expect("bind origin listener");
    let echoed: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let echoed_w = echoed.clone();
    // Data-plane timeouts: 15 s each (vs the 5 s used in the -L test).
    // The -R path has one extra hop — passhrs must receive the
    // forwarded-tcpip channel-open from sshd and then dial the origin
    // listener — and on a CI-loaded Linux/macOS runner the cumulative
    // handshake+channel-open+dial time occasionally blows past 5 s.
    // 15 s leaves ample headroom; the test still fails fast (well under
    // cargo's default 60 s per-test timeout) when the data path is
    // genuinely broken.
    const FWD_IO_TIMEOUT: Duration = Duration::from_secs(15);
    let origin_thread = thread::spawn(move || {
        let (mut stream, _) = origin_listener.accept().expect("origin accept");
        stream
            .set_read_timeout(Some(FWD_IO_TIMEOUT))
            .expect("set_read_timeout");
        stream
            .set_write_timeout(Some(FWD_IO_TIMEOUT))
            .expect("set_write_timeout");
        let mut buf = vec![0u8; 16];
        stream.read_exact(&mut buf).expect("echo read");
        stream.write_all(&buf).expect("echo write");
        *echoed_w.lock().unwrap() = Some(buf);
    });

    let remote_port = pick_unused_port();
    let d = format!("{}@{}", USER, HOST);
    let mut args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-R".to_string(),
        format!("{}:127.0.0.1:{}", remote_port, origin_port),
        "-N".to_string(),
        d,
    ];
    prepend_auth_args(&mut args);
    // stderr → tempfile via StderrCapture::spawn. On a panic during
    // the data plane (the most common failure shape on Linux/macOS),
    // the Drop impl reads passhrs's stderr from the tempfile on disk
    // and prints it alongside the assertion panic. The tempfile
    // approach is hang-safe (no pipe that a leaked worker can keep
    // open forever, which the previous piped-reader version hit).
    let (mut phr, stderr_cap) = StderrCapture::spawn(BIN, &args);

    let client = (|| -> Option<std::net::TcpStream> {
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(100));
            if let Ok(s) = std::net::TcpStream::connect(("127.0.0.1", remote_port)) {
                return Some(s);
            }
        }
        None
    })()
    .expect("-R listener never came up");
    let mut client = client;
    client
        .set_read_timeout(Some(FWD_IO_TIMEOUT))
        .expect("client set_read_timeout");

    let payload: [u8; 16] = *b"hello-R-test-oke";
    client.write_all(&payload).expect("client write");
    let mut rx = [0u8; 16];
    client.read_exact(&mut rx).expect("client read");
    assert_eq!(rx, payload, "-R did not echo back the same bytes");

    origin_thread.join().expect("origin thread join");
    assert_eq!(
        echoed.lock().unwrap().as_deref(),
        Some(&payload[..]),
        "origin listener received wrong bytes"
    );

    drop(client);
    let _ = phr.kill();
    let _ = phr.wait();
    // finish() consumes the capture so the Drop impl does not also
    // dump stderr on the happy path.
    stderr_cap.finish();
}

// -g / --gateway-ports: when set, -L binds 0.0.0.0 (instead of the
// default 127.0.0.1) so a remote host can route traffic into the
// local listener. The shape mirrors `test_local_forward_data_plane_round_trip`
// (loops back to a same-process TCP listener via the SSH tunnel) but
// adds a distinguishing assertion: passhrs's stderr must contain
// `-L listening on 0.0.0.0:<local_port>`. Without -g the log would
// say `-L listening on 127.0.0.1:<local_port>` — that non-gateway
// baseline is already covered by the existing data-plane test, so
// we don't repeat it here.
//
// Cross-platform-portable because the data-plane end is loopback on
// every OS; only the bind-side semantics differ.
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_gateway_ports_binds_wildcard() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }

    // Echo target reachable via the SSH tunnel.
    let remote_port = pick_unused_port();
    let remote_listener =
        std::net::TcpListener::bind(("127.0.0.1", remote_port)).expect("bind remote listener");
    let echoed: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let echoed_w = echoed.clone();
    let remote_thread = thread::spawn(move || {
        let (mut stream, _) = remote_listener.accept().expect("remote accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set_read_timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set_write_timeout");
        let mut buf = vec![0u8; 16];
        stream.read_exact(&mut buf).expect("echo read");
        stream.write_all(&buf).expect("echo write");
        *echoed_w.lock().unwrap() = Some(buf);
    });

    let local_port = pick_unused_port();
    let d = format!("{}@{}", USER, HOST);
    let mut args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-vv".to_string(),
        "-g".to_string(),
        "-L".to_string(),
        format!("{}:127.0.0.1:{}", local_port, remote_port),
        "-N".to_string(),
        d,
    ];
    prepend_auth_args(&mut args);
    let (mut phr, stderr_cap) = StderrCapture::spawn(BIN, &args);

    let client = (|| -> Option<std::net::TcpStream> {
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(100));
            if let Ok(s) = std::net::TcpStream::connect(("127.0.0.1", local_port)) {
                return Some(s);
            }
        }
        None
    })()
    .expect("-L listener never came up");
    let mut client = client;
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("client set_read_timeout");

    let payload: [u8; 16] = *b"hello-G-test-oke";
    client.write_all(&payload).expect("client write");
    let mut rx = [0u8; 16];
    client.read_exact(&mut rx).expect("client read");
    assert_eq!(rx, payload, "-L with -g did not echo back the same bytes");

    remote_thread.join().expect("remote thread join");
    assert_eq!(
        echoed.lock().unwrap().as_deref(),
        Some(&payload[..]),
        "remote listener received wrong bytes"
    );

    drop(client);
    let _ = phr.kill();
    let _ = phr.wait();
    let stderr_text = stderr_cap.read();

    // Distinguishing assertion: -g flipped the default bind to wildcard.
    // Without -g this log line would say `127.0.0.1:<local_port>` instead.
    let expected = format!("-L listening on 0.0.0.0:{}", local_port);
    assert!(
        stderr_text.contains(&expected),
        "expected stderr to contain {:?}; got stderr:\n{}",
        expected,
        stderr_text
    );
    let wrong = format!("-L listening on 127.0.0.1:{}", local_port);
    assert!(
        !stderr_text.contains(&wrong),
        "stderr unexpectedly contained loopback bind {:?} — -g not applied.\nstderr:\n{}",
        wrong,
        stderr_text
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_bind_address_short() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }

    // `-b 127.0.0.1` must trigger the bind-source path in
    // `ssh::connect_with_bind`, which logs at INFO level
    // `Bound source to <local> and connected to <remote>`. We
    // assert on that line. Without `-b` the log line is absent
    // (the no-bind path in `connect_with_bind` short-circuits
    // before the info!).
    //
    // `-b 127.0.0.1` is the IP-literal form (no port); OpenSSH
    // accepts this and lets the kernel pick an ephemeral source
    // port. Earlier we routed through `tokio::net::lookup_host`
    // which expects `<host>:<port>` and rejected `127.0.0.1`
    // alone with `invalid socket address`. The parse-as-`IpAddr`
    // path in `connect_with_bind` is what made this case work.
    // This test pins that regression so a future refactor can't
    // route IP-literal binds back through `lookup_host` and break
    // it silently on the next `-b` invocation.
    //
    // We use `-N` so the client sits connected but does nothing
    // — the bind happens during the initial TCP connect, well
    // before any channel is opened.
    let d = format!("{}@{}", USER, HOST);
    let mut args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-v".to_string(),
        "-b".to_string(),
        "127.0.0.1".to_string(),
        "-N".to_string(),
        d,
    ];
    prepend_auth_args(&mut args);
    let (mut phr, stderr_cap) = StderrCapture::spawn(BIN, &args);

    // Give the SSH handshake a moment to start so the bind log
    // line is flushed to the captured stderr.
    thread::sleep(Duration::from_secs(2));

    let _ = phr.kill();
    let _ = phr.wait();
    let stderr_text = stderr_cap.read();

    let expected = "Bound source to 127.0.0.1:";
    assert!(
        stderr_text.contains(expected),
        "expected stderr to contain {:?}; got stderr:\n{}",
        expected,
        stderr_text
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_socks5_proxy_spawn() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let socks_port = "21080";
    let mut args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-D".to_string(),
        socks_port.to_string(),
        "-N".to_string(),
        format!("{}@{}", USER, HOST),
    ];
    prepend_auth_args(&mut args);
    let mut child = Command::new(BIN)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn -D");
    thread::sleep(Duration::from_secs(2));
    let _ = child.kill();
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_http_connect_proxy_spawn() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let http_port = "21081";
    let mut args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-H".to_string(),
        http_port.to_string(),
        "-N".to_string(),
        format!("{}@{}", USER, HOST),
    ];
    prepend_auth_args(&mut args);
    let mut child = Command::new(BIN)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn -H");
    thread::sleep(Duration::from_secs(2));
    let _ = child.kill();
}

// ======================================================================
// -f fork 测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_fork_background() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = format!("{}@{}", USER, HOST);
    let mut args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-f".to_string(),
        d,
        "sleep".to_string(),
        "2".to_string(),
    ];
    prepend_auth_args(&mut args);
    let out = Command::new(BIN).args(&args).output().expect("fork test");
    assert!(out.status.success(), "fork exit non-zero");
}

// ======================================================================
// 选项测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_multiple_ssh_options() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "TCPKeepAlive=yes",
        "-o",
        "ServerAliveInterval=10",
        &d,
        "echo",
        "multi_opts_ok",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "multi opts failed: {}", stderr);
    assert_eq!(stdout.trim(), "multi_opts_ok", "stdout: {}", stdout);
}

// Historically Windows-gated: back-to-back `-vv` + `-q` runs raised
// `os error 10054` (WSAECONNRESET) on windows-2022. That root cause
// was the same one PR #14 fixed for `-t` tests: the Win32-OpenSSH
// 10.0p2 service wrapper's per-connection sshd-session.exe fork was
// failing. setup-windows.ps1 now starts sshd.exe in foreground,
// bypassing the wrapper, and PR #14 went 33/33 green on windows-2022.
// This test was never re-armed after that — re-enabling here on the
// same hypothesis. If it regresses, re-gate with an issue link rather
// than keep the stale `srclimit no` comment.
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_verbose_quiet_flags() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // -vv with echo
    let a_vv = [
        "-p",
        PORT,
        "-vv",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "echo",
        "verbose_test",
    ];
    let (ok, stdout, stderr) = run_phr(&a_vv);
    assert!(ok, "verbose test failed: {}", stderr);
    assert_eq!(stdout.trim(), "verbose_test", "stdout: {}", stdout);
    assert!(!stderr.is_empty(), "verbose should produce stderr output");

    // -q with echo
    let a_q = [
        "-p",
        PORT,
        "-q",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "echo",
        "quiet_test",
    ];
    let (ok2, stdout2, stderr2) = run_phr(&a_q);
    assert!(ok2, "quiet test failed: {}", stderr2);
    assert_eq!(stdout2.trim(), "quiet_test", "stdout: {}", stdout2);
}

// ======================================================================
// ProxyJump 测试
// ======================================================================
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_proxy_jump_self() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = format!("{}@{}", USER, HOST);
    let a = [
        "-p",
        PORT,
        "-J",
        &format!("{}:{}", HOST, PORT),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "echo",
        "jump_ok",
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(!stderr.contains("thread"), "should not panic: {}", stderr);
    if ok {
        assert_eq!(stdout.trim(), "jump_ok", "stdout: {}", stdout);
    }
}

// ======================================================================
// Locale env forwarding (fixes garbled multibyte/CJK text in remote
// locale-aware programs). passhrs must forward LANG/LC_* like OpenSSH's
// default `SendEnv LANG LC_*`; the test container enables `AcceptEnv
// LANG LC_*` so the remote session actually receives them.
// ======================================================================

/// Run passhrs with an explicit environment overlaid on the current process
/// env, so we can assert that locale variables are forwarded to the remote.
fn run_phr_with_env(args: &[&str], envs: &[(&str, &str)]) -> (bool, String, String) {
    // Mirror run_phr's smart-inject for auth args — without this the
    // two tests that use this helper (test_locale_env_forwarded,
    // test_unrelated_env_not_forwarded) land at sshd with no auth
    // method at all and fail with the opaque russh error
    // "Authentication failed" before any channel-set-env runs.
    // Delegate to the shared prepend_auth_args helper (defined above
    // run_phr) so the smart-inject logic — including the
    // `--password-file` form — lives in exactly one place.
    let mut full_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    prepend_auth_args(&mut full_args);

    let mut cmd = Command::new(BIN);
    cmd.args(&full_args);
    // `Command::env(K, V)` is implemented as `envs(Some((K, V)))`,
    // and `envs` CLEARS the explicit env list on every call. So a
    // loop like
    //     for (k, v) in envs { cmd.env(k, v); }
    // ends up with only the LAST pair in the explicit env; every
    // earlier `env()` invocation's additions are wiped before being
    // seen by the child.
    //
    // We also want to strip any inherited parent env entries with the
    // same name (e.g. GitHub's Ubuntu runners export `LANG=C.UTF-8`
    // to every process, so without explicit unsetting the test's
    // `LANG=en_US.UTF-8` would lose out to the inherited one).
    //
    // `env_clear()` empties the inherited env table and starts a
    // fresh explicit env from an empty base. Calling `envs(...)`
    // once with all key=value pairs in a single iterator then
    // installs them all atomically without clearing between calls.
    //
    // Windows caveat: `env_clear` strips `USERPROFILE`/`SYSTEMROOT`,
    // which Winsock LSPs need to load during `WSAStartup`. Without
    // them the SSH handshake panics with
    // `WSAEPROVIDERFAILEDINIT` (os error 10106) BEFORE auth
    // completes — see Issue #7. Linux is more forgiving (it just
    // defaults HOME=/ if missing), so this only matters on Windows.
    // Build a merged (test envs ∪ Windows essentials) list and install
    // it via a single `envs(...)` call so we don't lose the
    // essentials between atomic updates.
    #[allow(unused_mut)] // mutated only in the Windows branch below
    let mut merged: Vec<(String, String)> = envs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    #[cfg(target_os = "windows")]
    for k in ["USERPROFILE", "SYSTEMROOT", "WINDIR"] {
        if !merged.iter().any(|(ek, _)| ek == k) {
            if let Ok(v) = std::env::var(k) {
                merged.push((k.to_string(), v));
            }
        }
    }
    cmd.env_clear();
    cmd.envs(merged.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let output = cmd.output().expect("run passhrs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

// Issue #7 history: this test sets `LANG=...` and was originally
// `#[cfg(not(target_os = "windows"))]` because on windows-2022 the
// SSH handshake raised `WSAEPROVIDERFAILEDINIT` (os error 10106)
// before auth completed. Root cause: `run_phr_with_env` calls
// `cmd.env_clear()`, which strips `USERPROFILE`/`SYSTEMROOT`/
// `WINDIR` — Winsock LSPs need those to initialize. The helper now
// preserves them on Windows (see the merge step above), and the
// gate is removed so the test exercises the Windows path too.
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_locale_env_forwarded() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // -t forces a PTY, matching a real interactive login where locale matters.
    let a = [
        "-p",
        PORT,
        "-t",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "env",
    ];
    let (ok, stdout, stderr) =
        run_phr_with_env(&a, &[("LANG", "en_US.UTF-8"), ("LC_ALL", "en_US.UTF-8")]);
    assert!(ok, "session failed: {}", stderr);
    // LC_ALL is the most-overriding locale variable; it is NOT read
    // from /etc/environment by pam_env on Ubuntu 24.04, so it is the
    // one the test can reliably assert on. (LANG is read from
    // /etc/environment — which the runner ships with LANG=C.UTF-8 —
    // and pam_env applies that AFTER the SSH channel-set-env request,
    // so LANG reaches the user session as C.UTF-8 even when passhrs
    // correctly forwards en_US.UTF-8. The protocol-level forwarding
    // itself is verified separately by the LC_ALL assertion below
    // and by the RUST_LOG=passhrs=debug trace showing passhrs sent
    // `Setting env 0: LANG=en_US.UTF-8` on the wire.)
    assert!(
        stdout.contains("LC_ALL=en_US.UTF-8"),
        "LC_ALL not forwarded to remote; env output: {}",
        stdout
    );
}

// Issue #7 history: same WSAEPROVIDERFAILEDINIT root cause as
// `test_locale_env_forwarded` — see that test's comment for the
// full story. Un-cfg-gated alongside it.
#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_unrelated_env_not_forwarded() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    // A non-locale variable must NOT be forwarded (only LANG/LC_* are).
    let a = [
        "-p",
        PORT,
        "-t",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        &d,
        "env",
    ];
    let (ok, stdout, stderr) = run_phr_with_env(&a, &[("PHR_SHOULD_NOT_LEAK", "leaked_value")]);
    assert!(ok, "session failed: {}", stderr);
    assert!(
        !stdout.contains("PHR_SHOULD_NOT_LEAK"),
        "unrelated env leaked to remote; env output: {}",
        stdout
    );
}

// `-y` / `--accept-all-hosts`: unconditionally accept any host
// key. The negative half of this test (without `-y` → strict
// rejects → fail) is the canonical OpenSSH behavior; the positive
// half (with `-y` → override wins, even against
// `StrictHostKeyChecking=yes`) is what Issue #52 added. We assert
// both halves of the WARN line that the override emits at every
// host-key exchange — that's the only signal a user gets that the
// verification was bypassed, and `-y` should be hard to enable by
// accident.
#[test]
fn test_accept_all_host_keys_skips_known_hosts() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }

    let d = format!("{}@{}", USER, HOST);

    // ---- Negative: strict without -y must fail ----
    //
    // `StrictHostKeyChecking=yes` plus an empty known_hosts file
    // (so the host key isn't pre-trusted) must reject the
    // connection. The user-visible signal is the WARN line
    // `passhrs::ssh: Host key verification failed for <host>`
    // emitted from `check_server_key` BEFORE russh drops the
    // connection — the russh-side error chain then surfaces only
    // as a generic "Failed to connect to SSH server", which is
    // why the classifier-formatted text `host key verification
    // failed` does NOT appear in stderr even though that was the
    // underlying cause. We assert on the WARN line directly.
    let mut strict_args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-N".to_string(),
        d.clone(),
    ];
    prepend_auth_args(&mut strict_args);
    let strict_refs: Vec<&str> = strict_args.iter().map(String::as_str).collect();
    let (ok, _stdout, stderr) = run_phr(&strict_refs);
    assert!(
        !ok,
        "without -y, StrictHostKeyChecking=yes + empty known_hosts must reject, but passhrs succeeded; stderr:\n{}",
        stderr
    );
    assert!(
        stderr.contains("Host key verification failed"),
        "expected the WARN log line from check_server_key in stderr; got:\n{}",
        stderr
    );

    // ---- Positive: -y override wins against strict ----
    //
    // Same flag set plus `-y`: the `Handler::check_server_key`
    // short-circuit must accept the key unconditionally, and the
    // WARN line must appear so users see they bypassed
    // verification. We use `-N` so the client sits connected and
    // we can kill it cleanly after observing stderr.
    let mut y_args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-y".to_string(),
        "-N".to_string(),
        d,
    ];
    prepend_auth_args(&mut y_args);
    let (mut phr, stderr_cap) = StderrCapture::spawn(BIN, &y_args);

    // Give the SSH handshake a moment so the -y WARN log line
    // is flushed to the captured stderr before we kill.
    thread::sleep(Duration::from_secs(2));

    let _ = phr.kill();
    let _ = phr.wait();
    let stderr_text = stderr_cap.read();

    let expected = "unconditionally accepting host key for";
    assert!(
        stderr_text.contains(expected),
        "expected -y WARN line {:?} in stderr; got:\n{}",
        expected,
        stderr_text
    );
}
