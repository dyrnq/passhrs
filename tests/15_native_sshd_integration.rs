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
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

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
fn tmp_root() -> PathBuf {
    std::env::temp_dir()
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
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b != 0x1b {
            // Pass through; re-encode as UTF-8 safely via String::push_str
            // below in the surrogate escape branch.
            out.push(b as char);
            i += 1;
            continue;
        }
        // ESC: try to consume a known sequence shape. If we don't
        // recognise the introducer, drop just the ESC and keep
        // scanning — better to over-strip than to leave a stray
        // `\x1b` in the output.
        if i + 1 >= bytes.len() {
            break;
        }
        let intro = bytes[i + 1];
        match intro {
            b'[' => {
                // CSI: skip until final byte (0x40..=0x7e)
                let mut j = i + 2;
                while j < bytes.len() && !(0x40..=0x7e).contains(&bytes[j]) {
                    j += 1;
                }
                i = if j < bytes.len() { j + 1 } else { j };
            }
            b']' | b'P' | b'^' | b'_' => {
                // OSC / DCS / PM / APC: skip until BEL or ESC \\
                let mut j = i + 2;
                while j < bytes.len() {
                    if bytes[j] == 0x07 {
                        j += 1;
                        break;
                    }
                    if bytes[j] == 0x1b && j + 1 < bytes.len() && bytes[j + 1] == b'\\' {
                        j += 2;
                        break;
                    }
                    j += 1;
                }
                i = j;
            }
            b'=' | b'>' | b'}' => {
                i += 2;
            }
            _ => {
                // Unknown — drop just the ESC.
                i += 1;
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
    let local = "/tmp/phr_test_push.txt";
    let remote = "/tmp/phr_remote_push.txt";
    let local2 = "/tmp/phr_test_pulled.txt";
    std::fs::write(local, b"hello sftp push").unwrap();

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
    let pulled = std::fs::read_to_string(local2).unwrap_or_default();
    assert!(
        pulled.contains("hello sftp push"),
        "pulled content mismatch"
    );
    let _ = std::fs::remove_file(local);
    let _ = std::fs::remove_file(local2);
    let _ = std::fs::remove_file(&remote);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_push_dir() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let dir = "/tmp/phr_test_pushdir";
    let remote_dir = "/tmp/phr_remote_dir";
    let _ = std::fs::create_dir_all(dir);
    std::fs::write(format!("{}/a.txt", dir), b"file a").unwrap();
    let _ = std::fs::create_dir_all(format!("{}/sub", dir));
    std::fs::write(format!("{}/sub/c.txt", dir), b"file c").unwrap();
    let _ = std::fs::remove_dir_all(remote_dir);

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
    // No chown needed: testuser owns its own home and per-user temp dirs
    // on the native sshd host.
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_rsync_upload_basic() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let dir = "/tmp/phr_rsync_src";
    let remote_dir = "/tmp/phr_rsync_dst";
    let _ = std::fs::create_dir_all(dir);
    std::fs::write(format!("{}/f1.txt", dir), b"rsync test file 1").unwrap();
    std::fs::write(format!("{}/f2.txt", dir), b"rsync test file 2").unwrap();
    setup_rsync_remote(remote_dir);

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
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(remote_dir);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_rsync_delta() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let remote_dir = "/tmp/phr_delta_dst";
    let local_dir = "/tmp/phr_delta_src";
    setup_rsync_remote(remote_dir);
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
    let _ = std::fs::create_dir_all(local_dir);
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
    let _ = std::fs::remove_dir_all(local_dir);
    let _ = std::fs::remove_dir_all(remote_dir);
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_rsync_with_exclude() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let dir = "/tmp/phr_rsync_excl";
    let remote_dir = "/tmp/phr_rsync_excl_dst";
    let _ = std::fs::create_dir_all(dir);
    std::fs::write(format!("{}/keep.txt", dir), b"keep me").unwrap();
    std::fs::write(format!("{}/ignore.txt", dir), b"ignore me").unwrap();
    setup_rsync_remote(remote_dir);

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
    let a = [
        "-p",
        PORT,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "--exec-env",
        "PHR_TEST_VAR=hello_from_env",
        &d,
        "echo",
        "$PHR_TEST_VAR",
    ];
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
    let pw_path = "/tmp/phr_test_pw_file.txt";
    std::fs::write(pw_path, PASS).unwrap();
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
    let pw_path = "/tmp/phr_test_pw_flag.txt";
    std::fs::write(pw_path, PASS).unwrap();
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
    assert!(
        stdout.to_lowercase().contains("linux"),
        "should be Linux: {}",
        stdout
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
// PTY / 输出格式测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234!"]
fn test_command_with_pty() {
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
    ];
    let (ok, stdout, stderr) = run_phr(&a);
    assert!(ok, "ps aux failed: {}", stderr);
    assert!(stdout.contains("USER"), "missing USER column");
    assert!(stdout.contains("PID"), "missing PID column");
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
    cmd.env_clear();
    cmd.envs(envs.iter().map(|(k, v)| (*k, *v)));
    let output = cmd.output().expect("run passhrs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

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
