#![allow(
    clippy::zombie_processes,
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args
)]
//! -i 私钥认证 + --identity-passphrase 集成测试
//!
//! 验证三种 key-auth 场景:
//!   1. `test_key_auth_no_passphrase` — ed25519 无 passphrase,
//!      走 tests/sshd/setup-{linux,macos,windows}.* 落盘的
//!      PHR_TEST_KEY (基础设施由 tests/15 共享)。
//!   2. `test_key_auth_with_passphrase` — ed25519 有 passphrase,
//!      测试运行时生成密钥对,通过 PHR_TEST_KEY 通道把公钥追加
//!      到远端 authorized_keys,再用 `--identity-passphrase` 验证。
//!   3. `test_rsa_key_auth` — RSA-3072,Issue #1 的回归测试
//!      (OpenSSH 8.8+ 禁了 sha-rsa / SHA-1,要 SHA-2 fallback)。
//!
//! 三个测试都使用 tests/sshd/setup-* 启的本地 native sshd (port 22222),
//! 不再 docker。先有 sshd + PHR_TEST_KEY infrastructure (由 macOS + linux +
//! windows setup 脚本写),然后通过 std-only 工具 (ssh-keygen + passhrs)
//! 生成测试密钥、用 PHR_TEST_KEY 通道把公钥推上去、最后用新密钥
//! 验证 auth。
use std::process::Command;
use std::thread;
use std::time::Duration;

const HOST: &str = "127.0.0.1";
const PORT: &str = "22222";
// Same three-way platform split as tests/15_native_sshd_integration.rs:
// Linux runs as the pre-existing `runner` user; macOS uses a
// freshly-dscl'd `testuser` (Sonoma+ secure-token lockout blocks
// every password-set API for the runner account, so the setup
// script creates a dedicated testuser whose authorized_keys holds
// the PHR_TEST_KEY pubkey); windows-2022 (since runner 2.305.0)
// ships `runneradmin`. tests/sshd/setup-windows.ps1 expects
// `runneradmin` to exist on the runner image; the linux + macOS
// scripts manage their respective users.
#[cfg(target_os = "windows")]
const USER: &str = "runneradmin";
#[cfg(target_os = "macos")]
const USER: &str = "testuser";
#[cfg(target_os = "linux")]
const USER: &str = "runner";
const PASS: &str = "PassTest1234!";

/// True iff `tests/sshd/setup-*.sh` (or .ps1) has booted a native
/// sshd that passhrs can connect to. Mirrors `sshd_ok()` in
/// tests/15 — duplicated here to keep this binary self-contained
/// (cargo runs each test file in its own process; there's no
/// cross-file helper sharing).
///
/// macOS backoff (Issue #31): the 200 ms timeout the original
/// version used races sshd's accept-queue refill on a quiet
/// runner — the integration step's first `connect_timeout` after
/// the provision step's 30-second gap can land before sshd is
/// ready. Bump to 500 ms (matches tests/15) and retry twice on
/// macOS only; the retry is 100 ms sleep + 500 ms timeout, so
/// worst-case wait is ~1.7 s, well within cargo's per-test
/// default. Linux + Windows keep the single-probe shape because
/// they don't show the same flake.
fn sshd_ok() -> bool {
    use std::net::TcpStream;
    use std::net::ToSocketAddrs;
    let addr = match format!("{}:{}", HOST, PORT).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return false,
        },
        Err(_) => return false,
    };
    let probe = || TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok();
    if probe() {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        thread::sleep(Duration::from_millis(100));
        if probe() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
        return probe();
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Auth args for `passhrs`. Mirrors tests/15::auth_args(): if the
/// setup script exported PHR_TEST_KEY, use it (macOS / the new
/// linux+windows paths); otherwise fall back to password auth. Used
/// to install per-test pubkeys into authorized_keys (test_key_auth_*
/// run their own `ssh-keygen` and need a working channel to push
/// the new pubkey through).
///
/// macOS fail-fast (Issue #31): on macOS, falling back to `--password
/// PASS` is a silent failure — the brew-openssh setup script
/// configures `PasswordAuthentication no`, so the password attempt
/// raises a confusing `Permission denied (publickey)`, and the CI
/// retry loop in `.github/workflows/ci.yml` masks the real cause
/// (`PHR_TEST_KEY` didn't reach the test process). When the env
/// var is unset OR empty on macOS, panic with a clear message that
/// points at the right setup script and the env-var propagation
/// path. Linux + Windows keep the existing password-fallback shape
/// because their sshd_configs still accept password auth.
fn auth_args() -> Vec<String> {
    let key_path = std::env::var("PHR_TEST_KEY").ok();
    if let Some(key) = key_path {
        if !key.is_empty() {
            return vec!["-i".to_string(), key];
        }
    }
    #[cfg(target_os = "macos")]
    {
        panic!(
            "PHR_TEST_KEY is unset or empty on macOS — the brew-openssh \
             setup script must drop a test key (see \
             tests/sshd/setup-macos-brew-openssh.sh) and propagate it \
             via $GITHUB_ENV. The previous fallback to --password \
             masked this with Permission denied (publickey) and a \
             CI-side retry — see Issue #31 for context."
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        vec!["--password".to_string(), PASS.to_string()]
    }
}

/// Generate an ed25519 keypair at `prefix` (private key at
/// `prefix`, public at `prefix.pub`). Empty passphrase is used
/// when `passphrase` is None.
fn gen_ed25519(prefix: &str, passphrase: Option<&str>) {
    let _ = std::fs::remove_file(prefix);
    let _ = std::fs::remove_file(format!("{}.pub", prefix));
    let mut cmd = Command::new("ssh-keygen");
    cmd.args(["-t", "ed25519", "-f", prefix, "-N"]);
    cmd.arg(passphrase.unwrap_or(""));
    let out = cmd.output().expect("ssh-keygen ed25519");
    assert!(
        out.status.success(),
        "ssh-keygen ed25519 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Same as `gen_ed25519` but for RSA. The `-b` flag is required
/// because OpenSSH 9.x defaults to `-b 3072` (we want 3072 too,
/// but we spell it out for clarity and so a regression that
/// changes the default gets noticed).
fn gen_rsa(prefix: &str, bits: u32, passphrase: Option<&str>) {
    let _ = std::fs::remove_file(prefix);
    let _ = std::fs::remove_file(format!("{}.pub", prefix));
    let mut cmd = Command::new("ssh-keygen");
    cmd.args(["-t", "rsa", "-b", &bits.to_string(), "-f", prefix, "-N"]);
    cmd.arg(passphrase.unwrap_or(""));
    let out = cmd.output().expect("ssh-keygen rsa");
    assert!(
        out.status.success(),
        "ssh-keygen rsa failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Read the public-key line from `<key>.pub`. ssh-keygen writes
/// `ssh-ed25519 AAAA... [comment]\n` — we want the first two
/// whitespace-separated fields joined by a single space.
fn pubkey_line(key_path: &str) -> String {
    let raw = std::fs::read_to_string(format!("{}.pub", key_path)).expect("read pubkey");
    raw.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

/// Install `pubkey` into `~<USER>/.ssh/authorized_keys` on the
/// remote sshd. Goes through passhrs with the test key so we don't
/// have to plumb a second SSH client. Idempotent: caller is
/// expected to dedup or accept dup lines if running twice.
fn install_pubkey_via_passhrs(pubkey: &str) {
    // Build a single-quoted literal on the remote side to keep the
    // shell from interpreting anything in the pubkey. The pubkey
    // itself only contains [A-Za-z0-9+/=], no quotes, but being
    // defensive here costs nothing.
    let remote_cmd = format!(
        "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && \
         chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && \
         printf '%s\\n' '{}' >> ~/.ssh/authorized_keys",
        pubkey.replace('\'', "'\\''")
    );
    let mut args = auth_args();
    args.extend([
        "-p".to_string(),
        PORT.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        format!("{}@{}", USER, HOST),
        remote_cmd,
    ]);
    let out = Command::new("./target/release/passhrs")
        .args(&args)
        .output()
        .expect("passhrs install pubkey");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "install_pubkey_via_passhrs failed (exit {:?})\nstdout: {}\nstderr: {}",
        out.status.code(),
        stdout,
        stderr
    );
}

/// Run `passhrs -i <key> [extra args...]` and return (status,
/// stdout, stderr). Wraps the spawn so each test asserts on the
/// outcome with the right context. `extra_args` is appended after
/// `-i <key>` and before the destination + command.
fn run_passhrs_with_key(
    key: &str,
    extra_args: &[&str],
    remote_cmd: &str,
) -> (bool, String, String) {
    let mut args: Vec<String> = vec![
        "-p".to_string(),
        PORT.to_string(),
        "-i".to_string(),
        key.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
    ];
    args.extend(extra_args.iter().map(|s| s.to_string()));
    args.push(format!("{}@{}", USER, HOST));
    args.push(remote_cmd.to_string());
    let out = Command::new("./target/release/passhrs")
        .args(&args)
        .output()
        .expect("spawn passhrs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ======================================================================

/// Smoke test for the PHR_TEST_KEY infrastructure: if the setup
/// script wrote a pubkey for the runner user, this test proves
/// `passhrs -i $PHR_TEST_KEY` can drive a real `echo` over the
/// sshd. The other two tests depend on this path working (they use
/// it to install per-test pubkeys), so this also serves as a guard
/// for them — if PHR_TEST_KEY auth breaks, the first failure here
/// isolates the cause.
#[test]
#[ignore = "requires native sshd on 127.0.0.1:22222 with PHR_TEST_KEY in authorized_keys"]
fn test_key_auth_no_passphrase() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }
    let key = match std::env::var("PHR_TEST_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!("SKIP: PHR_TEST_KEY not set (setup script did not drop a test key)");
            return;
        }
    };
    let (ok, stdout, stderr) = run_passhrs_with_key(&key, &[], "echo key_ok");
    assert!(
        ok && stdout.contains("key_ok"),
        "key auth should succeed\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}

// ======================================================================

#[test]
#[ignore = "requires native sshd on 127.0.0.1:22222 + PHR_TEST_KEY auth working"]
fn test_key_auth_with_passphrase() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }
    // PHR_TEST_KEY auth must work for us to install the test pubkey.
    // Bailing early (without failing) when it's missing mirrors the
    // "soft skip" approach used in test_key_auth_no_passphrase: a
    // setup script that didn't drop a key shouldn't fail the whole
    // test file. install_pubkey_via_passhrs reads PHR_TEST_KEY via
    // auth_args() internally, so we only need to check the env var,
    // not bind it.
    if std::env::var("PHR_TEST_KEY")
        .ok()
        .is_none_or(|k| k.is_empty())
    {
        eprintln!("SKIP: PHR_TEST_KEY not set");
        return;
    }

    let key_path = "/tmp/phr_test_ed25519_passphrase";
    let passphrase = "my-test-passphrase-123";
    gen_ed25519(key_path, Some(passphrase));
    let pubkey = pubkey_line(key_path);

    // Install pubkey via the working PHR_TEST_KEY channel, then
    // small settle so sshd re-reads authorized_keys (sshd does this
    // on every auth attempt by default, but a tiny wait guards
    // against flaky first-connect races on slow runners).
    install_pubkey_via_passhrs(&pubkey);
    thread::sleep(Duration::from_millis(500));

    // Try without --identity-passphrase first — should FAIL.
    let (ok_no_phrase, stdout, stderr) =
        run_passhrs_with_key(key_path, &[], "echo should_not_appear");
    assert!(
        !ok_no_phrase,
        "auth without --identity-passphrase should fail\nstdout: {}\nstderr: {}",
        stdout, stderr
    );

    // Now with --identity-passphrase — should succeed.
    let (ok_phrase, stdout_phrase, stderr_phrase) = run_passhrs_with_key(
        key_path,
        &["--identity-passphrase", passphrase],
        "echo key_phrase_ok",
    );
    assert!(
        ok_phrase && stdout_phrase.contains("key_phrase_ok"),
        "key+passphrase auth should succeed\nstdout: {}\nstderr: {}",
        stdout_phrase,
        stderr_phrase
    );

    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(format!("{}.pub", key_path));
}

// ======================================================================

/// RSA key auth — verifies SHA-512/SHA-256 fallback for OpenSSH 8.8+.
/// `ssh-rsa` (SHA-1) was disabled by default in OpenSSH 8.8; the
/// russh client in passhrs must fall through to `rsa-sha2-512` or
/// `rsa-sha2-256` when sshd offers it. This was the original bug
/// behind Issue #1; the regression test lives here.
///
/// We use RSA-3072 because it's the most-deployed variant and what
/// `ssh-keygen -t rsa` defaults to on most distros. RSA-4096 would
/// also work but is ~10× slower to generate and doesn't add
/// coverage for the SHA-2 fallback.
#[test]
#[ignore = "requires native sshd on 127.0.0.1:22222 + PHR_TEST_KEY auth working"]
fn test_rsa_key_auth() {
    if !sshd_ok() {
        eprintln!("SKIP: no sshd");
        return;
    }
    // install_pubkey_via_passhrs reads PHR_TEST_KEY via auth_args(),
    // so the same env-var check guards both this test and the
    // passphrase test above — no need to bind it here.
    if std::env::var("PHR_TEST_KEY")
        .ok()
        .is_none_or(|k| k.is_empty())
    {
        eprintln!("SKIP: PHR_TEST_KEY not set");
        return;
    }

    let key_path = "/tmp/phr_test_rsa_id";
    gen_rsa(key_path, 3072, None);
    let pubkey = pubkey_line(key_path);

    install_pubkey_via_passhrs(&pubkey);
    thread::sleep(Duration::from_millis(500));

    let (ok, stdout, stderr) = run_passhrs_with_key(key_path, &[], "echo rsa_sha2_ok");
    assert!(
        ok && stdout.contains("rsa_sha2_ok"),
        "RSA key auth should succeed (SHA-512/SHA-256 fallback)\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(format!("{}.pub", key_path));
}
