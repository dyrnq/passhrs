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
//! `127.0.0.1:22222` with a known `testuser:PassTest1234#` account,
//! and the tests exercise passhrs end-to-end against it.
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
const USER: &str = "runner";
const PASS: &str = "PassTest1234#";
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

fn run_phr(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(BIN).args(args).output().expect("run passhrs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn dest() -> String {
    format!("{}@{}", USER, HOST)
}

// ======================================================================
// 基本连接测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_basic_command_exec() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
        "--password",
        PASS,
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
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_exec_env_remote() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_connect_timeout_integration() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = format!("{}@10.255.255.1", USER);
    let out = Command::new(BIN)
        .args([
            "--connect-timeout",
            "3",
            "--password",
            PASS,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            &d,
            "echo",
            "should_not_reach",
        ])
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_command_exit_code_zero() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_command_multiple_args() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_command_uname() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_command_which() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_command_yes_head() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_command_compress_flag() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_command_with_pty() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_ps_with_pipe() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_force_tty_flag() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_command_with_dest_ipv6() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = format!("{}@[::1]", USER);
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_local_forward_spawn() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let local_port = "22300";
    let mut child = Command::new(BIN)
        .args([
            "-p",
            PORT,
            "--password",
            PASS,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-L",
            &format!("{}:localhost:{}", local_port, PORT),
            "-N",
            &format!("{}@{}", USER, HOST),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn -L");
    thread::sleep(Duration::from_secs(2));
    let _ = child.kill();
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_socks5_proxy_spawn() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let socks_port = "21080";
    let mut child = Command::new(BIN)
        .args([
            "-p",
            PORT,
            "--password",
            PASS,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-D",
            socks_port,
            "-N",
            &format!("{}@{}", USER, HOST),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn -D");
    thread::sleep(Duration::from_secs(2));
    let _ = child.kill();
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_http_connect_proxy_spawn() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let http_port = "21081";
    let mut child = Command::new(BIN)
        .args([
            "-p",
            PORT,
            "--password",
            PASS,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-H",
            http_port,
            "-N",
            &format!("{}@{}", USER, HOST),
        ])
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_fork_background() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = format!("{}@{}", USER, HOST);
    let out = Command::new(BIN)
        .args([
            "-p",
            PORT,
            "--password",
            PASS,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-f",
            &d,
            "sleep",
            "2",
        ])
        .output()
        .expect("fork test");
    assert!(out.status.success(), "fork exit non-zero");
}

// ======================================================================
// 选项测试
// ======================================================================

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_multiple_ssh_options() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = dest();
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
        "--password",
        PASS,
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
        "--password",
        PASS,
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
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
fn test_proxy_jump_self() {
    if !sshd_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let d = format!("{}@{}", USER, HOST);
    let a = [
        "-p",
        PORT,
        "--password",
        PASS,
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
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("run passhrs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
        "--password",
        PASS,
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
    // The remote `env` output must contain the forwarded locale variables,
    // proving channel.set_env reached the remote (AcceptEnv accepted them).
    assert!(
        stdout.contains("LANG=en_US.UTF-8"),
        "LANG not forwarded to remote; env output: {}",
        stdout
    );
    assert!(
        stdout.contains("LC_ALL=en_US.UTF-8"),
        "LC_ALL not forwarded to remote; env output: {}",
        stdout
    );
}

#[test]
#[ignore = "requires native OpenSSH on 127.0.0.1:22222 with runner:PassTest1234#"]
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
        "--password",
        PASS,
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
