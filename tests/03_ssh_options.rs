#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: -o SSH选项解析、-F、-i、--password、--identity-passphrase
use std::process::Command;

fn run_phr(args: &[&str]) -> (bool, String, String) {
    let output = Command::new("./target/release/passhrs")
        .args(args)
        .output()
        .expect("failed to run passhrs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn test_o_option_strict_host_key() {
    let (_, _, stderr) = run_phr(&["-o", "StrictHostKeyChecking=no", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_o_option_known_hosts() {
    let (_, _, stderr) = run_phr(&["-o", "UserKnownHostsFile=/dev/null", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_o_option_tcp_keepalive() {
    let (_, _, stderr) = run_phr(&[
        "-o",
        "TCPKeepAlive=yes",
        "-o",
        "ServerAliveInterval=10",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_password_long_arg() {
    let (_, _, stderr) = run_phr(&["--password", "mypassword", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_identity_passphrase() {
    let (_, _, stderr) = run_phr(&[
        "--identity-passphrase",
        "mypassphrase",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_identity_file() {
    let (_, _, stderr) = run_phr(&["-i", "/tmp/test_key", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
