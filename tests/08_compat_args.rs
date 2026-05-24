#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: SSH 兼容参数 -C、-4、-6、-A、-a、-J、-S、-l、-p
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
fn test_compression_flag() {
    let (_, _, stderr) = run_phr(&["-C", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_ipv4_flag() {
    let (_, _, stderr) = run_phr(&["-4", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_ipv6_flag() {
    let (_, _, stderr) = run_phr(&["-6", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_agent_forward_on() {
    let (_, _, stderr) = run_phr(&["-A", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_agent_forward_off() {
    let (_, _, stderr) = run_phr(&["-a", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_proxy_jump() {
    let (_, _, stderr) = run_phr(&["-J", "jumpuser@jumphost:2222", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_control_socket() {
    let (_, _, stderr) = run_phr(&["-S", "/tmp/phr-ctrl.sock", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_login_name() {
    let (_, _, stderr) = run_phr(&["-l", "admin", "serverhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_port_flag() {
    let (_, _, stderr) = run_phr(&["-p", "2222", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_compression_with_push() {
    let (_, _, stderr) = run_phr(&[
        "-C",
        "--push",
        "/tmp/a.txt:/tmp/a.txt",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_compression_with_forward() {
    let (_, _, stderr) = run_phr(&["-C", "-L", "8080:localhost:80", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_compression_with_rsync() {
    let (_, _, stderr) = run_phr(&["-C", "--rsync", "/local:/remote", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_full_openssl_compatible() {
    let (_, _, stderr) = run_phr(&[
        "-p",
        "12322",
        "-N",
        "-f",
        "-C",
        "-n",
        "-i",
        "/tmp/id_rsa",
        "-o",
        "TCPKeepAlive=yes",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "user@43.129.204.111",
        "-L",
        "0.0.0.0:8118:127.0.0.1:8118",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
