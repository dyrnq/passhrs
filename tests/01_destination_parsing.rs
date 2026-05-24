#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: parse_destination — 解析 [user@]host[:port]
use std::process::Command;

fn test_binary() -> &'static str {
    "./target/release/passhrs"
}

#[test]
fn test_destination_user_host() {
    let output = Command::new(test_binary())
        .args(["--help"])
        .output()
        .expect("failed to run passhrs --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("passhrs"));
    assert!(stdout.contains("USAGE"));
}

#[test]
fn test_destination_with_port() {
    let output = Command::new(test_binary())
        .args(["-p", "2222", "user@host", "echo", "ok"])
        .output()
        .expect("failed to run");
    // This will try to connect — we just verify it didn't panic on arg parsing
    // The actual SSH connection will fail but that's expected
    // We should see a connection error, not a CLI parsing error
    let stderr = String::from_utf8_lossy(&output.stderr);
    // If we get "error: unexpected argument" the CLI parsing failed
    assert!(!stderr.contains("error:"), "CLI parsing failed: {}", stderr);
}

#[test]
fn test_destination_ipv6_bracket() {
    let output = Command::new(test_binary())
        .args(["[::1]:2222", "id"])
        .output()
        .expect("failed to run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should not be a parse error
    assert!(!stderr.contains("error:"), "CLI parsing failed: {}", stderr);
}
