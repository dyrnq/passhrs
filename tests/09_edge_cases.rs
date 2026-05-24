#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: 边界情况和错误处理
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
fn test_no_args_shows_help() {
    let (_, _stdout, stderr) = run_phr(&[] as &[&str]);
    // passhrs says "no destination specified" when run without args
    // Should not panic — just show error
    assert!(!stderr.contains("thread"), "should not panic: {}", stderr);
}

#[test]
fn test_help_flag() {
    let (_, stdout, _) = run_phr(&["--help"]);
    assert!(stdout.contains("USAGE"));
    assert!(stdout.contains("OPTIONS"));
}

#[test]
fn test_help_short() {
    let (_, _stdout, stderr) = run_phr(&["-h"]);
    let output = format!("{}{}", _stdout, stderr);
    assert!(output.contains("passhrs"), "output: {}", output);
}

#[test]
fn test_unknown_option() {
    let (_, _, stderr) = run_phr(&["--nonexistent-flag", "user@host"]);
    // Should error gracefully, not panic
    assert!(
        stderr.contains("error") || stderr.contains("USAGE"),
        "should show error for unknown flag: {}",
        stderr
    );
}

#[test]
fn test_invalid_port() {
    let (_, _, stderr) = run_phr(&["-p", "abc", "user@host"]);
    assert!(
        stderr.contains("error"),
        "should error on invalid port: {}",
        stderr
    );
}

#[test]
fn test_invalid_forward_spec() {
    let (_, _, stderr) = run_phr(&["-L", "invalid", "user@host"]);
    // Should fail gracefully
    let combined = stderr.to_string();
    assert!(
        !combined.contains("panic") && !combined.contains("thread"),
        "should not panic: {}",
        stderr
    );
}

#[test]
fn test_invalid_dynamic_spec() {
    let (_, _, stderr) = run_phr(&["-D", "", "user@host"]);
    let combined = stderr.to_string();
    assert!(
        !combined.contains("panic") && !combined.contains("thread"),
        "should not panic: {}",
        stderr
    );
}

#[test]
fn test_multi_value_o_option() {
    let (_, _, stderr) = run_phr(&[
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "UserKnownHostsFile=/tmp/known_hosts",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_identity_file_not_found() {
    // Should handle missing key gracefully
    let (_, _, stderr) = run_phr(&["-i", "/nonexistent/path/key", "user@localhost", "id"]);
    // Should not panic
    assert!(!stderr.contains("thread"), "should not panic: {}", stderr);
}

#[test]
fn test_ipv6_address() {
    let (_, _, stderr) = run_phr(&["user@::1", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
