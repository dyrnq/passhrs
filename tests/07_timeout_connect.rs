#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: --connect-timeout、--timeout、-E 日志、-q 静默
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
fn test_connect_timeout() {
    let (_, _, stderr) = run_phr(&["--connect-timeout", "5", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_inactivity_timeout() {
    let (_, _, stderr) = run_phr(&["--timeout", "30", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_both_timeouts() {
    let (_, _, stderr) = run_phr(&[
        "--connect-timeout",
        "10",
        "--timeout",
        "60",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_quiet_mode() {
    let (success, _, stderr) = run_phr(&["-q", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
    // --help should still work in quiet mode without connecting
    let (_, stdout, _) = run_phr(&["-q", "--help"]);
    assert!(stdout.contains("passhrs"));
}

#[test]
fn test_log_file() {
    use std::fs;
    let log_path = "/tmp/phr_test_log.txt";
    let _ = fs::remove_file(log_path);
    let (_, _, stderr) = run_phr(&["-E", log_path, "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
    // Clean up
    let _ = fs::remove_file(log_path);
}

#[test]
fn test_version_flag() {
    let (_, stdout, _) = run_phr(&["-V"]);
    assert!(stdout.contains("passhrs"));
}

#[test]
fn test_verbose_levels() {
    let (_, _, stderr) = run_phr(&["-v", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
    let (_, _, stderr) = run_phr(&["-vv", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
    let (_, _, stderr) = run_phr(&["-vvv", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
