#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: 端口转发参数解析 (-L, -R, -D)
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
fn test_local_forward_help_shows() {
    let (_, stdout, _) = run_phr(&["--help"]);
    assert!(stdout.contains("-L"), "help should show -L option");
    assert!(stdout.contains("-R"), "help should show -R option");
    assert!(stdout.contains("-D"), "help should show -D option");
}

#[test]
fn test_local_forward_simple() {
    // -L [bind:]port:host:port — just test parsing doesn't crash
    let (_, _, stderr) = run_phr(&["-L", "8080:localhost:80", "user@localhost", "id"]);
    // Should attempt connection, not fail on arg parsing
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_local_forward_bind_addr() {
    let (_, _, stderr) = run_phr(&["-L", "0.0.0.0:8080:localhost:80", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_remote_forward() {
    let (_, _, stderr) = run_phr(&["-R", "9090:localhost:90", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_dynamic_forward() {
    let (_, _, stderr) = run_phr(&["-D", "1080", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_dynamic_forward_bind() {
    let (_, _, stderr) = run_phr(&["-D", "0.0.0.0:1080", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_multiple_forwards() {
    let (_, _, stderr) = run_phr(&[
        "-L",
        "8080:localhost:80",
        "-L",
        "8443:localhost:443",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
