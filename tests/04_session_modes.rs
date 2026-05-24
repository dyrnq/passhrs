#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: 会话模式 -N、-t、-n、-f、command、shell
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
fn test_no_command_mode() {
    let (_, _, stderr) = run_phr(&["-N", "user@localhost"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_force_tty() {
    let (_, _, stderr) = run_phr(&["-t", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_redirect_stdin() {
    let (_, _, stderr) = run_phr(&["-n", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_fork_to_background() {
    let (_, _, stderr) = run_phr(&["-f", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_command_exec() {
    let (_, _, stderr) = run_phr(&["user@localhost", "echo", "hello"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_shell_mode() {
    let (_, _, stderr) = run_phr(&["user@localhost"]);
    // Without command and without -N, should open shell
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_combined_nohup_like() {
    // -N -f -L combination
    let (_, _, stderr) = run_phr(&["-N", "-f", "-L", "9999:localhost:9999", "user@localhost"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
