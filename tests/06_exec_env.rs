#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: --exec-env 环境变量参数
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
fn test_exec_env_single() {
    let (_, _, stderr) = run_phr(&[
        "--exec-env",
        "MYVAR=hello",
        "user@localhost",
        "echo",
        "$MYVAR",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_exec_env_multiple() {
    let (_, _, stderr) = run_phr(&[
        "--exec-env",
        "A=1",
        "--exec-env",
        "B=2",
        "user@localhost",
        "env",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_exec_env_from_system() {
    let (_, _, stderr) = run_phr(&["--exec-env", "PATH", "user@localhost", "echo", "$PATH"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_exec_env_empty_value() {
    let (_, _, stderr) = run_phr(&["--exec-env", "EMPTY=", "user@localhost", "env"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
