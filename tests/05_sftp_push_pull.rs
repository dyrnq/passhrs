#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: --push / --pull 文件传输参数解析
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
fn test_push_single_file() {
    let (_, _, stderr) = run_phr(&[
        "--push",
        "/tmp/local.txt:/remote/path.txt",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_push_multiple() {
    let (_, _, stderr) = run_phr(&[
        "--push",
        "/tmp/a.txt:/remote/a.txt",
        "--push",
        "/tmp/b.txt:/remote/b.txt",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_pull_single_file() {
    let (_, _, stderr) = run_phr(&[
        "--pull",
        "/remote/path.txt:/tmp/local.txt",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_pull_multiple() {
    let (_, _, stderr) = run_phr(&[
        "--pull",
        "/remote/a.txt:/tmp/a.txt",
        "--pull",
        "/remote/b.txt:/tmp/b.txt",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_push_and_pull() {
    let (_, _, stderr) = run_phr(&[
        "--push",
        "/tmp/script.sh:/tmp/script.sh",
        "--pull",
        "/tmp/result.log:/tmp/result.log",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_push_with_command() {
    let (_, _, stderr) = run_phr(&[
        "--push",
        "/tmp/script.sh:/tmp/script.sh",
        "user@localhost",
        "bash",
        "/tmp/script.sh",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_push_invalid_spec() {
    let (_, _, stderr) = run_phr(&["--push", "invalid_spec", "user@localhost", "id"]);
    // Should fail gracefully, not panic
    let combined = stderr.to_lowercase();
    assert!(
        !combined.contains("thread") || combined.contains("error"),
        "should not panic: {}",
        stderr
    );
}
