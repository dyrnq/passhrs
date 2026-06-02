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

// --rsync 参数解析测试

#[test]
fn test_rsync_upload_spec() {
    let (_, _, stderr) = run_phr(&["--rsync", "/local/dir:/remote/dir", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_rsync_with_opt_delete() {
    let (_, _, stderr) = run_phr(&[
        "--rsync",
        "/local/dir:/remote/dir",
        "--rsync-opt",
        "delete",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_rsync_with_opt_dry_run() {
    let (_, _, stderr) = run_phr(&[
        "--rsync",
        "/local/dir:/remote/dir",
        "--rsync-opt",
        "dry-run",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_rsync_with_opt_checksum() {
    let (_, _, stderr) = run_phr(&[
        "--rsync",
        "/local/dir:/remote/dir",
        "--rsync-opt",
        "checksum",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_rsync_with_opt_exclude() {
    let (_, _, stderr) = run_phr(&[
        "--rsync",
        "/local/dir:/remote/dir",
        "--rsync-opt",
        "exclude=.git",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_rsync_multiple_opts() {
    let (_, _, stderr) = run_phr(&[
        "--rsync",
        "/local/dir:/remote/dir",
        "--rsync-opt",
        "delete",
        "--rsync-opt",
        "exclude=.git",
        "--rsync-opt",
        "dry-run",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_rsync_relative_path_fails() {
    let (_, _, stderr) = run_phr(&[
        "--rsync",
        "relative/path:/remote/dir",
        "user@localhost",
        "id",
    ]);
    // Should not panic — error is expected (either path validation or auth failure)
    assert!(!stderr.contains("thread"), "should not panic: {}", stderr);
}

#[test]
fn test_rsync_invalid_spec() {
    let (_, _, stderr) = run_phr(&["--rsync", "invalid", "user@localhost", "id"]);
    let combined = stderr.to_lowercase();
    assert!(
        !combined.contains("thread") || combined.contains("error"),
        "should not panic: {}",
        stderr
    );
}

#[test]
fn test_rsync_push_and_pull_combined() {
    let (_, _, stderr) = run_phr(&[
        "--rsync",
        "/local/a:/remote/a",
        "--push",
        "/tmp/extra.sh:/tmp/extra.sh",
        "--pull",
        "/tmp/result.log:/tmp/result.log",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_rsync_with_unknown_opt() {
    let (_, _, stderr) = run_phr(&[
        "--rsync",
        "/local/dir:/remote/dir",
        "--rsync-opt",
        "unknown_option_xyz",
        "user@localhost",
        "id",
    ]);
    // Should warn about unknown opt but not error
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
