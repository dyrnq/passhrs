#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: --password 和 --identity-passphrase 支持从文件读取 (@file 和自动检测)
use std::fs;
use std::io::Write;
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

/// 创建一个临时文件，返回 (路径, 锁文件句柄)
fn create_temp_file(content: &str, suffix: &str) -> (std::path::PathBuf, fs::File) {
    let tmp_dir = std::env::temp_dir();
    let path = tmp_dir.join(format!("phr_test_{}_{}", std::process::id(), suffix));
    let mut f = fs::File::create(&path).expect("create temp file");
    write!(f, "{}", content).expect("write temp file");
    f.flush().expect("flush");
    (path, f)
}

#[test]
fn test_password_from_file_explicit() {
    let (path, _f) = create_temp_file("my_secret_pass", "pw1");
    let (_, _, stderr) = run_phr(&[
        "--password",
        &format!("@{}", path.display()),
        "user@localhost",
        "id",
    ]);
    let _ = fs::remove_file(&path);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_password_from_file_auto() {
    let (path, _f) = create_temp_file("auto_detect_pass", "pw2");
    let (_, _, stderr) = run_phr(&[
        "--password",
        &path.display().to_string(),
        "user@localhost",
        "id",
    ]);
    let _ = fs::remove_file(&path);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_passphrase_from_file_explicit() {
    let (path, _f) = create_temp_file("my_key_passphrase", "pp1");
    let (_, _, stderr) = run_phr(&[
        "--identity-passphrase",
        &format!("@{}", path.display()),
        "user@localhost",
        "id",
    ]);
    let _ = fs::remove_file(&path);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_passphrase_from_file_auto() {
    let (path, _f) = create_temp_file("auto_passphrase", "pp2");
    let (_, _, stderr) = run_phr(&[
        "--identity-passphrase",
        &path.display().to_string(),
        "user@localhost",
        "id",
    ]);
    let _ = fs::remove_file(&path);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_password_plaintext_still_works() {
    let (_, _, stderr) = run_phr(&["--password", "plaintext", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_password_file_with_trailing_newline() {
    let (path, _f) = create_temp_file("trailing\n", "pw3");
    let (_, _, stderr) = run_phr(&[
        "--password",
        &format!("@{}", path.display()),
        "user@localhost",
        "id",
    ]);
    let _ = fs::remove_file(&path);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_password_file_not_found() {
    let (_, _, stderr) = run_phr(&[
        "--password",
        "@/nonexistent/path/secret",
        "user@localhost",
        "id",
    ]);
    assert!(
        stderr.contains("error") || stderr.contains("failed to read"),
        "should error on missing file: {}",
        stderr
    );
}

#[test]
fn test_password_short_string_not_treated_as_file() {
    let (_, _, stderr) = run_phr(&["--password", "123", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_password_special_chars_no_file() {
    let (_, _, stderr) = run_phr(&["--password", "!@#$%", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
