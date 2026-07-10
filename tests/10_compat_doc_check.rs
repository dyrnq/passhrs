#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: --help 输出的参数是否完整
use std::process::Command;

#[test]
fn test_help_covers_all_options() {
    let output = Command::new("./target/release/passhrs")
        .arg("--help")
        .output()
        .expect("failed to run passhrs --help");
    assert!(output.status.success());
    let help_text = String::from_utf8_lossy(&output.stdout);

    // SSH 兼容参数
    for opt in &[
        "-L", "-R", "-D", "-i", "-o", "-p", "-N", "-f", "-C", "-v", "-q", "-E", "-J", "-t", "-T",
        "-n", "-4", "-6", "-A", "-a", "-l", "-S", "-H", "-V", "-c", "-m", "-g", "-Q", "-b", "-y",
        "-O",
    ] {
        assert!(help_text.contains(opt), "help should mention {}", opt);
    }

    // 独有参数（仅在 help 中存在的）
    for opt in &[
        "--password",
        "--identity-passphrase",
        "--exec-env",
        "--connect-timeout",
        "--timeout",
        "--push",
        "--pull",
        "--rsync",
    ] {
        assert!(help_text.contains(opt), "help should mention {}", opt);
    }
}
