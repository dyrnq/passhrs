#![allow(clippy::zombie_processes, clippy::needless_borrow, clippy::needless_borrows_for_generic_args)]
/// -i 私钥认证 + --identity-passphrase 集成测试
///
/// 在 Docker SSH 容器中创建密钥对，测试私钥登录和加密私钥登录。
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const HOST: &str = "127.0.0.1";
const PORT: &str = "22222";
const USER: &str = "testuser";

fn container_ok() -> bool {
    Command::new("docker")
        .args(["ps", "--filter", "name=phr-test-ssh", "--format", ""])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "phr-test-ssh")
        .unwrap_or(false)
}

fn setup_keypair(passphrase: Option<&str>) -> (String, String) {
    let key_path = "/tmp/phr_test_id";
    let pub_path = format!("{}.pub", key_path);

    // Remove old keys
    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(&pub_path);

    // Generate key
    let mut cmd = Command::new("ssh-keygen");
    cmd.args(["-t", "ed25519", "-f", &key_path, "-N"]);
    if let Some(pw) = passphrase {
        cmd.arg(pw);
    } else {
        cmd.arg("");
    }
    let out = cmd.output().expect("ssh-keygen failed");
    assert!(
        out.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Read pub key
    let pub_key = std::fs::read_to_string(&pub_path).expect("read pubkey");
    (key_path.to_string(), pub_key.trim().to_string())
}

fn add_key_to_container(pub_key: &str) {
    // Ensure .ssh dir and authorized_keys
    let key_setup = format!(
        "mkdir -p ~testuser/.ssh && echo '{}' >> ~testuser/.ssh/authorized_keys && chown -R testuser:testuser ~testuser/.ssh && chmod 600 ~testuser/.ssh/authorized_keys",
        pub_key
    );
    let out = Command::new("docker")
        .args(["exec", "phr-test-ssh", "sh", "-c", &key_setup])
        .output()
        .expect("docker exec key setup");
    assert!(
        out.status.success(),
        "key setup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn cleanup_key(key_path: &str) {
    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(format!("{}.pub", key_path));
}

#[test]
#[ignore = "requires docker SSH container running"]
fn test_key_auth_no_passphrase() {
    if !container_ok() {
        eprintln!("SKIP: no container");
        return;
    }

    let (key_path, pub_key) = setup_keypair(None);
    add_key_to_container(&pub_key);
    thread::sleep(Duration::from_secs(1));

    let out = Command::new("./target/release/passhrs")
        .args([
            "-p",
            PORT,
            "-i",
            &key_path,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            &format!("{}@{}", USER, HOST),
            "echo",
            "key_ok",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("passhrs key auth");

    cleanup_key(&key_path);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("key_ok"),
        "key auth should succeed\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}

#[test]
#[ignore = "requires docker SSH container running"]
fn test_key_auth_with_passphrase() {
    if !container_ok() {
        eprintln!("SKIP: no container");
        return;
    }

    let passphrase = "my-test-passphrase-123";
    let (key_path, pub_key) = setup_keypair(Some(passphrase));
    add_key_to_container(&pub_key);
    thread::sleep(Duration::from_secs(1));

    let out = Command::new("./target/release/passhrs")
        .args([
            "-p",
            PORT,
            "-i",
            &key_path,
            "--identity-passphrase",
            passphrase,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            &format!("{}@{}", USER, HOST),
            "echo",
            "key_phrase_ok",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("passhrs key+passphrase auth");

    cleanup_key(&key_path);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("key_phrase_ok"),
        "key+passphrase auth should succeed\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}
