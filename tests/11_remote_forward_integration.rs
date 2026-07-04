#![allow(clippy::zombie_processes)]
use std::net::TcpListener;
/// -R 远程转发集成测试（需要 Docker SSH 容器，AllowTcpForwarding yes）
///
/// 这些测试验证 -R 的参数解析和远程端口绑定。
/// 数据面转发已在手动测试中确认工作。
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const HOST: &str = "127.0.0.1";
const PORT: &str = "22222";
const USER: &str = "runner";
const PASS: &str = "PassTest1234#";

fn fport() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn container_ok() -> bool {
    Command::new("docker")
        .args(["ps", "--filter", "name=phr-test-ssh", "--format", ""])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "phr-test-ssh")
        .unwrap_or(false)
}

#[test]
#[ignore = "requires docker SSH container running with AllowTcpForwarding yes"]
fn test_r_port_is_listening_on_remote() {
    if !container_ok() {
        eprintln!("SKIP: no container");
        return;
    }
    let rp = fport();

    // Start -R connecting to a known port (localhost:2222 = sshd itself)
    let mut child = Command::new("./target/release/passhrs")
        .args([
            "-p",
            PORT,
            "--password",
            PASS,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-R",
            &format!("{}:localhost:{}", rp, PORT),
            "-N",
            &format!("{}@{}", USER, HOST),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn -R");
    thread::sleep(Duration::from_secs(3));

    // Verify remote port is listening via docker exec (bypassing passhrs)
    let out = Command::new("docker")
        .args(["exec", "phr-test-ssh", "netstat", "-tlnp"])
        .output()
        .expect("docker exec");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let port_str = format!(":{} ", rp);

    // Cleanup
    let _ = child.kill();
    thread::sleep(Duration::from_millis(200));

    assert!(
        stdout.contains(&port_str),
        "port {} should be listening on remote\nnetstat:\n{}",
        rp,
        stdout
    );
}

#[test]
#[ignore = "requires docker SSH container running with AllowTcpForwarding yes"]
fn test_r_forward_spec_parsing() {
    // Just test that -R with various spec formats doesn't cause CLI parse error
    for spec in &[
        "8080:localhost:80",
        "0.0.0.0:8080:localhost:80",
        "127.0.0.1:8080:localhost:80",
    ] {
        let out = Command::new("./target/release/passhrs")
            .args([
                "-p",
                PORT,
                "--password",
                PASS,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-R",
                spec,
                &format!("{}@{}", USER, HOST),
                "echo",
                "ok",
            ])
            .output()
            .expect("passhrs");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("error:"), "spec={} err={}", spec, stderr);
    }
}
