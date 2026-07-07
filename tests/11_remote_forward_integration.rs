#![allow(clippy::zombie_processes)]
//! -R 远程转发集成测试
//!
//! 这些测试验证 -R 的参数解析和远程端口绑定。
//! 数据面转发已在手动测试中确认工作。
use std::process::Command;

const HOST: &str = "127.0.0.1";
const PORT: &str = "22222";
// Same three-way platform split as tests/15_native_sshd_integration.rs:
// Linux runs as the pre-existing `runner` user; macOS uses a
// freshly-dscl'd `testuser` (Sonoma+ secure-token lockout blocks
// every password-set API for the runner account, so the setup
// script creates a dedicated testuser); windows-2022 (since runner
// 2.305.0) ships `runneradmin`.
#[cfg(target_os = "windows")]
const USER: &str = "runneradmin";
#[cfg(target_os = "macos")]
const USER: &str = "testuser";
#[cfg(target_os = "linux")]
const USER: &str = "runner";
const PASS: &str = "PassTest1234!";

// `-R <spec>:<host>:<port>` — well-formed forms must not produce an
// "error:" line in stderr. This is a CLI-parse smoke test only; the
// actual -R data plane round-trip is covered by
// `tests/15_native_sshd_integration::test_remote_forward_data_plane_round_trip`
// (which exercises native sshd via the tests/sshd setup scripts and
// proves bytes flow end-to-end). Kept here as a focused -R spec parser
// regression: a future change to `ForwardSpec::parse` that mis-handles
// one of these forms would silently regress to a broken -R without
// surfacing in tests/15 (which only exercises one -R shape).
#[test]
#[ignore = "requires ./target/release/passhrs binary + native sshd on 127.0.0.1:22222"]
fn test_r_forward_spec_parsing() {
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

// ---------------------------------------------------------------------
// The two docker-dependent tests in the original file
// (`test_r_port_is_listening_on_remote` and
// `test_r_forward_spec_parsing`'s docker fixture) have been removed:
//
//   * `test_r_port_is_listening_on_remote` — fully redundant. It used
//     `docker exec ... netstat -tlnp` to peek at what sshd was
//     listening on, but the equivalent assertion (port is reachable
//     and bytes flow) is what `test_remote_forward_data_plane_round_trip`
//     in tests/15_native_sshd_integration.rs already proves end-to-end
//     against the native sshd fixture.
//
//   * `fport()` and `container_ok()` helpers — only used by the dead
//     test above. `tests/15::pick_unused_port()` (private, reused there)
//     replaces `fport()` if any future test in this file needs an
//     unused port.
//
// The -R data plane has full e2e coverage in tests/15. Issue #20 is
// kept open only for tests/12_key_auth_integration.rs (key auth +
// identity-passphrase + RSA-3072 regression), which has no current
// native-sshd equivalent.
// ---------------------------------------------------------------------
