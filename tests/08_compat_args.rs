#![allow(clippy::zombie_processes, unused_variables, dead_code)]
/// Test: SSH 兼容参数 -C、-4、-6、-A、-a、-J、-S、-l、-p
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
fn test_compression_flag() {
    let (_, _, stderr) = run_phr(&["-C", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_ipv4_flag() {
    let (_, _, stderr) = run_phr(&["-4", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_ipv6_flag() {
    let (_, _, stderr) = run_phr(&["-6", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_agent_forward_on() {
    let (_, _, stderr) = run_phr(&["-A", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_agent_forward_off() {
    let (_, _, stderr) = run_phr(&["-a", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_proxy_jump() {
    let (_, _, stderr) = run_phr(&["-J", "jumpuser@jumphost:2222", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_control_socket() {
    let (_, _, stderr) = run_phr(&["-S", "/tmp/phr-ctrl.sock", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

// `-O <cmd>`: control command sent to a master at `-S <path>`
// (`check` / `exit` / `stop`). Companion to `-S` (Issue #54).
// These clap-acceptance tests pin the parser surface; the
// connect/dispatch behavior is verified end-to-end in
// tests/15 (`test_control_command_*`). The `-S` path is required
// (the runtime rejects `-O` without `-S` with its own error
// message) but `dest_str` is NOT required — `-O` is a
// control-client operation, not an SSH invocation.
//
// Unix-only: `-O` rides on Issue #29's Unix-domain-socket
// protocol. The Windows equivalent is a follow-up issue (named
// pipes). On Windows the `-O` dispatch in main.rs is compiled
// out, so `-O check` falls through to the empty-destination
// print-help path and exits 0 — which the assertion below
// would catch as a false failure. Gating on `cfg(unix)` keeps
// the test set honest about what the binary can actually do
// on each platform.
#[cfg(unix)]
#[test]
fn test_control_command_short_check() {
    // `-O check` must be accepted even without a destination —
    // the early-exit in `main()` runs before the help fallback.
    // We can't assert on the exact behavior here because the
    // control socket path /tmp/...sock doesn't exist; we just
    // pin that clap accepts the combination and the binary
    // doesn't crash on a parser-level error.
    let (ok, _, stderr) = run_phr(&["-O", "check", "-S", "/tmp/phr-ctrl-cmd.sock"]);
    // ok=false is fine — the runtime rejects the missing master;
    // what we DON'T want is a clap "unexpected argument" or
    // "a value is required" failure.
    assert!(
        !stderr.contains("unexpected argument"),
        "clap should recognize -O, but stderr complains: {}",
        stderr
    );
    assert!(
        !stderr.contains("a value is required"),
        "clap should accept the -O value, but stderr complains: {}",
        stderr
    );
    assert!(!ok, "with no live master, -O check must exit non-zero");
}

#[cfg(unix)]
#[test]
fn test_control_command_short_exit() {
    let (ok, _, stderr) = run_phr(&["-O", "exit", "-S", "/tmp/phr-ctrl-cmd.sock"]);
    assert!(!stderr.contains("unexpected argument"), "{}", stderr);
    assert!(!stderr.contains("a value is required"), "{}", stderr);
    assert!(!ok, "with no live master, -O exit must exit non-zero");
}

#[cfg(unix)]
#[test]
fn test_control_command_short_stop() {
    // `stop` is OpenSSH's alias for `exit`. The clap parser
    // accepts any string as the value; the runtime dispatches.
    let (ok, _, stderr) = run_phr(&["-O", "stop", "-S", "/tmp/phr-ctrl-cmd.sock"]);
    assert!(!stderr.contains("unexpected argument"), "{}", stderr);
    assert!(!stderr.contains("a value is required"), "{}", stderr);
    assert!(!ok, "with no live master, -O stop must exit non-zero");
}

#[cfg(unix)]
#[test]
fn test_control_command_long() {
    let (ok, _, stderr) = run_phr(&[
        "--control-command",
        "check",
        "--control-path",
        "/tmp/phr-ctrl-cmd.sock",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
    assert!(
        !ok,
        "with no live master, long form must also exit non-zero"
    );
}

#[cfg(unix)]
#[test]
fn test_control_command_requires_s() {
    // `-O check` without `-S` is a runtime error (the control
    // module needs a path to connect to). We verify clap accepts
    // the combination and the binary's stderr mentions the
    // missing `-S`.
    let (ok, _, stderr) = run_phr(&["-O", "check"]);
    assert!(!ok, "-O without -S must exit non-zero");
    assert!(
        stderr.contains("-O requires") || stderr.contains("-S"),
        "expected a runtime message about -S requirement, got: {:?}",
        stderr
    );
}

// `-Q <what>`: list supported algorithms. No SSH traffic, no
// destination. Each variant exits 0 and prints at least one name
// on stdout. `-Q help` lists the accepted queries. `-Q bogus`
// exits non-zero and stderr names the unknown query.
#[test]
fn test_query_cipher() {
    let (ok, stdout, _) = run_phr(&["-Q", "cipher"]);
    assert!(ok, "-Q cipher must exit 0");
    assert!(
        !stdout.trim().is_empty(),
        "-Q cipher must print at least one algorithm name"
    );
}

#[test]
fn test_query_mac() {
    let (ok, stdout, _) = run_phr(&["-Q", "mac"]);
    assert!(ok, "-Q mac must exit 0");
    assert!(!stdout.trim().is_empty());
}

#[test]
fn test_query_kex() {
    let (ok, stdout, _) = run_phr(&["-Q", "kex"]);
    assert!(ok, "-Q kex must exit 0");
    assert!(!stdout.trim().is_empty());
}

#[test]
fn test_query_compression() {
    let (ok, stdout, _) = run_phr(&["-Q", "compression"]);
    assert!(ok, "-Q compression must exit 0");
    assert!(!stdout.trim().is_empty());
}

#[test]
fn test_query_key() {
    let (ok, stdout, _) = run_phr(&["-Q", "key"]);
    assert!(ok, "-Q key must exit 0");
    assert!(!stdout.trim().is_empty());
}

#[test]
fn test_query_help_lists_accepted_queries() {
    let (ok, stdout, _) = run_phr(&["-Q", "help"]);
    assert!(ok, "-Q help must exit 0");
    for q in &["cipher", "mac", "kex", "compression", "key", "help"] {
        assert!(
            stdout.contains(q),
            "-Q help must mention {} (got: {:?})",
            q,
            stdout
        );
    }
}

#[test]
fn test_query_unknown_exits_nonzero() {
    let (ok, _, stderr) = run_phr(&["-Q", "definitely-not-a-real-query"]);
    assert!(!ok, "unknown -Q must exit non-zero");
    assert!(
        stderr.contains("definitely-not-a-real-query"),
        "stderr must mention the rejected query, got: {:?}",
        stderr
    );
    // Message format matches OpenSSH: "Valid queries: cipher, …, help".
    // The "help" entry is the canonical pointer to discoverability.
    assert!(
        stderr.contains("Valid queries") && stderr.contains("help"),
        "stderr should list the valid queries (incl. help), got: {:?}",
        stderr
    );
}

#[test]
fn test_query_multiple_flags() {
    // Multiple -Q values: each prints in turn, exits 0.
    let (ok, stdout, _) = run_phr(&["-Q", "cipher", "-Q", "mac"]);
    assert!(ok, "multiple -Q must exit 0 when all known");
    assert!(!stdout.trim().is_empty());
}

// `-g / --gateway-ports`: flips the default bind of `-L` and `-D`
// from loopback (127.0.0.1) to wildcard (0.0.0.0). Surfaced
// here as a clap-acceptance test; the bind-side semantics are
// verified end-to-end in tests/15 (test_gateway_ports_binds_wildcard).
#[test]
fn test_gateway_ports_short() {
    let (_, _, stderr) = run_phr(&["-g", "-L", "8118:localhost:80", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_gateway_ports_long() {
    let (_, _, stderr) = run_phr(&[
        "--gateway-ports",
        "-L",
        "8118:localhost:80",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_gateway_ports_via_o_option() {
    // `-o GatewayPorts=yes` is the long-form alias OpenSSH accepts.
    let (_, _, stderr) = run_phr(&[
        "-o",
        "GatewayPorts=yes",
        "-L",
        "8118:localhost:80",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_gateway_ports_via_o_option_no() {
    // `-o GatewayPorts=no` must also be accepted (loopback default).
    let (_, _, stderr) = run_phr(&[
        "-o",
        "GatewayPorts=no",
        "-L",
        "8118:localhost:80",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_gateway_ports_with_dynamic() {
    // `-g` should also flip the default bind of `-D`.
    let (_, _, stderr) = run_phr(&["-g", "-D", "1080", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_login_name() {
    let (_, _, stderr) = run_phr(&["-l", "admin", "serverhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_disable_pty_short() {
    let (_, _, stderr) = run_phr(&["-T", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_disable_pty_long() {
    let (_, _, stderr) = run_phr(&["--no-pty", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_cipher_spec_short() {
    let (_, _, stderr) = run_phr(&["-c", "aes128-ctr", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_cipher_spec_long() {
    let (_, _, stderr) = run_phr(&["--cipher-spec", "aes128-ctr", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_cipher_spec_multi() {
    // comma-separated multi-value: clap value_delimiter=',' splits this
    let (_, _, stderr) = run_phr(&[
        "-c",
        "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_mac_spec_short() {
    let (_, _, stderr) = run_phr(&["-m", "hmac-sha2-256", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_mac_spec_long() {
    let (_, _, stderr) = run_phr(&["--mac-spec", "hmac-sha2-256", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_version_short() {
    // clap 4 auto-version flag provides -V via the `version =`
    // attribute on #[command]. Previously the README lied about
    // this being unimplemented; the test pins it.
    let (ok, stdout, stderr) = run_phr(&["-V"]);
    assert!(ok, "-V should exit 0: {}", stderr);
    assert!(
        stdout.starts_with("passhrs "),
        "-V should print 'passhrs <ver>', got: {}",
        stdout
    );
}

#[test]
fn test_version_long() {
    let (ok, stdout, stderr) = run_phr(&["--version"]);
    assert!(ok, "--version should exit 0: {}", stderr);
    assert!(
        stdout.starts_with("passhrs "),
        "--version should print 'passhrs <ver>', got: {}",
        stdout
    );
}

#[test]
fn test_port_flag() {
    let (_, _, stderr) = run_phr(&["-p", "2222", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_compression_with_push() {
    let (_, _, stderr) = run_phr(&[
        "-C",
        "--push",
        "/tmp/a.txt:/tmp/a.txt",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_compression_with_forward() {
    let (_, _, stderr) = run_phr(&["-C", "-L", "8080:localhost:80", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_compression_with_rsync() {
    let (_, _, stderr) = run_phr(&["-C", "--rsync", "/local:/remote", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

// Issue #27: `--debug-all` is the surviving half of a docs/cli mismatch
// (the other half -- `--nohup` -- was removed from README because it's
// better expressed via the shell's job control). This test pins the
// accept-by-clap surface so a clap-parser regression gets caught
// before the rest of issue #27's flow shows up at the user.
// `-b <address>` / `--bind <address>`: source bind address for
// the outbound SSH connection. Mirrors OpenSSH `-b` and the
// long-form `-o BindAddress=<address>`. Surfaced here as
// clap-acceptance tests; the bind-side semantics (real
// `TcpSocket::bind` before `connect`) are verified end-to-end in
// tests/15 via the same `StderrCapture` helper that
// `test_gateway_ports_binds_wildcard` uses.
#[test]
fn test_bind_address_short() {
    let (_, _, stderr) = run_phr(&["-b", "127.0.0.1", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_bind_address_long() {
    let (_, _, stderr) = run_phr(&["--bind", "127.0.0.1", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_bind_address_via_o_option() {
    // `-o BindAddress=…` is the long-form alias OpenSSH accepts.
    let (_, _, stderr) = run_phr(&["-o", "BindAddress=127.0.0.1", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_bind_address_empty_string_accepted() {
    // `-b ""` is OpenSSH's "let the kernel pick" form. The CLI
    // must accept it without error; `connect_with_bind` treats
    // empty as `None`.
    let (_, _, stderr) = run_phr(&["-b", "", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_bind_address_ipv6() {
    // IPv6 bind should also be accepted by clap. The connect
    // path resolves the address and picks `TcpSocket::new_v6()`
    // for `is_ipv6()` resolved locals.
    let (_, _, stderr) = run_phr(&["-b", "::1", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

// `-y` / `--accept-all-hosts`: unconditionally accept any host
// key. Surfaced here as clap-acceptance tests; the
// `check_server_key` short-circuit is verified end-to-end in
// tests/15 (test_accept_all_host_keys_skips_known_hosts).
#[test]
fn test_accept_all_host_keys_short() {
    let (_, _, stderr) = run_phr(&["-y", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_accept_all_host_keys_long() {
    let (_, _, stderr) = run_phr(&["--accept-all-hosts", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_accept_all_host_keys_with_strict() {
    // `-y` must be accepted alongside `-o StrictHostKeyChecking=yes`
    // (they would otherwise be contradictory; `-y` wins at runtime
    // — the test only verifies clap accepts the combination).
    let (_, _, stderr) = run_phr(&[
        "-y",
        "-o",
        "StrictHostKeyChecking=yes",
        "user@localhost",
        "id",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

// `-e <ch>`: interactive escape character for PTY sessions
// (Issue #57). Mirrors OpenSSH `ssh -e <ch>`: a single byte
// (or caret notation, e.g. `^a` for Ctrl-A) typed at the start
// of a line on the local pty can trigger session-level actions
// (`~.` disconnects, `~?` prints help). `none` disables the
// scan. Only has effect when a PTY is allocated (`-t` or
// auto-pty with a TTY). These tests pin the clap surface; the
// runtime behavior is verified in `tests/15`
// (`test_escape_*`).
#[test]
fn test_escape_char_short_tilde() {
    let (_, _, stderr) = run_phr(&["-e", "~", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "clap should recognize -e, but stderr complains: {}",
        stderr
    );
}

#[test]
fn test_escape_char_long() {
    let (_, _, stderr) = run_phr(&["--escape-char", "~", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_escape_char_none_disables() {
    // `none` (case-insensitive) is OpenSSH's literal for "no
    // escape char". Clap must accept the value verbatim.
    let (_, _, stderr) = run_phr(&["-e", "none", "user@localhost", "id"]);
    assert!(
        !stderr.contains("error:"),
        "parsing failed for `-e none`: {}",
        stderr
    );
}

#[test]
fn test_escape_char_caret_notation() {
    // `^a` is Ctrl-A. Verify clap accepts the caret form (the
    // resolver at `cli::parse_escape_char` then maps it to 0x01).
    let (_, _, stderr) = run_phr(&["-e", "^a", "user@localhost", "id"]);
    assert!(
        !stderr.contains("error:"),
        "parsing failed for `-e ^a`: {}",
        stderr
    );
}

#[test]
fn test_escape_char_question_mark() {
    // `?` is a valid single-byte escape (different from OpenSSH's
    // default `~`, useful if the user's shell expands `~`).
    let (_, _, stderr) = run_phr(&["-e", "?", "user@localhost", "id"]);
    assert!(
        !stderr.contains("error:"),
        "parsing failed for `-e ?`: {}",
        stderr
    );
}

#[test]
fn test_escape_char_with_tty_flag() {
    // `-e` must be combinable with `-t` (force PTY); both flags
    // affect interactive sessions.
    let (_, _, stderr) = run_phr(&["-e", "~", "-t", "user@localhost", "id"]);
    assert!(
        !stderr.contains("error:"),
        "parsing failed for `-e ~ -t`: {}",
        stderr
    );
}

#[test]
fn test_escape_char_with_no_pty_flag() {
    // `-e` combined with `-T` (no PTY) is accepted — the runtime
    // simply ignores the escape when no PTY is allocated.
    let (_, _, stderr) = run_phr(&["-e", "~", "-T", "user@localhost", "id"]);
    assert!(
        !stderr.contains("error:"),
        "parsing failed for `-e ~ -T`: {}",
        stderr
    );
}

// `-B <interface>`: bind the outbound TCP connection to a
// specific local network interface (OpenSSH `-B`). Implements
// `SO_BINDTODEVICE` on Linux. Distinct from `-b <address>`
// (source IP) — `-B` and `-b` are orthogonal and stack
// (`-b 192.0.2.10 -B eth0` pins both). Issue #60.
#[test]
fn test_bind_interface_short() {
    let (_, _, stderr) = run_phr(&["-B", "eth0", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "clap should recognize -B, but stderr complains: {}",
        stderr
    );
}

#[test]
fn test_bind_interface_long() {
    let (_, _, stderr) = run_phr(&["--bind-interface", "eth0", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_bind_interface_combined_with_bind_address() {
    // `-B eth0 -b 192.0.2.10` must be parseable: the two flags
    // stack (one picks the source IP, the other pins the
    // kernel's interface). Both flows are independent in
    // `connect_with_bind`.
    let (_, _, stderr) = run_phr(&["-B", "eth0", "-b", "192.0.2.10", "user@localhost", "id"]);
    assert!(
        !stderr.contains("error:"),
        "parsing failed for `-B -b` combo: {}",
        stderr
    );
}

#[test]
fn test_bind_interface_empty_string_accepted() {
    // `-B ""` is the "let me skip you but still set the flag"
    // form, mirroring `-b ""`. clap accepts; runtime treats it
    // as if `-B` was not passed (`apply_bind_interface` early-
    // returns on empty string).
    let (_, _, stderr) = run_phr(&["-B", "", "user@localhost", "id"]);
    assert!(
        !stderr.contains("error:"),
        "parsing failed for `-B \"\"`: {}",
        stderr
    );
}

#[test]
fn test_bind_interface_via_o_option() {
    // OpenSSH accepts the long-form
    // `-o BindInterface=eth0` alias (mirrors the
    // `-o BindAddress=` companion of `-b`).
    //
    // NOTE: `-o BindInterface` is not yet honored at runtime by
    // passhrs's `parse_ssh_options` plumb — this test pins only
    // the clap-side "the value is accepted by `-o` regardless".
    // Runtime honoring is a follow-up if we decide `-o
    // BindInterface` should win over the explicit `-B` flag
    // (OpenSSH precedence is unspecified).
    let (_, _, stderr) = run_phr(&["-o", "BindInterface=eth0", "user@localhost", "id"]);
    assert!(
        !stderr.contains("error:"),
        "parsing failed for `-o BindInterface=`: {}",
        stderr
    );
}

#[test]
fn test_debug_all_flag() {
    let (_, _, stderr) = run_phr(&["--debug-all", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
    // Also exercise the short-circuited path that previously raised
    // "unexpected argument --debug-all found". The error message
    // string is what clap prints when the flag is not declared.
    assert!(
        !stderr.contains("unexpected argument"),
        "clap should now recognize --debug-all, but stderr still complains: {}",
        stderr
    );
}

#[test]
fn test_full_openssl_compatible() {
    let (_, _, stderr) = run_phr(&[
        "-p",
        "12322",
        "-N",
        "-f",
        "-C",
        "-n",
        "-i",
        "/tmp/id_rsa",
        "-o",
        "TCPKeepAlive=yes",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "user@43.129.204.111",
        "-L",
        "0.0.0.0:8118:127.0.0.1:8118",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}
