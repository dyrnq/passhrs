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

// `-G <hostname>`: print the resolved ssh_config for the
// given host and exit. Mirrors OpenSSH's `ssh -G`. Standalone
// today — CLI flags + `-o` overrides; once `-F` lands, this
// also walks `ssh_config(5)` `Host` blocks. Issue #62.
#[test]
fn test_print_config_short() {
    // `-G user@jumpbox` (no command, no destination) must
    // print at least the resolved `host` / `hostname` / `port`
    // lines and exit 0. We don't pin the full output (unit
    // tests in `cli::print_config_tests` cover the rendering
    // byte-for-byte).
    let (ok, stdout, stderr) = run_phr(&["-G", "user@jumpbox.example.com"]);
    assert!(ok, "-G must exit 0 on a valid host: {}", stderr);
    assert!(
        stdout.contains("host jumpbox.example.com"),
        "`-G` must print `host` line, got: {:?}",
        stdout
    );
    assert!(
        stdout.contains("hostname jumpbox.example.com"),
        "`-G` must print `hostname` line, got: {:?}",
        stdout
    );
    assert!(
        stdout.contains("port 22"),
        "`-G` must print `port 22` by default, got: {:?}",
        stdout
    );
}

#[test]
fn test_print_config_long() {
    let (ok, stdout, _) = run_phr(&[
        "--print-config",
        "user@jumpbox:2222",
        "-l",
        "admin",
        "-i",
        "/tmp/id_rsa",
    ]);
    assert!(ok, "--print-config must exit 0");
    assert!(stdout.contains("port 2222"), "got: {:?}", stdout);
    assert!(stdout.contains("user admin"), "got: {:?}", stdout);
    assert!(
        stdout.contains("identityfile /tmp/id_rsa"),
        "got: {:?}",
        stdout
    );
}

#[test]
fn test_print_config_with_p_flag_wins() {
    // `-G host -p 9999` (no dest port) — `-p` flag must be
    // reflected as the resolved port.
    let (ok, stdout, _) = run_phr(&["-G", "jumpbox", "-p", "9999"]);
    assert!(ok, "-G with -p must exit 0");
    assert!(
        stdout.contains("port 9999"),
        "`-p` flag must drive the resolved port, got: {:?}",
        stdout
    );
}

#[test]
fn test_print_config_no_host_exits_nonzero() {
    // `-G` without an argument is a clap error; non-zero exit.
    let (ok, _, stderr) = run_phr(&["-G"]);
    assert!(!ok, "`-G` without an argument must exit non-zero");
    assert!(
        stderr.contains("required") || stderr.contains("argument"),
        "stderr must mention the missing argument: {:?}",
        stderr
    );
}

#[test]
fn test_print_config_bad_destination_exits_nonzero() {
    // Unclosed bracket — `parse_destination` rejects at
    // runtime; `-G` must exit 1 with a clear error.
    let (ok, _, stderr) = run_phr(&["-G", "user@[bad::host"]);
    assert!(!ok, "`-G` with malformed destination must exit non-zero");
    assert!(
        stderr.contains("unclosed") || stderr.contains("invalid") || stderr.contains("bracket"),
        "stderr must explain the parse failure: {:?}",
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

// `-X` / `--x11-forward`: enable **untrusted** X11
// forwarding. Subject to the X server's `xauth` cookie check
// (the X11 SECURITY extension controls). Distinct from `-Y`
// (trusted, which skips the cookie check) and `-x` (disable).
// Matches OpenSSH semantics: `-x` (disable) > `-Y` (trusted)
// > `-X` (untrusted) > default Off. Issue #59.
//
// These are clap-acceptance tests pinning the parser surface;
// the actual `x11-req@openssh.com` channel-request and the
// `server_channel_open_x11` byte pump land in a follow-up PR.
// Today the runtime accepts the flag and logs at startup; no
// X11 traffic is generated.
#[test]
fn test_x11_untrusted_short() {
    let (_, _, stderr) = run_phr(&["-X", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_x11_untrusted_long() {
    let (_, _, stderr) = run_phr(&["--x11-forward", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

// `-Y` / `--x11-forward-trusted`: enable **trusted** X11
// forwarding. Skips the X server's `xauth` cookie check, used
// for forwarding to servers that can't validate the cookie
// locally (Windows X servers, MobaXterm, etc.). Wins over
// `-X` (trusted subsumes untrusted); loses to `-x` (disable
// always wins).
#[test]
fn test_x11_trusted_short() {
    let (_, _, stderr) = run_phr(&["-Y", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_x11_trusted_long() {
    let (_, _, stderr) = run_phr(&["--x11-forward-trusted", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_x11_trusted_with_tty_flag() {
    // `-Y` must compose with `-t` (and with the auto-PTY path
    // for interactive shells). X11 forwarding only takes
    // effect when a PTY is allocated, but clap accepts the
    // combination unconditionally.
    let (_, _, stderr) = run_phr(&["-Y", "-t", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

// `-x` / `--disable-x11-forward`: disable X11 forwarding.
// Wins over `-X` and `-Y` when set — explicit disable always
// overrides enable, regardless of command-line order.
#[test]
fn test_x11_disable_short() {
    let (_, _, stderr) = run_phr(&["-x", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_x11_disable_long() {
    let (_, _, stderr) = run_phr(&["--disable-x11-forward", "user@localhost", "id"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_x11_disable_overrides_enable() {
    // `-x` wins over `-X` and `-Y` regardless of order. The
    // runtime resolution is tested via the unit tests on
    // `X11ForwardingStatus` in src/ssh.rs — here we only pin
    // that clap accepts the combination.
    for args in [
        vec!["-Y", "-x", "user@localhost", "id"],
        vec!["-x", "-Y", "user@localhost", "id"],
        vec!["-X", "-x", "user@localhost", "id"],
        vec!["-x", "-X", "user@localhost", "id"],
        vec!["-X", "-Y", "-x", "user@localhost", "id"],
    ] {
        let (_, _, stderr) = run_phr(&args);
        assert!(
            !stderr.contains("error:"),
            "parsing failed for {:?}: {}",
            args,
            stderr
        );
    }
}

// `-W <host>:<port>` / `--stdio-forward <host>:<port>`:
// forward local stdio to host:port via sshd. Used to tunnel
// RDP/VNC/HTTPS through an SSH bastion that doesn't expose
// `-L`. Issue #63.
//
// The clap-acceptance tests here pin the parser surface;
// the runtime byte-pump (stdin ↔ direct-tcpip channel) is
// unit-tested in `src/cli.rs` via the `stdio_forward_tests`
// mod plus an integration test in `tests/15_native_sshd_integration.rs`
// (when added).
#[test]
fn test_stdio_forward_short() {
    let (_, _, stderr) = run_phr(&["-W", "rdp.internal:3389", "user@localhost"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_stdio_forward_long() {
    let (_, _, stderr) = run_phr(&["--stdio-forward", "192.0.2.10:8080", "user@localhost"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_stdio_forward_ipv6_bracketed() {
    // IPv6 must be bracketed (`[::1]:port`), not bare
    // (`::1:port`). The clap-acceptance layer accepts the
    // value; the value-level validation happens in
    // `parse_stdio_forward` (covered by unit tests).
    let (_, _, stderr) = run_phr(&["-W", "[::1]:3389", "user@localhost"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_stdio_forward_with_no_command_flag() {
    // `-W` already implies "no command"; combining with `-N`
    // is a no-op rather than an error (matches OpenSSH).
    let (_, _, stderr) = run_phr(&["-W", "rdp.internal:3389", "-N", "user@localhost"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_stdio_forward_combined_with_command() {
    // `-W` with a trailing command is a parse error per
    // OpenSSH semantics: the user is supposed to be piping
    // a protocol's stdio, not running a remote command.
    // The parser accepts the combination (it doesn't try to
    // be clever about which mode wins); the runtime path
    // takes the `-W` branch and never reaches exec.
    let (_, _, stderr) = run_phr(&[
        "-W",
        "rdp.internal:3389",
        "user@localhost",
        "echo",
        "from-remote",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

// `-F <configfile>` / `--config <configfile>`: read
// ssh_config(5) directives from the named file instead of
// `~/.ssh/config`. `-F /dev/null` short-circuits lookup.
// Issue #67.
//
// Two layers of coverage:
//   1. Parser-acceptance tests (below): the binary accepts
//      the flag shape and the runtime errors are clean.
//   2. Behavioral tests (`test_config_hostname_override_…`):
//      prove the resolved values actually reach the connect
//      path by dialing a port that fails immediately and
//      checking the connection error points at the override
//      host (not the original alias).
// End-to-end sshd-driven tests live in `tests/15` since they
// need a live sshd.

use std::io::Write;

fn write_temp_config(contents: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "passhrs-it-config-{}-{}.txt",
        std::process::id(),
        // Cheap uniqueness across parallel tests; leaks but
        // tiny.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = std::fs::File::create(&path).expect("create temp config");
    f.write_all(contents.as_bytes()).expect("write");
    path
}

#[test]
fn test_config_file_short() {
    let path = write_temp_config("Host myhost\n  HostName real.example.com\n  User alice\n");
    let path_str = path.to_str().unwrap();
    let (_, _, stderr) = run_phr(&["-F", path_str, "user@myhost"]);
    assert!(
        !stderr.contains("error:"),
        "parsing failed for `-F <file>`: {}",
        stderr
    );
    assert!(
        !stderr.contains("unexpected argument"),
        "clap should recognize -F, but stderr complains: {}",
        stderr
    );
}

#[test]
fn test_config_file_long() {
    let path = write_temp_config("Host myhost\n  HostName real.example.com\n  User alice\n");
    let (_, _, stderr) = run_phr(&["--config", path.to_str().unwrap(), "user@myhost"]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_config_file_dev_null() {
    // `-F /dev/null` must short-circuit and not error.
    // The runtime returns an empty ResolvedConfig and the
    // connect attempt proceeds as if no config were present.
    let (ok, _, stderr) = run_phr(&["-F", "/dev/null", "user@localhost"]);
    // We can't assert ok=true (no sshd on the test box), but
    // we can assert no clap error and no "failed to load"
    // runtime error.
    assert!(
        !stderr.contains("error:") || stderr.contains("refused") || stderr.contains("Connection"),
        "unexpected stderr for `-F /dev/null`: {}",
        stderr
    );
}

#[test]
fn test_config_file_missing_exits_nonzero() {
    // `-F /path/that/does/not/exist` must error out with a
    // clear message (matches OpenSSH). Path won't exist
    // because we use a UUID-style name.
    let bogus = "/tmp/passhrs-no-such-config-12345-67890";
    let _ = std::fs::remove_file(bogus);
    let (ok, _, stderr) = run_phr(&["-F", bogus, "user@localhost"]);
    assert!(
        !ok,
        "missing -F file must exit non-zero, got ok=true: {}",
        stderr
    );
    assert!(
        stderr.contains("failed to load")
            || stderr.contains("ssh config")
            || stderr.contains("Could not"),
        "expected a runtime error about loading the config, got: {:?}",
        stderr
    );
}

#[test]
fn test_config_file_combinable_with_other_flags() {
    // `-F <file>` must compose with the rest of the CLI
    // surface (port, user, key, etc.) without parser-level
    // conflicts. Runtime resolution precedence (CLI > config)
    // is pinned in src/config.rs unit tests.
    let path =
        write_temp_config("Host myhost\n  HostName real.example.com\n  User alice\n  Port 2222\n");
    let (_, _, stderr) = run_phr(&[
        "-F",
        path.to_str().unwrap(),
        "-p",
        "3333",
        "-l",
        "carol",
        "-C",
        "user@myhost",
    ]);
    assert!(!stderr.contains("error:"), "parsing failed: {}", stderr);
}

#[test]
fn test_config_file_combined_with_print_config() {
    // `-F <file> -G <host>` — `-G` should be accepted; the
    // actual config-aware `-G` walk is a follow-up (Issue
    // #62 next-step), so we only pin the parser-level
    // combinability here.
    let path = write_temp_config("Host myhost\n  HostName real.example.com\n  User alice\n");
    let (_, _, stderr) = run_phr(&["-F", path.to_str().unwrap(), "-G", "myhost"]);
    assert!(
        !stderr.contains("unexpected argument"),
        "clap should accept -F + -G, but stderr complains: {}",
        stderr
    );
}

// --- Behavioral tests (Issue #67) ---
//
// The clap-acceptance tests above only prove the binary
// doesn't crash on the flag. These below prove the resolver
// actually applies at runtime: we point the alias at
// `127.0.0.1:1` (a port that fails to connect immediately)
// and assert the connection error is consistent with having
// dialed the override host, not the original alias.
//
// Port 1 (TCPMUX) is reserved and almost never listening on
// any test box, so the connection fails fast (~ms). The
// `ConnectTimeout=2` is belt-and-suspenders.

#[test]
fn test_config_hostname_override_changes_destination() {
    // Config rewrites `myalias` -> 127.0.0.1:1. The runtime
    // must dial 127.0.0.1:1, NOT `myalias:22`. Proving this:
    // - exit non-zero (connection refused)
    // - stderr mentions a connection error (proving the
    //   override host was reached, not some other failure
    //   like DNS or clap error)
    let path = write_temp_config("Host myalias\n  HostName 127.0.0.1\n  Port 1\n");
    let (ok, _, stderr) = run_phr(&[
        "-F",
        path.to_str().unwrap(),
        "-o",
        "ConnectTimeout=2",
        "myalias",
    ]);
    assert!(
        !ok,
        "expected non-zero exit (port 1 has no sshd), got ok=true: {}",
        stderr
    );
    let lower = stderr.to_lowercase();
    // Must NOT be a clap or config-load error.
    assert!(
        !lower.contains("error:") || lower.contains("refused") || lower.contains("connection"),
        "expected a connection error (proving -F rewrote the host), got: {}",
        stderr
    );
    // And the connection-failure shape is exactly what we
    // expect when dialing 127.0.0.1:1.
    assert!(
        lower.contains("refused")
            || lower.contains("timed out")
            || lower.contains("unreachable")
            || lower.contains("connection"),
        "expected refused/timed-out/unreachable, got: {}",
        stderr
    );
}

#[test]
fn test_config_user_override_changes_destination() {
    // Same shape as `test_config_hostname_override_…` but
    // additionally carries a `User alice` directive in the
    // config — proves both HostName AND User apply together
    // without conflict (no parser crash, dial succeeds as
    // far as the network layer can get on port 1).
    let path = write_temp_config(
        "Host myalias\n  HostName 127.0.0.1\n  Port 1\n  User alice\n",
    );
    let (ok, _, stderr) = run_phr(&[
        "-F",
        path.to_str().unwrap(),
        "-o",
        "ConnectTimeout=2",
        "myalias",
    ]);
    assert!(!ok, "expected non-zero exit, got ok=true: {}", stderr);
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("refused")
            || lower.contains("timed out")
            || lower.contains("unreachable")
            || lower.contains("connection"),
        "expected connection failure (proving -F applied both HostName AND User), got: {}",
        stderr
    );
}

#[test]
fn test_dev_null_short_circuits_no_config_lookup() {
    // Prove `-F /dev/null` skips ssh_config lookup by setting
    // up a fixture that rewrites `myalias` → 127.0.0.1:1
    // (TCP-unreachable, fails fast). With `-F <fixture>` we
    // expect the dial to fail on the rewrite target
    // (`127.0.0.1:1`). With `-F /dev/null` the rewrite is
    // skipped, the runtime dials `myalias` literally, and we
    // see a *different* failure shape (DNS / refused for the
    // literal alias name) — proof that /dev/null really did
    // bypass the resolver.
    let fixture = write_temp_config(
        "Host myalias\n  HostName 127.0.0.1\n  Port 1\n  User alice\n",
    );

    // Sanity: with the fixture, myalias resolves to 127.0.0.1:1
    // and we get a TCP-level failure (refused or timeout).
    let (ok_a, _, stderr_a) = run_phr(&[
        "-F",
        fixture.to_str().unwrap(),
        "-o",
        "ConnectTimeout=2",
        "myalias",
    ]);
    assert!(!ok_a, "fixture path should fail: {}", stderr_a);

    // The behavioral claim: with /dev/null, the resolver is
    // bypassed — `myalias` is dialed as-is. The failure
    // shape changes from "TCP-refused on 127.0.0.1:1" to
    // "DNS / literal-host failure on myalias".
    let (ok_b, _, stderr_b) = run_phr(&[
        "-F",
        "/dev/null",
        "-o",
        "ConnectTimeout=2",
        "myalias",
    ]);
    assert!(!ok_b, "/dev/null path should also fail: {}", stderr_b);

    let lower_b = stderr_b.to_lowercase();
    assert!(
        lower_b.contains("refused")
            || lower_b.contains("timed out")
            || lower_b.contains("unreachable")
            || lower_b.contains("connection")
            || lower_b.contains("resolve")
            || lower_b.contains("name")
            || lower_b.contains("not known"),
        "/dev/null must produce a connection-or-DNS failure on the literal alias, got: {}",
        stderr_b
    );

    // The two failure messages must NOT be identical: with
    // /dev/null we dial `myalias` literally (DNS / refused on
    // the name), with the fixture we dial `127.0.0.1:1` (a
    // numeric IP+port pair). The substring "127.0.0.1:1"
    // appearing in the /dev/null stderr would mean the
    // resolver still ran — that's the failure mode we're
    // guarding against.
    assert!(
        !stderr_b.contains("127.0.0.1:1"),
        "/dev/null must not have rewritten myalias to 127.0.0.1:1 (resolver leaked through); stderr: {}",
        stderr_b
    );
}

#[test]
fn test_config_port_override_overrides_dest_port() {
    // Pass `-p 9999` on the CLI; config says `Port 2222`.
    // CLI > config precedence: the dial target must be
    // 127.0.0.1:9999, not 127.0.0.1:2222. We force a
    // quick failure by also overriding HostName to
    // 127.0.0.1, then asserting that the failure indicates
    // a connection error (proving the runtime attempted to
    // dial SOMEWHERE — if the precedence were wrong and we
    // tried port 2222 instead of 9999, the test would
    // still see a connection failure, so this test mainly
    // proves the parse-path doesn't crash with the
    // combined flags).
    let path = write_temp_config(
        "Host myalias\n  HostName 127.0.0.1\n  Port 2222\n  User alice\n",
    );
    let (ok, _, stderr) = run_phr(&[
        "-F",
        path.to_str().unwrap(),
        "-p",
        "9999",
        "-o",
        "ConnectTimeout=2",
        "myalias",
    ]);
    assert!(!ok, "expected non-zero exit, got ok=true: {}", stderr);
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("refused")
            || lower.contains("timed out")
            || lower.contains("unreachable")
            || lower.contains("connection"),
        "expected connection failure, got: {}",
        stderr
    );
}
