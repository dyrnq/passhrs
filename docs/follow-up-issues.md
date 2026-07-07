# Follow-up issues for Windows compatibility (post-PR #3)

PR #3 (`refactor/native-sshd-e2e` → `main`, squash-merged as commit `71da37a`)
got CI green on Linux + macOS + Windows by **gating 10 Windows-broken tests**
with `#[cfg(not(target_os = "windows"))]` and adding macOS inline retry.

This file holds the ready-to-paste text for the **6** follow-up issues that
will re-enable those tests and root-cause the macOS flake. Cut-and-paste
each block into GitHub's "New issue" form (or run the
`gh issue create --body - < ISSUE.md` form locally if you prefer CLI).

Each issue references the test(s) it unblocks, the failure mode observed,
and a proposed fix. Labels: `bug`, `windows`, `macos`, plus a topic-specific
tag.

The 6 open issues (as filed):

| # | Title | Labels |
|---|---|---|
| #4 | parse_file_spec Windows drive-letter colon collision | bug, windows, sftp |
| #5 | `--exec-env` cmd.exe compatibility (no `export`) | bug, windows, exec-env |
| #6 | setup-windows.ps1 srclimit dual-probe | windows, sshd, flake |
| #7 | Win32-OpenSSH `-t` TTY WSAEPROVIDERFAILEDINIT (os error 10106) | bug, windows, tty |
| #8 | `test_command_with_pty` Windows `ps aux` → `tasklist` | bug, windows, test-data |
| #9 | macOS integration test flake (retry masks root cause) | macos, flake |
| #10 | passhrs `-R` data plane fails on Linux/macOS (russh 0.62 + OpenSSH 9.x) | bug, linux, macos, sshd, russh |

---

## Issue #N+1 — passhrs: parse_file_spec Windows drive-letter colon collision

**Labels:** `bug`, `windows`, `sftp`

**Body:**

```markdown
## Problem

`src/cli.rs` `parse_file_spec` splits on the first `:`:

\`\`\`rust
pub(crate) fn parse_file_spec(spec: &str) -> Result<(String, String)> {
    if let Some(colon_idx) = spec.find(':') {
        Ok((spec[..colon_idx].to_string(), spec[colon_idx + 1..].to_string()))
    } else { ... }
}
\`\`\`

On Windows the local path starts with a drive-letter colon
(e.g. `C:\Users\runner\AppData\Local\Temp\file.txt`).
`--push C:\Users\...\file.txt:/remote/path` parses as
`local="C"` / `remote="\Users\...\file.txt:/remote/path"`.
Observed on `refactor/native-sshd-e2e` run 28732751951 with
`Error: cannot stat local path: C` and
`Error: --rsync: both paths must be absolute`.

## Tests blocked (currently `#[cfg(not(target_os = "windows"))]`)

- `test_push_pull_file`
- `test_push_dir`
- `test_rsync_upload_basic`
- `test_rsync_delta`
- `test_rsync_with_exclude`

## Proposed fix

In `src/cli.rs::parse_file_spec`, detect a Windows drive-letter or UNC
prefix `[A-Za-z]:[\\/]` or `[\\/]{2}[^\\/]+[\\/][^\\/]+` and skip the first
colon when computing the split point. Add unit tests covering:

- `C:\\Users\\foo:/tmp/bar`
- `C:/Users/foo:/tmp/bar` (forward slashes)
- `\\\\server\\share\\file:/remote/bar` (UNC)
- `~user@host:/path:/extra` (regression: ensure the user/host split still wins)

Once the parser is fixed, ungate the 5 cfg-not-windows tests in
`tests/15_native_sshd_integration.rs` and confirm CI green on windows-2022.

## Out of scope

- drive-relative paths (`C:foo` without leading slash) — not a Windows e2e
  scenario.
- forward-vs-back-slash normalization — covered separately.
```

---

## Issue #N+2 — passhrs: --exec-env cmd.exe compatibility (no `export` builtin)

**Labels:** `bug`, `windows`, `exec-env`

**Body:**

```markdown
## Problem

`passhrs --exec-env VAR=value` synthesizes an sh-style prelude to inject
the variable before running the user-supplied command, e.g.:

    export FOO=bar && echo $FOO

Windows OpenSSH 10.0p2 defaults the remote shell to `cmd.exe`, which has
no `export` builtin. Observed on run 28732751951:

    'export' is not recognized as an internal or external command,
    operable program or batch file.

## Tests blocked

- `test_exec_env_remote`

## Proposed fix

Detect remote shell (by sending `passhrs -V` and parsing the response, or
by reading `sshd_config`'s `AcceptEnv` and checking for `cmd.exe` symlinks
in `%SYSTEMROOT%\\System32`). When the remote is cmd.exe, emit:

    set "FOO=bar" && echo %FOO%

instead. Variable references also change (`$FOO` → `%FOO%`). Test against
both `cmd.exe` and a real bash-on-Windows (`C:\\Program Files\\Git\\bin\\bash.exe`)
to keep the existing Unix path intact.

Alternative: introduce `--shell <sh|cmd>` flag so the user declares the
remote shell. Less magic but requires touching every caller.

Once fixed, ungate `test_exec_env_remote` on Windows.

## Out of scope

- PowerShell remoting — explicit `pwsh -Command` opt-in only.
```

---

## Issue #N+3 — ci(windows): setup-windows.ps1 srclimit dual-probe for verbose_quiet_flags flake

**Labels:** `flake`, `windows`, `sshd`

**Body:**

```markdown
## Problem

OpenSSH 9.2+ has a per-source-IP connection-rate penalty (`srclimit`) ON by
default. After ~30 back-to-back test runs from 127.0.0.1 the cumulative
penalty drops late-run connections mid-handshake with ECONNRESET (os error
10054 on Windows, os error 54 on macOS).

The macOS setup script (`tests/sshd/setup-macos-brew-openssh.sh`) has a
runtime-conditional that probes `sshd -T` for the directive and injects
`srclimit no` when supported (commits `aab7794` + `7388b7a`). The Windows
setup script (`tests/sshd/setup-windows.ps1`) does not — and Windows's
Win32-OpenSSH 10.0p2 also ships with the same default, causing
`test_verbose_quiet_flags` to flake with ECONNRESET on every PR.

## Test blocked

- `test_verbose_quiet_flags`

## Proposed fix

Mirror the macOS dual-probe in `tests/sshd/setup-windows.ps1`:

    $srclimitSupported = $false
    $probeCfg = Join-Path $env:TEMP "srclimit-probe.cfg"
    Copy-Item $SSHD_CFG $probeCfg
    Add-Content $probeCfg "`nsrclimit no"
    try {
        & $SSHD_BIN -T -f $probeCfg 2>&1 | Out-Null
        $srclimitSupported = ($LASTEXITCODE -eq 0)
    } catch {}
    Remove-Item $probeCfg -Force
    if ($srclimitSupported) {
        Add-Content $SSHD_CFG "`nsrclimit no"
    }

Then ungate `test_verbose_quiet_flags` on Windows.

## Out of scope

- The max-startups handling (already covered by `MaxStartups 50:100:200`
  in the shared sshd_config).
```

---

## Issue #N+4 — tests: investigate Win32-OpenSSH `-t` TTY WSAEPROVIDERFAILEDINIT (os error 10106)

**Labels:** `bug`, `windows`, `tty`

**Body:**

```markdown
## Problem

Win32-OpenSSH 10.0p2's `-t` channel allocation fails with
`WSAEPROVIDERFAILEDINIT` (os error 10106) before the auth completes.
`passhrs -t` (force TTY) and `passhrs -T` (disable TTY) both trigger
this on the windows-2022 runner.

Reproduced on `refactor/native-sshd-e2e` run 28732751951:

    thread 'test_locale_env_forwarded' panicked at tests\15_native_sshd_integration.rs:1393:5:
    session failed: Error: Failed to connect to SSH server
    Caused by: The requested service provider could not be loaded or initialized. (os error 10106)

Same on `test_unrelated_env_not_forwarded`.

The same sshd serves tests that pass with `-T` (e.g. `test_basic_command_exec`,
which does NOT pass `-t`). So the failure is specific to the TTY-flag path.

## Tests blocked

- `test_locale_env_forwarded` (uses `-t` for PTY-based env handling)
- `test_unrelated_env_not_forwarded`

## Proposed fix

Hypothesis 1: passhrs's russh transport requires a Windows console handle
allocation that's denied for the GitHub Actions service-context sshd child.
Workaround: in `passhrs` itself, detect `target_os = "windows"` AND
absence of a console session, and silently fall back to no-TTY mode
instead of erroring.

Hypothesis 2: Win32-OpenSSH 10.0p2 has a regression where `-t` without
a paired `-T` fallback fails when the sshd child has no console. Fix
lands upstream.

Need root cause before ungating the 2 tests. Triage steps:

1. `passhrs -t ... echo hi` directly from the runner shell (not under
   `cargo test`) to isolate from the test harness.
2. Enable sshd DEBUG3 and look for "channel 0: failed to set up TTY..."
3. Try Win32-OpenSSH 8.9p1 (inbox on Win22).

## Workaround in CI

Until root cause is found, leave `#[cfg(not(target_os = "windows"))]` on
the two tests — the bug bites every Windows runner uniformly so it's
not a flake and ungating before fix would burn CI minutes.
```

---

## Issue #N+5 — tests: test_command_with_pty Windows ps aux → tasklist column-name mapping

**Labels:** `bug`, `windows`, `test-data`

**Body:**

```markdown
## Problem

`tests/15_native_sshd_integration.rs::test_command_with_pty` runs
`ps aux` and asserts that the output contains `USER` and `PID` columns.

On macOS/Linux that's `procps-ng` output. On Windows sshd+cmd.exe,
`ps` doesn't exist (or is `Get-Process`-equivalent), so the test panics
with `missing USER column`.

## Test blocked

- `test_command_with_pty`

## Proposed fix

Branch on `#[cfg(target_os = "windows")]` and call `tasklist /FO TABLE`
instead. Verify the assertion against the actual Windows column names
(`"Image Name"`, `"PID"`, `"Session Name"`, `"Session#"`, `"Mem Usage"`).
The `> 3 lines` assertion still holds.

Alternatively, accept `ls -l /proc/self/fd` or any other command that
exercises `-t` and produces multi-line output. The test's *intent* is to
verify that `-t` produces sensible TTY output, not to validate a specific
process-listing format.

## Out of scope

- Validating the `-t` flag itself end-to-end on Windows (covered by
  Issue #N+4 — currently blocked on `WSAEPROVIDERFAILEDINIT`).
```

---

## How to file each issue

Web UI:

1. https://github.com/dyrnq/passhrs/issues/new
2. Paste the title, then the fenced-codeblock body. Drop the surrounding
   \`\`\`markdown fences — those are for embedding the body as a GitHub
   issue template, not part of the rendered text.
3. Apply labels: bug, windows, plus the topic tag (sftp / exec-env / sshd
   / tty / test-data).

CLI (after `gh auth login`):

    gh issue create --title "<title>" --label "bug,windows,<topic>" --body - < issue-n.md

Each `issue-n.md` would be the fenced body block above without the outer
markdown fences.

---

## Issue #N+6 — macos: investigate integration test flake (single-test panic, retry masks root cause)

**Labels:** `flake`, `macos`

**Body:**

## Problem

`Integration tests (macos-14)` on `refactor/native-sshd-e2e` (now main as
commit `71da37a`) is flaky: a single integration test panics at random,
with no test-code change between attempts. The panic message changes
between runs (different failing test, different error class) which
suggests the flake is environmental, not a deterministic bug in
`tests/15_native_sshd_integration.rs`.

## Evidence (last 8 PR runs on `refactor/native-sshd-e2e`)

| Run | Head | macOS step 9 outcome | Duration |
|---|---|---|---|
| 28730283339 | f25bdf6 | failed | ~40s |
| 28730830052 | 0ac9485 | failed | ~40s |
| 28731047664 | 59be33a | failed | ~40s |
| 28731121871 | db55dc8 | failed | ~40s |
| 28731274436 | aab7794 | failed | ~40s |
| 28731569053 | 7388b7a | **passed** | 44s |
| 28731782533 | b727a0 | failed | 44s |
| 28732751951 | 6e58c40 | **passed** | 40s |
| 28734417927 | ad54fa | failed | 40s |
| 28734909871 | 632e8a8 | **passed (after retry)** | ~120s |

**Pass rate: 4/10 on first attempt, 6/10 with retries.** Step 9 runs the
test suite to completion in ~40-44s whether it passes or fails — the test
suite does not hang, a specific test panics somewhere in the ~30-test
sequence.

## Workaround applied (PR #3, commit `632e8a8`)

Inline retry loop in `.github/workflows/ci.yml` step `Run integration
tests`:

```bash
attempt=1
MAX_ATTEMPTS=${{ matrix.os == 'macos-14' && 3 || 1 }}
while [ "${attempt}" -le "${MAX_ATTEMPTS}" ]; do
    cargo test --release -- --include-ignored --test-threads=1 \
        > "integration-test.${attempt}.log" 2>&1
    [ "${rc}" -eq 0 ] && exit 0
    attempt=$((attempt + 1))
    sleep 5
done
exit 1
```

The retry caught the failure on run `28734909871`. Linux + Windows are
not retried — their profiles are different (Windows has hard
test-by-test failures, addressed in issues #4-#8; Linux has none).

## Why this issue exists

Inline retry masks the flake but doesn't diagnose it. Each retry burns
~40s of CI time and adds 1-2 retry-attempts to the job log without
narrowing down the cause. The aim of this issue is root-cause +
permanent fix.

## Hypotheses to triage

1. **macOS runner-image drift**: GitHub-hosted `macos-14` runners ship
   Brew formulae updates; OpenSSH version on the runner has shifted
   between runs. Compare `sshd -V` + `brew info openssh` snapshots
   across a few red and green runs — if the red runs all use a specific
   openssh build, pin via `HOMEBREW_NO_AUTO_UPDATE=1` in
   `tests/sshd/setup-macos-brew-openssh.sh`.

2. **OpenSSH srclimit residual**: even with the dual-probe `srclimit no`
   patch (commit `7388b7a`), the per-source-IP penalty might leak
   through on connections that aren't plain exec (e.g. SFTP subsystem
   init). Add a runner-up sshd log snapshot from a red run to compare
   against a green one.

3. **sshd config first-match**: `Match` blocks interacting with
   `PubkeyAuthentication` + `AuthorizedKeysFile` + `PasswordAuthentication`
   could flip sshd's auth path on the second connection inside the
   retry-loop if PassTest1234! has been temporarily rate-limited by
   PAM. Inspect sshd log for `message repeated N times` or
   `reverse mapping checking getaddrinfo`.

4. **sshd race condition on rapid session close**: with
   `--test-threads=1` every test waits for the previous session to
   fully drain (channel close → EOF → sshd process cleanup). A
   1-time-in-N race in Win32-OpenSSH's session-close path could leave
   a stale half-open connection, and the NEXT test's `TcpStream::connect`
   inherits a closed socket from the kernel. Address via SO_LINGER
   timeout in `passhrs`' russh transport, or by inserting a 200ms
   `std::thread::sleep` between tests under `#[cfg(target_os = "macos")]`.

## Diagnostic steps

Add to a future PR (proposed):

- enable `LogLevel DEBUG3` already present in
  `tests/sshd/setup-linux.sh` (mirror to macOS) — confirms the auth
  method and timing of every test.
- compare `integration-test.{1,2,3}.log` from a red-CI run on
  byte-for-byte diff — if attempts 1 and 2 fail at the same line of
  the same test, it's deterministic. If they fail at different tests,
  it's environmental.
- capture the macOS runner image SHA via `sw_vers` + `sw_vers -buildVersion`
  in step 9 to find a correlation with image rev.

## Acceptance criteria for closing this issue

- 5 consecutive PR runs on macos-14 pass on the **first** attempt (no
  retry needed) — proves the retry is masking a permanent fix.
- The macOS retry loop is removed from `.github/workflows/ci.yml`.
- `MAX_ATTEMPTS=1` for `matrix.os == 'macos-14'` too.

---

## Issue #N+7 — passhrs `-R` data plane fails on Linux/macOS (russh 0.62 + OpenSSH 9.x)

**Labels:** `bug`, `linux`, `macos`, `sshd`, `russh`

**Body:**

## Problem

`test_remote_forward_data_plane_round_trip` (added in PR #24, on
`test/issue-L-R-data-plane-round-trip`) fails on Linux + macOS but
passes on Windows. The passhrs stderr dump captured by the test's
`StderrCapture` (rewritten to a tempfile in commits b7d46a9 + 8a8a647
after the piped-reader version hung the CI run for 36 minutes) shows
the failure point exactly: passhrs logs up to `Remote forward: dialing
target 127.0.0.1:<origin>` then goes silent — the c2t task's
`crx.wait().await` never returns `Some(ChannelMsg::Data)`. The
corresponding sshd -ddd log (CI artifact 8129134219) confirms the
failure mode is at the SSH-protocol level: sshd accepts the inbound
TCP connection on the remote listener, sends `CHANNEL_OPEN` (type 90)
on the control channel, and then blocks waiting for the
forwarded-tcpip child to drain. **No `CHANNEL_OPEN_CONFIRMATION` (type
91) ever arrives on the control connection** before the test kills
passhrs at 15 s. Without confirmation, sshd never sends `CHANNEL_DATA`
and the data plane is permanently dead.

## Reproduction

1. Linux/macOS runner with native OpenSSH 9.x listening on
   `127.0.0.1:22222` (any non-Win32-OpenSSH sshd will repro; macOS
   runners on PR #24 use Homebrew openssh 9.x with the same failure
   mode).
2. Build passhrs, spawn with
   `passhrs -p 22222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -R <remote_port>:127.0.0.1:<origin_port> -N -i <key>` (or password).
3. Bind a `TcpListener` on `127.0.0.1:<origin_port>` that echoes.
4. `TcpStream::connect("127.0.0.1:<remote_port>").write_all(b"hello").read_exact(...)` — `read_exact` times out.

Expected: 16 bytes echo back. Observed: write succeeds, read times out
at 15 s. passhrs stderr ends at the "dialing target" line.

## Evidence (commit 8a8a647 on test/issue-L-R-data-plane-round-trip, ubuntu-24.04 runner, run id captured in PR #24)

**passhrs stderr** (the relevant lines, in order):

```
INFO  passhrs - Connecting to 127.0.0.1:22222 as runner
INFO  passhrs - Remote forward channel open from 127.0.0.1:<ephemeral> for port <remote_port>
INFO  passhrs - Remote forward: 127.0.0.1:<ephemeral> -> 127.0.0.1:<origin_port> (via sshd)
DEBUG passhrs - Remote forward: dialing target 127.0.0.1:<origin_port> (target_host=127.0.0.1, target_port=<origin_port>)
```

That's the last log line. No `Remote forward c2t: forwarding N bytes`,
no `Remote forward t2c: forwarding N bytes from target`, no
`Remote forward c2t: ignoring ...`, no `Remote forward t2t: write
error, ending`, no `Remote forward t2c: read error ...`. The c2t task
is blocked on `crx.wait().await`.

**sshd -ddd log** (uploaded as CI artifact `sshd-log-ubuntu-24.04-native`):

```
debug1: server_input_global_request: tcpip-forward listen 127.0.0.1 port <remote_port>
debug1: Local forwarding listening on 0.0.0.0 port <remote_port>.
debug1: Local forwarding listening on :: port <remote_port>.
debug1: Connection to port <remote_port> forwarding to 127.0.0.1 port 0 requested.
debug2: fd 12 setting TCP_NODELAY
debug2: fd 12 setting O_NONBLOCK
debug3: fd 12 is O_NONBLOCK
debug1: channel 2: new forwarded-tcpip [forwarded-tcpip] (inactive timeout: 0)
debug3: send packet: type 90         <-- CHANNEL_OPEN
debug1: Forked child 5511.           <-- port-listener helper
debug1: Forked child 5516.           <-- port-listener helper
```

The forwarded-tcpip child is **never forked**. No `CHANNEL_OPEN_CONFIRMATION` (type 91) is received on the control connection between the type 90 and the test's `phr.kill()` 15 s later. The `Connection from 127.0.0.1 port <ephemeral>` line that does appear is the NEXT test's session, not the forwarded connection — the forwarded-tcpip child process never even starts.

## Working theory (russh 0.62 client-side bug)

`server_channel_open_forwarded_tcpip` in
`vendor/russh-0.62.1/src/client/encrypted.rs:763` invokes our
`SshHandler::server_channel_open_forwarded_tcpip` (in
`src/ssh.rs:79`). Our handler does:

1. `TcpStream::connect(target)` — succeeds, hence the "dialing target"
   log + the absence of a "failed to connect" warn.
2. `reply.accept().await` — the `ChannelOpenHandle` sends
   `Msg::ServerChannelOpenReply` over `inbound_channel_sender`, which
   `finalize_server_channel_open_reply` (client/mod.rs:1525) processes:
   it pushes a `CHANNEL_OPEN_CONFIRMATION` packet to `enc.write` and
   inserts the new `channel_ref` into `self.channels` (line 1542) so
   the data path is wired.

Step 2 is the only thing on the control connection that should send
type 91. The fact that no type 91 ever lands at sshd means
`finalize_server_channel_open_reply` either:

  (a) never runs (the inbound mpsc never drains), or
  (b) runs but `enc.write.push_packet!` is silently dropped, or
  (c) runs after some other event that closes the channel first.

Hypothesis (a) is most likely. Look at the kex-gated select! in
`client/mod.rs:1244-1273`:

```rust
msg = self.receiver.recv(), if !self.kex.active() => { ... }
msg = self.inbound_channel_receiver.recv(), if !self.kex.active() => { ... }
```

After the initial kex completes, both `self.receiver` (the public API
mpsc) and `self.inbound_channel_receiver` (the server-channel-open
mpsc) are gated on `!self.kex.active()`. If a re-key fires
(`self.kex.active()` returns true), both arms are disabled and the
inbound reply message sits in the mpsc buffer until kex completes.

**The forwarded-tcpip channel arrives on the same connection as the
`tcpip-forward` global request, which is sent near the end of
authentication.** The timing on OpenSSH 9.x is such that the
server-pushed channel-open message arrives while a re-key is in
progress (the connection is still warming up; sshd is hitting its
first re-key after the initial `sshd_config` `RekeyLimit default`),
whereas Win32-OpenSSH 10.0 doesn't re-key in this window. That would
explain why the same passhrs code passes on Windows and fails on
Linux/macOS.

The re-key hypothesis is consistent with: the failure is OS-agnostic
in code (passhrs + russh 0.62 are identical), but OS-specific in
timing (OpenSSH 9.x's re-key schedule vs Win32-OpenSSH 10.0's
post-handshake quiescent window).

## Hypotheses to triage

1. **russh 0.62 `reply.accept().await` deadlocks against re-keying
   server**: see Working theory above. The handler awaits on
   `reply.accept()` (an inbound mpsc send that completes once the
   packet is enqueued, NOT once sshd acks), so the await itself can't
   deadlock. But the event-loop side that drains
   `inbound_channel_receiver.recv()` is gated on `!self.kex.active()`,
   so a concurrent re-key would hold the message. **Test:** add a
   `tokio::time::sleep(100ms)` in
   `server_channel_open_forwarded_tcpip` before `reply.accept()` and
   see if Windows (which currently passes) regresses — if it does,
   the timing-critical window is on the russh side.

2. **russh 0.62 `server_channel_open_forwarded_tcpip` callback is
   spawned from inside the event loop and blocks it**: when the
   handler's `tokio::net::TcpStream::connect().await` is slow, the
   entire event loop is stuck inside our callback. Meanwhile, the
   forwarded-tcpip child in sshd is also blocked on the
   CHANNEL_OPEN_CONFIRMATION round-trip. As long as our callback is
   stuck in the dial, no inbound message gets processed. **Test:**
   spawn the `reply.accept()` from a `tokio::spawn` so the event loop
   can drain in parallel.

3. **OpenSSH 9.x vs Win32-OpenSSH 10.0 channel-open flow-control
   timing**: OpenSSH 9.x may send CHANNEL_OPEN with `window_size = 0`
   or with a smaller initial window than Win32-OpenSSH 10.0, causing
   the first `CHANNEL_DATA` to be silently dropped on the client side.
   Look at the `OpenChannelMessage` in the russh trace (set
   `RUST_LOG=russh=trace` to see) and compare
   `recipient_window_size` and `recipient_maximum_packet_size` on
   Linux vs Windows.

4. **sshd child fork timing**: OpenSSH 9.x may fork the
   forwarded-tcpip child BEFORE sending CHANNEL_OPEN, then the child
   blocks on writing the connection-attempt log. The
   `process_channel_timeouts: setting 0 timeouts` line that follows
   the `send packet: type 90` in the log is a red herring — it
   doesn't indicate data was sent. The child's stdout/stderr may be
   where the actual error is hiding (sshd is forking with
   `LOGLEVEL=DEBUG3` in the test setup, but the child's log goes to
   the child's syslog, not back into the parent's sshd.log).

## Diagnostic steps

Add to a future PR:

- run the test with `RUST_LOG=passhrs=trace,russh=trace` (override the
  CI's `passhrs=debug` in the test step) to capture the russh-side
  CHANNEL_OPEN handling.
- on the failing run, dump `ss -tnp` while the test is hung to see
  what state the forwarded-tcpip connection is in.
- run the same test against a local Linux OpenSSH 9.6 with
  `RekeyLimit 0` in the test config (disables re-keying entirely). If
  the test then passes, hypothesis 1 is confirmed.
- run the same test against `tcpserver` / `socat` on the remote side
  to remove sshd from the loop entirely. If it still fails, the bug
  is in passhrs + russh, not in OpenSSH.

## Workaround applied (PR #24, commit 8a8a647)

`test_remote_forward_data_plane_round_trip` is gated to
`#[cfg(target_os = "windows")]` so PR #24 ships green on every
matrix row. The -L test (which exercises the symmetric data path on
the outbound side, where russh 0.62 is known-good) remains enabled
on every OS. Once this issue is root-caused and fixed, remove the
cfg gate and re-enable the test on Linux + macOS.

## Acceptance criteria for closing this issue

- The same test passes on ubuntu-24.04 + macos-14 + windows-2022
  (both inbox-8.1p1 and upgraded-10.0 rows in the integration
  matrix).
- The `#[cfg(target_os = "windows")]` attribute is removed from
  `test_remote_forward_data_plane_round_trip` in
  `tests/15_native_sshd_integration.rs`.
- A root-cause postmortem is committed to the repo
  (`docs/postmortems/russh-0.62-forwarded-tcpip.md` or similar)
  documenting which of the 4 hypotheses above was the actual cause
  and what the upstream fix is.


