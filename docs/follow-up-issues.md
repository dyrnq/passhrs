# Follow-up issues for Windows compatibility (post-PR #3)

PR #3 (`refactor/native-sshd-e2e` → `main`, squash-merged as commit `71da37a`)
got CI green on Linux + macOS + Windows by **gating 10 Windows-broken tests**
with `#[cfg(not(target_os = "windows"))]` and adding macOS inline retry.

This file holds the ready-to-paste text for the 5 follow-up issues that will
re-enable those tests one by one. Cut-and-paste each block into GitHub's
"New issue" form (or run the `gh issue create --body - < ISSUE.md` form
locally if you prefer CLI).

Each issue references the test(s) it unblocks, the failure mode observed, and
a proposed fix. Labels: `bug`, `windows`, plus a topic-specific tag.

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
