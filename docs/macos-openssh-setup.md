# macOS OpenSSH Setup for the passhrs Integration Suite

The macOS runner (`macos-14`) stands up the OS-shipped OpenSSH server
on `127.0.0.1:22222` and exercises the e2e suite in
`tests/15_native_sshd_integration.rs` against it. Unlike Linux and
Windows, no OpenSSH installation is needed — `/usr/sbin/sshd` and
`/usr/libexec/sftp-server` come with the OS — but the
**detachment pattern matters** because macOS's process-group
behaviour interacts badly with bash job control on CI runners.

## TL;DR

| Aspect | Value |
|--------|-------|
| sshd path | `/usr/sbin/sshd` (stock macOS) |
| sftp-server path | `/usr/libexec/sftp-server` (stock macOS) |
| Test user | `testuser`, password `PassTest1234!` (created via `dscl`) |
| Listen | `127.0.0.1:22222` and `[::1]:22222` (dual-stack loopback) |
| Launch | `sudo /usr/sbin/sshd -D &` wrapped in `nohup`, stdio→`/dev/null`, `disown -h` |
| Config | `tests/sshd/sshd_config` materialised to `${TMPDIR}/passhrs-test-sshd/sshd_config` |

## Why the detachment trick

The naive pattern
```
sudo /usr/sbin/sshd ... -D &
```
keeps sshd in the script's bash job table. When the script exits,
bash sends SIGHUP to remaining backgrounded children, which kills
sshd. The TCP readiness probe at the end of the script passes
because the TCP listener is up the moment `-p 22222` is parsed, but
~100 seconds later — between the end of `cargo build --release` and
the start of `cargo test` — passhrs tries to open a real SSH
session, sshd is gone, and every test gets `Connection reset by
peer (os error 54)`.

That is precisely what the macOS integration suite hit on
2026-07-04 run `28691512307`: 23 of 29 sshd-touching tests failed
with `Connection reset by peer` immediately, while the unit-test
binaries (which don't touch sshd) passed.

The fix in `tests/sshd/setup-macos.sh` is to **fully detach**:

```bash
sudo "${SSHD_BIN}" \
    -f "${SSHD_CFG}" \
    -h "${HOST_KEY}" \
    -E "${SSHD_LOG}" \
    -p "${PORT}" \
    -D \
    </dev/null >/dev/null 2>&1 &
SSHD_PID=$!
echo "${SSHD_PID}" > "${SSHD_PID_FILE}"
nohup sudo kill -0 "${SSHD_PID}" >/dev/null 2>&1 || true
disown -h "${SSHD_PID}" 2>/dev/null || disown "${SSHD_PID}" 2>/dev/null || true
```

What each piece does:

- `</dev/null >/dev/null 2>&1` — sshd inherits no stdio from the
  script. Without it, sshd's stdin/stdout/stderr are connected to
  the script's pipes; when the script exits, those pipes close and
  sshd may receive SIGPIPE / EOF on the next read.
- `&` plus `disown -h` — removes sshd from bash's job table and
  marks it to NOT receive SIGHUP. The `disown -h` form is GNU
  bash; on macOS bash 3.2 (the Apple-shipped `/bin/bash`) `disown
  -h` may not be supported, hence the fallback to plain `disown`.
- `nohup ... kill -0` — belt-and-suspenders: re-confirms sshd is
  alive via `sudo kill -0` after the `nohup` shim. Without this,
  if detach silently failed and sshd died, the readiness loop would
  just spin waiting on `/dev/tcp` and surface as a generic
  `sshd did not start within 10s` after 10 s; with this, we know
  the sshd PID went away and print the actual log immediately.

We keep `-D` so we can `kill $SSHD_PID` directly (the daemonsised
form would put the daemon PID inside sshd's fork tree, and we
would not be able to read it back from `$!`).

## What the script does step by step

File: `tests/sshd/setup-macos.sh`.

| Step | Lines | What it does | Why |
|------|-------|--------------|-----|
| 0 | 9-25 | Resolve paths under `${TMPDIR}/passhrs-test-sshd/` (config, host key, log, pidfile) | Per-run ephemeral state |
| 0a | 27-34 | `Test-Path` style checks on `/usr/sbin/sshd` and `/usr/libexec/sftp-server` | Stock macOS has both; we fail fast if a stripped image lacks one |
| 1 | 38-41 | `sed`-substitute `__SFTP_SERVER_PATH__` in shared sshd_config template → write to `${SSHD_CFG}` | Shared config is platform-agnostic |
| 2 | 43-46 | Generate host key on first run (`ssh-keygen -t ed25519`), reuse on subsequent runs | Re-using the host key keeps `~/.ssh/known_hosts` stable across reruns. |
| 3 | 48-60 | Create `testuser` via `dscl . -create /Users/testuser ...` and `sudo createhomedir -u testuser` | macOS user records live in OpenDirectory, not `/etc/passwd`. The naive Linux `useradd` would silently fail or write to /etc/passwd (which is no longer authoritative on modern macOS). |
| 3b | 62-63 | `sudo dscl . -passwd /Users/testuser PassTest1234!` | Reset password each run so the credential stays deterministic |
| 4 | 65-72 | Tear down any previous sshd bound to 22222 by reading `${SSHD_PID_FILE}` and sending SIGTERM | Idempotent re-runs |
| 5 | 74-100 | Launch sshd fully detached (see above) | **The critical step — see "Why the detachment trick"** |
| 6 | 102-116 | Readiness probe: 50 × 200 ms TCP-connect loop with `kill -0` liveness check | Fails fast if sshd died during launch |

## Shared config (dual-stack, headroom for the test suite)

`tests/sshd/sshd_config` is shared across all three platforms; only
the per-platform setup script does environment-specific
substitutions. Two settings matter specifically for macOS:

1. **`ListenAddress` is unset.** macOS sshd (and Linux/OpenSSH in
   general) defaults to listening on all interfaces when no
   `ListenAddress` is given. Combined with `AddressFamily any` (set
   in the shared config), sshd binds `0.0.0.0:22222` and `[::]:22222`.
   This is required by `test_command_with_dest_ipv6` in
   `tests/15_native_sshd_integration.rs`, which connects as
   `testuser@[::1]`. Previous to the fix, `ListenAddress 127.0.0.1`
   silently dropped v6 and the test failed with `Connection refused
   (os error 111)`.

2. **Generous `MaxStartups`, `MaxSessions`, `LoginGraceTime`.** The
   test suite, with `--test-threads=1`, still opens a fresh SSH
   session per test (29 tests in `tests/15` plus several others).
   OpenSSH's default `MaxStartups 10:30:100` starts dropping 30 %
   of unauthenticated connections once 10 are queued; combined with
   kernel `TIME_WAIT`, the test suite sees mid-handshake connection
   resets. The shared config now uses:

   ```
   LoginGraceTime 60
   MaxStartups 50:100:200
   MaxSessions 100
   ```

   These values are well above the real concurrency the tests need
   (≤ 4 simultaneous connection attempts) but headroom protects
   against any unexpected parallelism or upstream delays.

## User creation, macOS-style

The `dscl . -create` sequence (lines 50-60) is the supported way to
add a local user on macOS that survives reboots:

```bash
sudo dscl . -create "/Users/${USER}"
sudo dscl . -create "/Users/${USER}" UserShell "/bin/zsh"
sudo dscl . -create "/Users/${USER}" RealName "Passhrs Test User"
sudo dscl . -create "/Users/${USER}" UniqueID "55555"
sudo dscl . -create "/Users/${USER}" PrimaryGroupID 20
sudo dscl . -create "/Users/${USER}" NFSHomeDirectory "/Users/${USER}"
sudo dscl . -create "/Users/${USER}" Password "${PASS}"
sudo createhomedir -u "${USER}"
```

- `UserShell` is set to `/bin/zsh` because GitHub-hosted
  `macos-14` images ship zsh as the default user shell, and
  testuser needs a real shell to be allowed to authenticate over
  SSH (`PermitRootLogin yes` in the shared config; the user
  account must have a usable shell).
- `UniqueID 55555` is high enough not to collide with system UIDs.
- `PrimaryGroupID 20` is the `staff` group, which gets read/write
  on the user's home directory by `createhomedir`.

Without `createhomedir`, `testuser` exists in OpenDirectory but has
no `/Users/testuser` directory, so sshd's `chdir`-to-home-step
fails with `Could not chdir to home directory /Users/testuser: No
such file or directory`. That was an early iteration blocker.

## Diagnostic surface on failure

If sshd fails to start (readiness probe times out OR `kill -0`
sees the PID gone), the script prints the last 50 lines of
`${SSHD_LOG}` and exits 1. The CI log captures that as part of
the failed step's output, which is enough to debug most startup
problems — typically a syntax error in the rendered config or
the host key ACL regressing.

For deeper debugging:
- `scutil --dns` — DNS resolver state (rarely relevant on a clean
  runner)
- `sudo lsof -nP -iTCP:22222 -sTCP:LISTEN` — confirms the listener
- `ps -p $SSHD_PID -o pid,ppid,pgid,sid,command` — confirms sshd's
  process group and session

## File references

- Provisioning: `tests/sshd/setup-macos.sh`
- Shared config: `tests/sshd/sshd_config`
- Test suite: `tests/15_native_sshd_integration.rs`
- CI: `.github/workflows/ci.yml`
