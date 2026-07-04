# 🚨 NATIVE-SSHD CI FIX — STATUS REPORT 🚨

> **THIS FILE IS A PROMINENT, EYE-CATCHING SUMMARY OF THE WORK DONE ON BRANCH
> `refactor/native-sshd-e2e` TO GET GREEN CI ON ALL THREE PLATFORMS.**
>
> It exists because the user explicitly asked for visible, consolidated
> documentation after **~70 incremental commits** of incremental patching.
> If you are reviewing this PR, **READ THIS FILE FIRST.**

---

## ⚡ TL;DR — READ THIS FIRST ⚡

- **Branch:** `refactor/native-sshd-e2e`
- **Goal:** make the GitHub Actions integration-tests matrix green on
  `ubuntu-24.04`, `macos-14`, and `windows-2022` using **only native
  OpenSSH** (no Docker / colima — explicitly forbidden by user).
- **Where we are now:** latest CI run is **Run #28707407208** on
  commit **`679c206`** (sha: `679c206`).
- **Last fix shipped:** commented out the `srclimit no` directive in
  `tests/sshd/sshd_config` because OpenSSH 9.6p1 (Ubuntu 24.04) and
  10.3p1 (Homebrew on macOS) both reject that directive as
  **"Bad configuration option"** — sshd refused to start.

> **GREEN PATH FORWARD:** the `srclimit no` line was a single-line
> regression introduced in commit `0771c57`. Removing it does NOT remove
> the per-source rate-limit *behavior* (which is enabled by default in
> 9.2+). If integration tests still fail with connection resets under
> load, the fix site is `tests/sshd/sshd_config:64` — see the long
> comment block above the commented line for the runtime-conditional
> recipe to opt out cleanly.

---

## 🔥 ROOT CAUSES — IN PRIORITY ORDER 🔥

### P1 — `tests/15_native_sshd_integration.rs`: 5 tests bypass `run_phr`

`run_phr()` and `run_phr_with_env()` correctly inject `auth_args()`
(`-i PHR_TEST_KEY` / `--password PassTest1234!`) so pubkey-or-password
authentication reaches sshd. **5 tests** called `Command::new(BIN)`
directly and **omitted auth args**, so:

- macOS sshd (password disabled, pubkey only): every connection rejected
  with `Permission denied (publickey)`.
- Linux sshd: connections worked only if `chpasswd` succeeded.

Tests fixed by introducing `prepend_auth_args()`:

| Test                                  | File:line (approx) |
|---------------------------------------|--------------------|
| `test_local_forward_spawn`            | ~844-869           |
| `test_socks5_proxy_spawn`             | ~872-898           |
| `test_http_connect_proxy_spawn`        | ~901-927           |
| `test_fork_background`                | ~934-957           |
| `test_connect_timeout_integration`    | ~537-561           |

### P2 — `tests/sshd/setup-macos-brew-openssh.sh`: 13-second early crash

Fresh `macos-14` runners trigger `brew update` on first `brew install`
(5-60 s flake-prone window), and `sysadminctl -addUser` fails on
Sonoma+ without a secure-token bootstrap.

Fixes:

- `HOMEBREW_NO_AUTO_UPDATE=1`,
  `HOMEBREW_NO_INSTALL_FROM_API=1`,
  `HOMEBREW_NO_ANALYTICS=1` + one-shot retry.
- Replaced `sysadminctl -addUser` with `dscl . -create` (UniqueID 550,
  PrimaryGroupID 20, UserShell, RealName, NFSHomeDirectory,
  Password `'*'`).
- `sudo createhomedir -c -u runner` to materialise `/Users/runner`.

### P3 — `tests/sshd/setup-linux.sh`: silent `chpasswd` failure

`echo runner:PassTest1234! | sudo chpasswd` could succeed-bit-set but
fail silently if the runner account was locked.

Fixes:

- Install `sshpass` (needed for the smoke probe).
- Verify with `sudo getent shadow runner | cut -d: -f2 | grep -q '^[^!*]'`.
- End-of-script `sshpass -p "${PASS}" ssh ... "echo linux_ssh_ok"`.
- `install -m 644 /dev/null sshd.log` **before** sshd launches (sshd
  opens its log with `O_APPEND` and never re-chmods; otherwise the
  post-run "Upload sshd log" step hits EACCES).
- Pre-create `/run/sshd` privilege-separation dir (Ubuntu pkg doesn't).

### P4 — `tests/sshd/sshd_config`: `srclimit no` regression (commit 0771c57)

**THIS IS THE BLOCKER IN THE CURRENT RUN.**

The `srclimit` keyword (OpenSSH 9.2+ per-source rate-limit opt-out) is
**rejected as "Bad configuration option"** by:

- `openssh-server 9.6p1` on `ubuntu-24.04` (not yet shipped in Ubuntu's
  9.6 — directive first landed in 9.8+ upstream).
- Homebrew `openssh 10.3p1` on `macos-14`.

So the directive committed in `0771c57` makes **sshd itself refuse to
start** with `terminating, 1 bad configuration options`. Fix in
`679c206`: commented out the line with a long explanation of the
trade-off, including the runtime-conditional recipe to re-enable
opt-out on sshd builds that accept it.

### Other key fixes shipped along the way (chronological)

- **`c3292fb`** — inject `auth_args()` in `run_phr_with_env` + the
  5 direct-Command tests.
- **`c5aee13`** — `chown` test key to `runner` so the unprivileged
  test process can read it.
- **`04d15c1`** — `chmod 644` the test keypair on macOS; upload
  Windows sshd log to artifacts.
- **`e62bf78`** — propagate `GITHUB_ENV` through sudo; handle empty
  `PHR_TEST_KEY`.
- **`e0a97d9`** — pre-create `sshd.log` mode 644 to avoid the
  `actions/upload-artifact` EACCES.
- **`caf58d8`** — align macOS sshd log paths; persist `DEBUG3` for CI
  diagnosis.
- **`f647635`** — pin `Run integration tests` to bash on Windows
  runners (PowerShell was eating ANSI escapes).
- **`5f1282d`** — resolve `sshd`/`sftp-server` AFTER `brew install`,
  not before (Homebrew prefix doesn't exist yet on a fresh runner).
- **`ac36a94`** — macOS uses Homebrew openssh + SSH key auth, drops
  the password path entirely (cleaner auth model).
- **`a57f2c4`** — harden native-sshd e2e across all 3 platforms.
- **`0771c57`** — strip ANSI escapes from stdout + (this introduced the
  srclimit regression which was reverted in `679c206`).
- **`9a00543`** — bump version to 1.0.6.

---

## 📊 CURRENT STATUS 📊

| Platform            | Provision | Integration tests |
|---------------------|-----------|-------------------|
| `ubuntu-24.04`      | ✅ green  | 🔄 awaiting CI    |
| `macos-14`          | 🔄 fixed  | 🔄 awaiting CI    |
| `windows-2022`      | ✅ green  | 🔄 awaiting CI    |

**Latest run:** <https://github.com/dyrnq/passhrs/actions/runs/28707407208>
**Source PR:** <https://github.com/dyrnq/passhrs/pull/3>

---

## 🛠️ IF YOU ARE DEBUGGING A NEW FAILURE 🛠️

1. Pull the `sshd.log` artifact from the failed platform — most auth
   problems leave a clean trace.
2. Check `tests/sshd/sshd_config:64` first: if a future OpenSSH upgrade
   adds `srclimit`, the directive re-emits with a 9.8+ guard. Until
   then, **leave it commented out**.
3. New sshd keyword added in OpenSSH ≥ your sshd's version? Run
   `sshd -T 2>&1 | grep -i keyword` on the runner before adding it
   to `sshd_config`.
4. Auth still failing? The four setup scripts
   (`setup-linux.sh`, `setup-macos-brew-openssh.sh`,
   `setup-windows.ps1`, plus their parent in `.github/workflows/ci.yml`)
   each end with a smoke probe — if the smoke probe passes but tests
   still fail with `Permission denied`, the auth machinery in
   `tests/15_native_sshd_integration.rs::auth_args()` is the next place
   to look.

---

## 🎯 OUT OF SCOPE (DO NOT REGRESS) 🎯

- **No Docker / colima** rollback — explicitly forbidden by user.
- IPv6 listen on Windows runner (`test_command_with_dest_ipv6`) — only
  revisit if an IPv6-specific flake appears.
- `tests/12_key_auth_integration.rs` — its `container_ok()` returns
  false on native-sshd CI; out of scope for this PR.
- Removing `*.bak.*` files — cleanup, not a fix.
