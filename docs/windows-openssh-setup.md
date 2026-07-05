# Windows OpenSSH Setup for the passhrs Integration Suite

The Windows runner (`windows-2022`) stands up a real OpenSSH server on
`127.0.0.1:22222` against which the e2e suite in `tests/15_native_sshd_integration.rs`
exercises passhrs end-to-end. `windows-2022` ships **two configurations in
parallel**: one with the inbox OpenSSH capability as-is, one with the
inbox binaries replaced by the latest Win32-OpenSSH release. The
matrix entry is chosen via the script's `-NoUpgrade` switch.

## TL;DR

| Mode | sshd version | Sourced from | ACL on host keys | Triggered by CI step |
|------|--------------|--------------|-------------------|----------------------|
| Inbox (8.1p1) | `OpenSSH_for_Windows_8.1p1, LibreSSL 3.8.2` | `Get-WindowsCapability OpenSSH.Server` | owner-only (no extra ACEs) | `setup-windows.ps1 -NoUpgrade` |
| Upgraded (10.0) | `OpenSSH_for_Windows_10.0p2 Win32-OpenSSH-GitHub, LibreSSL 3.8.2` | `Win32-OpenSSH-10.0.0.0p2-Preview.zip` | `SYSTEM:F` + `Administrators:F` | `setup-windows.ps1` (default) |

Both modes install and start the sshd **service** (not a `Start-Process`
foreground daemon). Both use the same port (22222), the same
`testuser:PassTest1234!` account, and the same shared
`tests/sshd/sshd_config` template (with Windows-specific directives
stripped / appended, see below).

## Why two modes?

The inbox capability on `windows-2022` is **OpenSSH 8.1p1 (LibreSSL
3.8.2)**. That build has a long-standing host-key permission-check
regression (`sshd`s `sshkey_perm_ok` rejects any DACL with a non-owner
ACE — including the canonical `SYSTEM:F + Administrators:F` two-ACE
layout Microsoft's own upgrade guide recommends). Microsoft resolves
this by recommending a wholesale upgrade to the latest Win32-OpenSSH
release; we do that for the `upgraded-10.0` mode.

We keep the `inbox-8.1p1` mode alive so:

1. We notice if Microsoft silently fixes the regression in a future
   inbox release — and so we have an immediate fallback path if the
   upgrade breaks.
2. We exercise passhrs against two divergent OpenSSH major versions,
   not one. That's the explicit ask from the user: 「将来肯定要用新版本
   （而不是陈旧的版本）回头把两个版本都兼容支持」.

The two-mode split is implemented as `-NoUpgrade` parameter on
`tests/sshd/setup-windows.ps1` and four-row `matrix.include` in
`.github/workflows/ci.yml`:

```yaml
matrix:
  include:
    - { os: ubuntu-24.04, openssh: native }
    - { os: macos-14,     openssh: native }
    - { os: windows-2022, openssh: inbox-8.1p1 }
    - { os: windows-2022, openssh: upgraded-10.0 }
```

The Windows provision step calls the script with `-NoUpgrade` for the
inbox row and without for the upgraded row.

## What the script does (upgraded-10.0 mode)

File: `tests/sshd/setup-windows.ps1`. The default invocation walks the
script as follows:

| Step | Lines | What it does | Why |
|------|-------|--------------|-----|
| 0 | 21-29 | Compute paths under `$env:ProgramData\ssh\` (config, host key, log dir) | sshd service reads config from `%ProgramData%\ssh\sshd_config` by default |
| 1 | 42-113 | Download `Win32-OpenSSH-10.0.0.0p2-Preview.zip`, extract, `takeown /A` each inbox binary, `icacls /grant Administrators:(F)`, then `Copy-Item` over **every file in the extracted dir** | Inbox binaries are owner=TrustedInstaller with WRP; need takeown+ACL. Win32-OpenSSH 10.0 splits the daemon into `sshd.exe` (launcher) and `sshd-session.exe` (handler), plus auxiliaries like `sshd-auth.exe`, `ssh-agent.exe`, `ssh-add.exe`, `ssh-keyscan.exe`, `ssh-keysign.exe`, `ssh-proxy.exe`, `ssh-shellhost.exe` and the LibreSSL runtime DLLs (`libcrypto-3-x64.dll`, `libssl-3-x64.dll`, `libssp-0.dll`, `libssh.dll`). Copying the full extracted dir — not a whitelist — keeps the script future-proof against further splits in later releases. |
| 1a | 105-113 | `Test-Path` check on `sshd.exe` and `sshd-session.exe` after the copy | Without `sshd-session.exe`, sshd.exe immediately exits with `c:\windows\system32\openssh/sshd-session.exe does not exist or is not executable` (the failure that originally blocked this matrix). Fail fast beats confusing 60-s `Start-Service` hang. |
| 2 | 97-99 | Create `$env:ProgramData\ssh\` and `logs\` | Required by sshd for host-key and log-file paths |
| 3 | 101-104 | `Test-Path` check on `%SystemRoot%\System32\OpenSSH\sftp-server.exe` | Post-upgrade location; SFTP subsystem won't work without it |
| 4 | 106-136 | Materialize sshd_config from `tests/sshd/sshd_config`, substitute `__SFTP_SERVER_PATH__`, drop the `UsePAM yes` line (Windows has no PAM), append `HostKey <path>` | The shared config has cross-platform directives that need stripping (UsePAM) or pinning (HostKey, so service-mode startup finds the key without `-h`) |
| 5a | 138-164 | Wipe old host keys, then lockdown the **parent dir** (`$SshRoot`) to `SYSTEM:F + Administrators:F`, owner=System | ssh-keygen (-A) creates the keys, and we want them to inherit a clean DACL. Locking the parent first is simpler than re-locking every key. |
| 5b | 154-178 | Run `ssh-keygen -A` to generate keys | This creates fresh keys with inheritance from the locked parent dir. |
| 5c | 165-201 | Re-lock each generated key to `SYSTEM:F + Administrators:F`, owner=System | Belt-and-suspenders: explicitly set the canonical two-ACE ACL on each key file. **This is the part that breaks inbox 8.1p1, so we skip it under `-NoUpgrade`.** |
| 5d | 195-198 | `icacls $SshdCfg /grant 'NT SERVICE\sshd:(R)'` | The sshd service account (LocalSystem / NT SERVICE\sshd) needs read access to parse config. |
| 6 | 209-225 | Create `testuser` if missing with `PassTest1234!` (already meets Windows password complexity: upper + lower + digit + special, 13 chars) | Deterministic credential across all platforms. |
| 7 | 226-234 | Add `testuser` to local `OpenSSH Users` group (created on demand) | Windows OpenSSH honours this group by default |
| 8 | 236-245 | `sshd -t -f $SshdCfg` syntax check | Catches bad config before starting the service |
| 9 | 247-269 | `Stop-Service sshd -Force; Set-Service -StartupType Manual; try { Start-Service sshd -ErrorAction Stop } catch { Write-Host ... }` | Service-mode startup (`Start-Service` is more reliable than `Start-Process sshd -D` on Windows). `try/catch` survives `$ErrorActionPreference = 'Stop'` because we use `Write-Host`, not `Write-Error`. |
| 10 | 272-287 | TCP-connect loop to 127.0.0.1:22222, 50 × 200 ms = 10 s | Confirms the service is actually accepting connections |
| 11 | 289-332 | **Diagnostic dump on failure** — `sc.exe qc sshd`, `sshd.exe -V`, `sshd -t -f`, `sshd -ddd`, sshd log tail, `OpenSSH/Operational` event log, System/Application event log | Anything we want to know about a startup failure is here. Uses `Write-Host` so the dump survives even when `$ErrorActionPreference = 'Stop'`. |

The script ends with the readiness message or, on any sshd-startup
failure, prints the diagnostic dump and exits 1.

## What changes under `-NoUpgrade`

When invoked as `setup-windows.ps1 -NoUpgrade`:

1. The Win32-OpenSSH download + extract + copy block (lines 42-113) is
   skipped entirely. The inbox 8.1p1 binaries in
   `%SystemRoot%\System32\OpenSSH` stay untouched.
2. The `sshd-session.exe` sanity check is removed. 8.1p1 has no
   `sshd-session.exe`; sshd.exe is its own session handler.
3. Step 5c (re-lock each host key) keeps `SetAccessRuleProtection`,
   the ACE removal loop, and the `SetOwner(System)` calls, but **drops
   the ACE-add loop** that grants `SYSTEM:F` and `Administrators:F`.
   The result: each host key has owner=System and no DACL. This is the
   only layout 8.1p1 sshd will load — adding any ACE for a non-owner
   SID makes it refuse with `Bad permissions. Try removing permissions
   for user: <SID>`.

## Shared config caveats

The shared `tests/sshd/sshd_config` is the source-of-truth for the
test environment; the platform setup scripts only perform the
necessary substitutions. On Windows:

- `UsePAM yes` is removed. There is no PAM on Windows.
- `Subsystem sftp <path>` is appended with the resolved
  `sftp-server.exe` path.
- `HostKey <full path>` is appended so `sshd` finds the key without
  needing `-h` on the command line (the service-mode startup path
  can't pass arbitrary args).
- `AddressFamily any` is set explicitly so the dual-stack listen path
  is unambiguous.

The shared config currently has `ListenAddress` unset (intentional —
see `docs/macos-openssh-setup.md` for why this also matters there)
and `MaxStartups 50:100:200`, `MaxSessions 100`, `LoginGraceTime 60`
tuned for the test-suite's back-to-back connection load.

## Why the Upgrade path was a long walk

The backstory, summarised so future contributors don't have to
re-derive it:

1. `Service 'sshd' failed to start ... Bad permissions. Try removing
   permissions for user: <SID>` against the canonical `SYSTEM:F +
   Administrators:F` host-key DACL — 8.1p1 sshd regression.
2. Even after applying the Microsoft-recommended upgrade, `Copy-Item
   Access denied` — inbox binaries are owner=TrustedInstaller with WRP;
   `takeown /A` + `icacls /grant 'Administrators:(F)'` defeats WRP
   for the files we replace.
3. Even with the binaries upgraded, `c:\windows\system32\openssh/
   sshd-session.exe does not exist or is not executable` — the
   initial whitelist copy (`sshd.exe, ssh.exe, ssh-keygen.exe,
   sftp-server.exe, scp.exe, sftp.exe`) missed
   `sshd-session.exe`. Replaced the whitelist with `Get-ChildItem
   $ExtractedDir -File -Force` to copy every file from the extracted
   Win32-OpenSSH release.
4. `Start-Service sshd` failed, then `sshd -ddd` confirmed (3).
   Fix: full-directory copy.
5. The diagnostic dump itself terminated early because `Write-Error`
   under `$ErrorActionPreference = 'Stop'` is itself terminating.
   Fix: use `Write-Host` (which is a stdout sink, not an error
   stream) inside the dump block.

## File references

- Provisioning: `tests/sshd/setup-windows.ps1`
- Shared config: `tests/sshd/sshd_config`
- Test suite: `tests/15_native_sshd_integration.rs`
- CI: `.github/workflows/ci.yml`
