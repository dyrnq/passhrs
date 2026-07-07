# Provision a real OpenSSH server on 127.0.0.1:22222 on a Windows runner.
#
# Targets GitHub-hosted windows-2022 runners. The OpenSSH server is
# installed as a Windows capability; we then create a local testuser,
# write a minimal sshd_config, and start the sshd service.
#
# Note: the default password 'PassTest1234!' already meets Windows
# password complexity (upper + lower + digit + special, 13 chars),
# so no Local Security Policy tweak is required.
[CmdletBinding()]
param(
    # GitHub-hosted windows-2022 runners (since runner 2.305.0) create a
    # local account named `runneradmin` — there is NO `runner` user.
    # Earlier runner images created `runner` and the setup was correct,
    # but the current image rejects `Get-LocalUser -Name 'runner'` with
    # a "not present" error. We default to `runneradmin` and accept
    # either name on the command line so the same script works against
    # both image variants.
    [string]$User = 'runneradmin',
    # PassTest1234! satisfies Windows password complexity (upper + lower
    # + digit + special, 13 chars). Same value used by every platform
    # setup script and the e2e tests so the test sshd authenticates
    # passhrs consistently across Linux, macOS and Windows runners.
    [string]$Pass = 'PassTest1234!',
    [int]$Port = 22222,
    [string]$SshdConfigTemplate = "$PSScriptRoot\sshd_config",
    # Skip the Win32-OpenSSH 10.0 download/replace and keep the inbox
    # 8.1p1 binaries + the 8.1p1-compatible single-ACE host-key ACL.
    # CI matrix widens to exercise BOTH code paths: -NoUpgrade=false
    # (default) is the previously-validated upgrade path that goes
    # 33/33 green on windows-2022; -NoUpgrade=true exercises the
    # inbox 8.1p1 capability as-shipped by Microsoft, which is the
    # baseline most end-users will actually run. Issue #17 / PR
    # ci:split-windows-matrix tracks the matrix widening.
    [switch]$NoUpgrade = $false
)
$ErrorActionPreference = 'Stop'

$ListenHost = '127.0.0.1'
$ProgData   = $env:ProgramData
$SshRoot    = Join-Path $ProgData 'ssh'
$SshdCfg    = Join-Path $SshRoot 'sshd_config'
$HostKey    = Join-Path $SshRoot 'ssh_host_ed25519_key'
$SftpServer = Join-Path $env:SystemRoot 'System32\OpenSSH\sftp-server.exe'
$SshdLog    = Join-Path $SshRoot 'logs\sshd.log'
# Diagnostic-only debug log path. The Win32-OpenSSH service wrapper
# reads HKLM\SOFTWARE\OpenSSH-Server-Ini\LogFile / LogLevel and passes
# them to sshd.exe on start, so writing these registry values before
# `Start-Service sshd` makes the service emit a -ddd trace to a fixed
# file. dump-on-failure then prints it inline so a future windows-2022
# red run has a raw protocol trace to diff against a green run. See
# PR #14 root-cause investigation. Remove this block once windows-2022
# is green again.
$SshdDebugLog = Join-Path $SshRoot 'logs\sshd-debug.log'
# Test-user ed25519 keypair for pubkey auth. Mirrors the linux +
# macOS setup scripts so tests/12 (and any future key-auth test)
# can drive `passhrs -i ${TestKey}` against this sshd. The private
# key path is exported as PHR_TEST_KEY for the integration-tests
# step to consume.
$TestKey    = Join-Path $SshRoot 'runner_id_ed25519'
$TestKeyPub = "${TestKey}.pub"

# 1. The inbox Windows OpenSSH capability ships OpenSSH 8.1p1 (LibreSSL
#    3.8.2) on windows-2022 runners and that build has a known
#    permission-check regression: it prints "Bad permissions. Try
#    removing permissions for user: <SID>" against host keys whose DACL
#    has any non-owner ACE, including the canonical
#        SYSTEM:(F) Administrators:(F)
#    "two-ACL" pattern recommended by Microsoft's own upgrade guide.
#    Microsoft's recommended fix is to replace the inbox binaries with
#    the latest Win32-OpenSSH release. We do that by downloading the
#    x64 ZIP and overwriting the binaries in
#    %SystemRoot%\System32\OpenSSH in place.
$Win32OpenSshUrl = 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-Win64.zip'
$WorkDir = Join-Path $env:TEMP 'passhrs-win32-openssh'
$ZipPath = Join-Path $WorkDir 'OpenSSH-Win64.zip'
$ExtractedDir = Join-Path $WorkDir 'OpenSSH-Win64'
$SshdBinDir = Join-Path $env:SystemRoot 'System32\OpenSSH'

# Ensure the OpenSSH capability is present (gives us the sshd service
# registration and the %ProgramData%\ssh layout); the binaries inside
# will be replaced below.
$sshdFeature = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction SilentlyContinue
if ($null -eq $sshdFeature -or $sshdFeature.State -ne 'Installed') {
    Write-Host 'Installing OpenSSH.Server capability...'
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}

if ($NoUpgrade) {
    # Inbox 8.1p1 path: keep the binaries shipped by the OpenSSH
    # capability. Sanity-check sshd.exe is present (8.1p1 has no
    # sshd-session.exe — that split was introduced in Win32-OpenSSH
    # 10.0). Record the version so the post-lockdown summary line
    # shows which path actually ran.
    $sshdInbox = Join-Path $SshdBinDir 'sshd.exe'
    if (-not (Test-Path $sshdInbox)) {
        throw "FATAL: $sshdInbox missing; OpenSSH.Server capability install did not produce sshd.exe"
    }
    $sshdAfterUpgrade = & $sshdInbox -V 2>&1 | Select-Object -First 1
    Write-Host "-NoUpgrade set: keeping inbox OpenSSH capability binaries"
    Write-Host "sshd -V (inbox): $sshdAfterUpgrade"
} else {
Write-Host "Upgrading OpenSSH binaries to Win32-OpenSSH 10.0.0.0..."
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
Invoke-WebRequest -Uri $Win32OpenSshUrl -OutFile $ZipPath -UseBasicParsing
if (Test-Path $ExtractedDir) {
    Remove-Item -Recurse -Force $ExtractedDir
}
Expand-Archive -Path $ZipPath -DestinationPath $WorkDir -Force

# Stop the sshd service before swapping binaries; it caches old ones.
Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Replace every binary the inbox capability installed with the
# matching one from the Win32-OpenSSH release. Win32-OpenSSH 10.0
# is what adds sshd-session.exe: sshd.exe became a thin launcher that
# forks sshd-session.exe for the per-connection session, so leaving
# the old 8.1p1 sshd-session.exe-or-no-session-binary layout means
# sshd.exe immediately exits with
# "c:\windows\system32\openssh/sshd-session.exe does not exist or
# is not executable". We also pull across the auxiliary binaries
# (sshd-auth.exe, ssh-agent.exe, ssh-add.exe, ssh-keyscan.exe,
# ssh-keysign.exe, ssh-proxy.exe, ssh-shellhost.exe) and the
# LibreSSL runtime DLLs (libcrypto-3-x64.dll, libssl-3-x64.dll,
# libssp-0.dll, libssh.dll) — sshd.exe dynamically loads all of
# them, so leaving the inbox 8.1p1 DLLs in place after swapping the
# EXEs is also broken. Iterating over $ExtractedDir keeps the script
# future-proof: future Win32-OpenSSH releases that split or rename
# binaries again will Just Work without editing this list.
$UpgradeFiles = Get-ChildItem -Path $ExtractedDir -File -Force
Write-Host "Win32-OpenSSH release contains $($UpgradeFiles.Count) files; copying all of them to $SshdBinDir"

foreach ($file in $UpgradeFiles) {
    $src = $file.FullName
    $dst = Join-Path $SshdBinDir $file.Name
    # The inbox OpenSSH binaries live under %SystemRoot%\System32\OpenSSH
    # and are protected: they default to owner=TrustedInstaller with a
    # restricted DACL, so Administrator cannot overwrite them even when
    # the sshd service is stopped. Re-acquire ownership and grant
    # Administrators FullControl on each target before overwriting,
    # which is sufficient to defeat Windows Resource Protection for
    # files we ourselves will replace.
    if (Test-Path $dst) {
        takeown /F $dst /A | Out-Null
        icacls $dst /grant 'Administrators:(F)' | Out-Null
    }
    Copy-Item -Path $src -Destination $dst -Force
}

# Sanity check that the file sshd.exe strictly depends on is in place.
# sshd.exe prints a fatal error and exits if this file is missing or
# not executable, so verify before attempting to start the service.
foreach ($required in @('sshd.exe','sshd-session.exe')) {
    $p = Join-Path $SshdBinDir $required
    if (-not (Test-Path $p)) {
        throw "FATAL: $p missing after upgrade; the extracted Win32-OpenSSH release does not contain $required"
    }
}

$sshdAfterUpgrade = & (Join-Path $SshdBinDir 'sshd.exe') -V 2>&1 | Select-Object -First 1
Write-Host "sshd -V after upgrade: $sshdAfterUpgrade"
}



# 2. Ensure sshd directories exist.
New-Item -ItemType Directory -Force -Path $SshRoot | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $SshdLog) | Out-Null

# 3. Locate sftp-server.exe.
if (-not (Test-Path $SftpServer)) {
    throw "FATAL: $SftpServer not found after installing OpenSSH capability"
}

# 4. Materialise sshd_config from the shared template, substituting the
#    Windows sftp-server path. Then drop directives the Windows OpenSSH
#    build rejects (UsePAM, which Linux/macOS require but Windows has
#    no concept of) and append HostKey so the service-mode startup can
#    find the key without a -h CLI flag.
(Get-Content $SshdConfigTemplate -Raw) `
    -replace '__SFTP_SERVER_PATH__', ($SftpServer -replace '\\', '\\') `
    -replace '(?m)^\s*UsePAM\s+yes\s*\r?\n', '' `
    | Set-Content -Path $SshdCfg -Encoding ASCII
Add-Content -Path $SshdCfg -Value "HostKey $HostKey"

# 5. Wipe any prior host keys (including the ones the OpenSSH capability
#    installer pre-created) so ssh-keygen runs against a clean directory
#    and writes a key with no inherited pollution.
Get-ChildItem -Path $SshRoot -Filter 'ssh_host_*' -Force |
    Remove-Item -Force -ErrorAction SilentlyContinue

# 5a. Lock down the parent directory ACL FIRST so ssh-keygen creates new
#     host key files that inherit a clean ACL. Microsoft's OpenSSH 8.1p1
#     is known to reject keys whose SD contains metadata `icacls`
#     cannot fully display — so we now drive everything via the
#     directory and let the keys inherit from it.
#
#     SKIP under -NoUpgrade: 8.1p1 sshd refuses to load a host key
#     whose DACL contains a non-owner ACE (the canonical "Bad
#     permissions. Try removing permissions for user: <SID>" check).
#     The two-ACE SYSTEM:F + Administrators:F pattern below is a
#     non-owner ACE by Administrators' SID, which 8.1p1 rejects.
#     The Win32-OpenSSH 10.0 upgrade removes that historical
#     check, which is why this is the right layout for the
#     upgrade path. For -NoUpgrade, skip the lockdown entirely
#     and let the inbox ssh-keygen create keys with the default
#     ACL (owner=runner user, DACL has just the runner user's
#     ACE) — that layout satisfies 8.1p1's check because every
#     ACE matches the owner, and sshd started via Start-Process
#     inherits the runner user's identity and so can read the
#     key as the file's owner.
$systemSid = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$adminsSid = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
if (-not $NoUpgrade) {
    $dirAcl = Get-Acl -Path $SshRoot
    $dirAcl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($dirAcl.Access)) {
        $dirAcl.RemoveAccessRuleSpecific($rule)
    }
    foreach ($sid in @($systemSid, $adminsSid)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $dirAcl.AddAccessRule($rule)
    }
    $dirAcl.SetOwner($systemSid)
    Set-Acl -Path $SshRoot -AclObject $dirAcl
} else {
    Write-Host "-NoUpgrade set: skipping 5a parent-dir ACL lockdown (inbox 8.1p1 ssh-keygen will set the canonical ACL itself)"
}

# 5b. Generate host keys via ssh-keygen -A, the canonical Windows
#     OpenSSH way that knows the right ACL for host keys. ssh-keygen
#     from the inbox OpenSSH folder is intentional; it's the same
#     binary that produced the warning, so it should produce a key it
#     is willing to load.
$SshBin = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
if (-not (Test-Path $SshBin)) {
    throw "FATAL: ssh-keygen.exe not found at $SshBin"
}
& $SshBin -A
if ($LASTEXITCODE -ne 0) {
    throw "ssh-keygen -A failed (exit $LASTEXITCODE)"
}

# 5c. Re-lock each newly generated host key ACL. With the upgraded
#     Win32-OpenSSH 10.0 the historical 8.1p1 SD regression is gone,
#     so we can use the standard two-ACE ACL the Microsoft upgrade
#     guide recommends: SYSTEM and Administrators, both FullControl.
#     We do still strip inherited ACEs to make sure nothing loose
#     leaks in from the parent directory.
#
#     SKIP under -NoUpgrade for the same reason 5a is skipped: the
#     two-ACE pattern is a non-owner ACE that 8.1p1 sshd rejects.
#     Inbox ssh-keygen created the keys with the canonical 8.1p1
#     layout (owner=runner user, DACL has the runner user's ACE)
#     in step 5b; leave them alone.
if (-not $NoUpgrade) {
    Get-ChildItem -Path $SshRoot -Filter 'ssh_host_*_key' -Force | ForEach-Object {
        $keyFile = $_.FullName
        takeown /F $keyFile /A | Out-Null
        $keyAcl = Get-Acl -Path $keyFile
        $keyAcl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($keyAcl.Access)) {
            $keyAcl.RemoveAccessRuleSpecific($rule)
        }
        foreach ($sid in @($systemSid, $adminsSid)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, 'FullControl', 'Allow')
            $keyAcl.AddAccessRule($rule)
        }
        $keyAcl.SetOwner($systemSid)
        Set-Acl -Path $keyFile -AclObject $keyAcl
    }
} else {
    Write-Host "-NoUpgrade set: skipping 5c per-key ACL lockdown (keys retain the inbox 8.1p1 default ACL)"
}

# 5d. The sshd_config file is not secret — grant NT SERVICE\sshd read
#     so the service can parse its config, while preserving the
#     inherited Administrators ACE that the runner user needs to run
#     `sshd -t -f` for syntax validation.
icacls $SshdCfg /grant 'NT SERVICE\sshd:(R)' | Out-Null

Write-Host "After lockdown, icacls ${HostKey}:"
icacls $HostKey | Out-Host
Write-Host "sshd -V: $sshdAfterUpgrade"

# 6. Set the runner user's password to the known test value. The
#    `runneradmin` account is created by the GitHub-hosted Windows
#    image with admin privileges; we don't New-LocalUser it. Resetting
#    the password via `net user` is the supported way and survives
#    across re-runs. The default $Pass value ('PassTest1234!') already
#    satisfies Windows password complexity (upper + lower + digit +
#    special, 13 chars), so no policy tweak is required.
#
#    `net user` is invoked with `-Pass` quoted as a single token so the
#    `#` in the password is not interpreted as a PowerShell comment
#    delimiter on the call site. (`& net user $User $Pass` works when
#    `$Pass` is already a string variable, but the explicit quoting
#    documents intent and shields against future callers passing the
#    password inline.)
if (-not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
    throw "FATAL: ${User} user not present (expected on GitHub Windows runner; current image uses 'runneradmin', older images used 'runner')"
}
& net user $User "$Pass" | Out-Null

# 7. Allow testuser to authenticate via sshd: add to the SSH users group
#    that Windows OpenSSH honours by default (Administrators + the
#    account's own ACL on the profile directory are also accepted).
$group = 'OpenSSH Users'
if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
    New-LocalGroup -Name $group | Out-Null
}
Add-LocalGroupMember -Group $group -Member $User -ErrorAction SilentlyContinue

# 7a. Generate the test-user ed25519 keypair used by tests/12 (and
#     any future key-auth test). Idempotent: only generate on first
#     run so the file persists across re-runs.
$SshKeygenBin = Join-Path $SshdBinDir 'ssh-keygen.exe'
if (-not (Test-Path $TestKey)) {
    & $SshKeygenBin -t ed25519 -f $TestKey -N '""' -q
    if ($LASTEXITCODE -ne 0) {
        throw "FATAL: ssh-keygen ed25519 failed (exit $LASTEXITCODE)"
    }
}

# 7b. Drop the public key into the runner's authorized_keys.
#     sshd resolves authorized_keys to `%USERPROFILE%\.ssh\authorized_keys`
#     for the authenticated user — NOT the runner that executes this
#     script. On GitHub Windows runners $User (e.g. `runneradmin`)
#     and the runner that executes this script are different
#     accounts with different profile paths.
#
#     (Get-LocalUser $User).Profile is the natural API but returns
#     an empty string for accounts that have never logged in
#     interactively (which is the case for `runneradmin` on a fresh
#     GitHub-hosted runner — the user is created by the image but
#     the profile directory is lazily created on first logon).
#     Construct the path directly from the canonical Windows layout
#     (`C:\Users\<User>`) and verify it exists; throw if not so a
#     future image layout change surfaces here instead of as a
#     cryptic sshd auth failure later.
$userProfile = Join-Path $env:SystemDrive ("Users\$User")
if (-not (Test-Path $userProfile)) {
    throw "FATAL: expected user profile dir not found at $userProfile — image layout changed?"
}
$AuthorizedKeysDir  = Join-Path $userProfile '.ssh'
$AuthorizedKeysPath = Join-Path $AuthorizedKeysDir 'authorized_keys'
New-Item -ItemType Directory -Force -Path $AuthorizedKeysDir | Out-Null
if (-not (Test-Path $AuthorizedKeysPath)) {
    New-Item -ItemType File -Force -Path $AuthorizedKeysPath | Out-Null
}
$pubkeyLine = (Get-Content -LiteralPath $TestKeyPub -Raw).Trim() -replace '\s+', ' '
$existingLines = ''
if (Test-Path $AuthorizedKeysPath) {
    $existingLines = (Get-Content -LiteralPath $AuthorizedKeysPath -Raw) -replace '\s+', ' '
}
if ($existingLines -notmatch [regex]::Escape($pubkeyLine)) {
    Add-Content -LiteralPath $AuthorizedKeysPath -Value $pubkeyLine
}
# ACL note: Win32-OpenSSH sshd rejects authorized_keys whose DACL
# has any ACE granting access to an SID that isn't the target user,
# Administrators, or SYSTEM — this is the same host-key check that
# step 5b-5c do for ssh_host_ed25519_key. We strip inheritance
# and grant only $User:R + Administrators:F + SYSTEM:F to match.
icacls $AuthorizedKeysPath /inheritance:r /grant:r "${User}:(R)" /grant:r 'BUILTIN\Administrators:(F)' /grant:r 'NT AUTHORITY\SYSTEM:(F)' | Out-Null
Write-Host "pubkey auth: appended $(Split-Path $TestKeyPub -Leaf) to $AuthorizedKeysPath"

# 8. Validate the config syntactically before launching sshd. `sshd -t`
#    parses the file and exits non-zero on any error, printing the
#    offending line to stderr. This is now safe because the upgraded
#    Win32-OpenSSH accepts the canonical host-key ACL we generated in
#    step 5c, so `sshd -t` (running as the runner user) can read the
#    key file as part of its validation pass.
& sshd -t -f $SshdCfg
if ($LASTEXITCODE -ne 0) {
    throw "sshd config validation failed (exit $LASTEXITCODE)"
}

# 8a. Runtime-conditional `srclimit no`: OpenSSH 9.2+ adds a per-source-IP
#     connection-rate penalty that is ON by default. After ~30 back-to-back
#     test runs from 127.0.0.1 the cumulative penalty drops late-run
#     connections mid-handshake with ECONNRESET (os error 10054 on
#     Windows, os error 54 on macOS), causing test_verbose_quiet_flags
#     (and other late-run tests) to flake. The `srclimit` config
#     directive was added in OpenSSH 9.8; the Win32-OpenSSH 10.0p2 binary
#     we install above should support it, but we still probe before
#     appending so a future binary downgrade doesn't break provision.
#
#     Two probe strategies in order, mirroring setup-macos-brew-openssh.sh
#     so the same logic catches the same edge cases across platforms:
#       1. Write `srclimit no` to a scratch config, run `sshd -T -f`,
#          check exit status. sshd -T exits 0 if the config parses,
#          non-zero if it contains a directive this build rejects.
#       2. Run `sshd -T -f $SshdCfg` (no override) and grep the output
#          for a `srclimit` line — some builds advertise the directive
#          at its default value even when probe #1 succeeded because
#          they treat `srclimit no` as a no-op against the same default.
#     We use the upgraded Win32-OpenSSH sshd.exe for both probes (it's
#     what the service runs), not the inbox binary.
$SshdProbeBin = Join-Path $SshdBinDir 'sshd.exe'
if (-not (Test-Path $SshdProbeBin)) {
    # Fall back to whatever `sshd` resolves to in $env:PATH (inbox binary).
    # Worst case: probe below fails, we skip the patch, and the runner
    # falls back to the unpatched default — same as the pre-fix state.
    $SshdProbeBin = 'sshd'
}
$ScratchCfg = Join-Path $env:TEMP ("sshd-srclimit-probe-{0}.cfg" -f ([guid]::NewGuid().ToString('N')))
try {
    Copy-Item -LiteralPath $SshdCfg -Destination $ScratchCfg -Force
    Add-Content -LiteralPath $ScratchCfg -Value 'srclimit no'
    $srclimitSupported = $false
    try {
        & $SshdProbeBin -T -f $ScratchCfg 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $srclimitSupported = $true }
    } catch {
        # sshd rejected the directive; leave $srclimitSupported as $false.
    }
    if (-not $srclimitSupported) {
        $probeOut = & $SshdProbeBin -T -f $SshdCfg 2>&1 | Out-String
        if ($probeOut -match '(?m)^srclimit') { $srclimitSupported = $true }
    }
    if ($srclimitSupported) {
        Write-Host "    sshd supports srclimit directive -- appending 'srclimit no'"
        Add-Content -LiteralPath $SshdCfg -Value 'srclimit no'
    } else {
        Write-Host "    sshd rejects srclimit directive -- keeping 9.2+ default penalty"
    }
} finally {
    Remove-Item -LiteralPath $ScratchCfg -Force -ErrorAction SilentlyContinue
}

# 9. Start sshd as a foreground process via Start-Process, NOT as a
#    Windows service. The PR #14 root-cause dump on 28780534625
#    showed that the Win32-OpenSSH 10.0p2 service wrapper (the
#    sshd.exe shipped as the service entry point) does NOT honour
#    HKLM\SOFTWARE\OpenSSH-Server-Ini\LogFile/LogLevel — the file
#    was never created even though the registry values were set
#    correctly — and that the OpenSSH/Operational Event Log is
#    empty even after a 33-test connection storm. Symptom: port
#    22222 accepts TCP connections but every SSH handshake is RST'd
#    with os error 10054. The service's per-connection sshd-session.exe
#    fork is silently failing.
#
#    Running sshd.exe directly with `-D -E $SshdLog` (foreground
#    daemon mode + explicit log path) bypasses the service wrapper
#    entirely: the parent sshd.exe writes its -ddd trace to
#    $SshdLog, sshd-session.exe forks per-connection under our
#    runner user (not as NT SERVICE\sshd), and connection failures
#    show up in the log instead of being silently swallowed. The
#    process is started with Start-Process -PassThru so the PID
#    is captured for the dump-on-failure path; the GitHub Actions
#    runner's job-object teardown kills it when the integration
#    step ends, so no manual cleanup is required.
#
#    The earlier comment in this step claimed "Start-Process with
#    -D ... does not reliably support" daemon mode; that was
#    wrong. The Windows sshd build supports -D (verified by the
#    Win32-OpenSSH 10.0.0.0p2 release notes: -D is the canonical
#    non-service mode and is what the service wrapper itself
#    internally invokes). The reason that path wasn't taken
#    before is that "Run as a service" matched the OpenSSH
#    capability installer's recommended setup, but the
#    recommendation doesn't apply to a CI-runner sshd whose
#    lifetime is exactly one step.
Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Force the wrapper to also not be holding the port. `sc.exe delete`
# would be too aggressive (it removes the registration entirely);
# `sc.exe config` to manual startup is enough to ensure it doesn't
# auto-restart on our Start-Process.
$svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($null -ne $svc) {
    try { Set-Service -Name sshd -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1

# Confirm no other process is still bound to 22222 — if the service
# had a stuck sshd.exe child, this would block our Start-Process.
$portBusy = $false
try {
    $probe = New-Object System.Net.Sockets.TcpClient
    $probe.Connect($ListenHost, $Port)
    $probe.Close()
    $portBusy = $true
} catch {}
if ($portBusy) {
    # Port still busy: an existing sshd (probably the service's
    # sshd.exe) is bound. Find and stop it. This is rare — Stop-Service
    # + the sleep above is usually enough — but on a flaky runner
    # the service can leave a zombie sshd.exe holding the port.
    Get-Process -Name sshd,sshd-session -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Host "    killing lingering sshd pid=$($_.Id)"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    Start-Sleep -Seconds 2
}

# Wipe any stale log file from a previous run so the dump-on-failure
# path's "is the file present?" check has a clean baseline.
Remove-Item -LiteralPath $SshdLog       -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $SshdDebugLog  -Force -ErrorAction SilentlyContinue

# Start sshd.exe directly. -D = "do not daemonize" (foreground,
# required for our Start-Process model), -E $SshdLog = explicit
# log file (so the service wrapper's failure-to-honour-LogFile
# is moot), -f $SshdCfg = explicit config path. -ddd = full debug3
# trace for the PR #14 root-cause investigation; this is the same
# level the registry override was supposed to produce, but now
# actually delivered because we're not going through the wrapper.
# We do NOT pass -o (override) for the password / forwarding
# directives — those live in the rendered $SshdCfg, and a future
# debug that adds an -o override should be a one-line change.
$sshdProc = $null
$sshdStartupOk = $false
try {
    $sshdProc = Start-Process `
        -FilePath (Join-Path $SshdBinDir 'sshd.exe') `
        -ArgumentList @('-D', '-E', $SshdLog, '-ddd', '-f', $SshdCfg) `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardError "$SshdLog.err" `
        -ErrorAction Stop
    $sshdStartupOk = $true
    Write-Host "    sshd started pid=$($sshdProc.Id) (foreground, log=$SshdLog)"
} catch {
    Write-Host "Start-Process sshd threw: $_"
}
Start-Sleep -Seconds 1

# 10. Wait for port 22222 to accept connections.
if ($sshdStartupOk) {
    $ready = $false
    for ($i = 0; $i -lt 50; $i++) {
        Start-Sleep -Milliseconds 200
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect($ListenHost, $Port)
            $client.Close()
            $ready = $true
            break
        } catch {
            # not ready yet
        }
    }
}

if (-not $sshdStartupOk) {
    Write-Host "Start-Process sshd failed; emitting diagnostic dump:"
} elseif (-not $ready) {
    Write-Host "sshd did not accept connections within 10s; emitting diagnostic dump:"
}

if (-not $sshdStartupOk -or -not $ready) {
    Write-Host "sshd did not accept connections within 10s."

    # Confirm the sshd.exe we tried to launch is the upgraded one.
    Write-Host "sshd.exe on disk reports version:"
    & (Join-Path $SshdBinDir 'sshd.exe') -V 2>&1 | ForEach-Object { Write-Host $_ }

    Write-Host "sshd -t -f ${SshdCfg}:"
    & (Join-Path $SshdBinDir 'sshd.exe') -t -f $SshdCfg 2>&1 | ForEach-Object { Write-Host $_ }

    # The sshd log file is the canonical post-mortem for the foreground
    # mode introduced in PR #14. If it's empty or missing, the sshd
    # binary couldn't even open the port -- check for a stderr file
    # (Start-Process -RedirectStandardError redirected it for us).
    Write-Host "Recent sshd log entries:"
    if (Test-Path $SshdLog) { Get-Content $SshdLog -Tail 100 | Write-Host }
    else { Write-Host "  (no $SshdLog)" }

    if (Test-Path "$SshdLog.err") {
        Write-Host "sshd stderr (from Start-Process -RedirectStandardError):"
        Get-Content "$SshdLog.err" -Tail 50 | Write-Host
    }

    # Bumped from 20 to 500 in PR #14 diagnostic: the OpenSSH/Operational
    # channel is the canonical log on Windows builds where the service
    # wrapper ignores LogFile/LogLevel registry values. Even with the
    # override, Event Log entries are the audit trail the wrapper
    # always emits, so a green run's first 20 events are insufficient
    # to cover a 33-test connection storm.
    Write-Host "Windows Event Log (sshd, last 500):"
    Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 500 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host $_.Message }
    Write-Host "Windows Event Log (System, sshd-related, last 200):"
    Get-WinEvent -LogName System -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'sshd' -or $_.Message -match 'sshd' } |
        ForEach-Object { Write-Host $_.Message }
    Write-Host "Windows Event Log (Application, last 200):"
    Get-WinEvent -LogName Application -MaxEvents 200 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host $_.Message }
    exit 1
}

Write-Host "test sshd ready at ${ListenHost}:${Port} (foreground sshd.exe pid=$($sshdProc.Id), log=$SshdLog)"

# 13. Export PHR_TEST_KEY so the integration-tests step can drive
#     `passhrs -i ${PHR_TEST_KEY}` without needing to know where
#     the key lives. Mirrors setup-linux.sh + setup-macos-brew-
#     openssh.sh so tests/12 + tests/15 auth_args() work identically
#     on every platform. GITHUB_ENV is set by GitHub Actions; the
#     `Add-Content` is a no-op when running the script locally
#     for iteration.
if ($env:GITHUB_ENV) {
    Add-Content -LiteralPath $env:GITHUB_ENV -Value "PHR_TEST_KEY=$TestKey"
    Write-Host "==> Wrote PHR_TEST_KEY=$TestKey to GITHUB_ENV"
} else {
    Write-Host "==> PHR_TEST_KEY=$TestKey (set manually for local iteration)"
}

# 14. Smoke-probe pubkey auth end-to-end so a misconfigured ACL on
#     $AuthorizedKeysPath surfaces here instead of in the integration
#     tests' first `-i` invocation. Uses the inbox ssh.exe if it's
#     on PATH; falls back to skipping the probe (the test will
#     surface the failure with a clearer context).
$SshBin = Join-Path $SshdBinDir 'ssh.exe'
if (-not (Test-Path $SshBin)) { $SshBin = 'ssh' }
Write-Host "==> Smoke-testing ssh pubkey auth..."
try {
    $probeOutput = & $SshBin -i $TestKey -p $Port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 "${User}@${ListenHost}" "echo win_pubkey_ok" 2>&1
    if ($LASTEXITCODE -ne 0 -or ($probeOutput -notmatch 'win_pubkey_ok')) {
        Write-Host "FATAL: ssh pubkey auth probe failed; check authorized_keys ACL + key perms" -ForegroundColor Red
        Write-Host "probe output: $probeOutput"
        if (Test-Path $SshdLog) { Get-Content $SshdLog -Tail 50 | Write-Host }
        exit 1
    }
} catch {
    Write-Host "WARN: pubkey smoke probe could not run (no ssh.exe on PATH?) — continuing. Error: $_"
}
