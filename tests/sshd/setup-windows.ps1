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
    [string]$SshdConfigTemplate = "$PSScriptRoot\sshd_config"
)
$ErrorActionPreference = 'Stop'

$ListenHost = '127.0.0.1'
$ProgData   = $env:ProgramData
$SshRoot    = Join-Path $ProgData 'ssh'
$SshdCfg    = Join-Path $SshRoot 'sshd_config'
$HostKey    = Join-Path $SshRoot 'ssh_host_ed25519_key'
$SftpServer = Join-Path $env:SystemRoot 'System32\OpenSSH\sftp-server.exe'
$SshdLog    = Join-Path $SshRoot 'logs\sshd.log'

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
$dirAcl = Get-Acl -Path $SshRoot
$dirAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($dirAcl.Access)) {
    $dirAcl.RemoveAccessRuleSpecific($rule)
}
$systemSid = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$adminsSid = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
foreach ($sid in @($systemSid, $adminsSid)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $dirAcl.AddAccessRule($rule)
}
$dirAcl.SetOwner($systemSid)
Set-Acl -Path $SshRoot -AclObject $dirAcl

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

# 8a. Runtime-conditional `PerSourcePenalties no`: OpenSSH 9.8+ adds a
#     per-source-IP connection-rate penalty. The default changed
#     between 9.8 (OFF) and 10.0 (ON); see
#     https://github.com/openssh/openssh-portable/blob/V_10_0/servconf.c
#     `fill_default_server_options`: if enabled stays -1 it gets
#     bumped to 1. After ~30 back-to-back test runs from 127.0.0.1
#     the cumulative penalty drops late-run connections mid-handshake
#     with ECONNRESET (os error 10054 on Windows, os error 54 on
#     macOS), causing test_verbose_quiet_flags (and other late-run
#     tests) to flake.
#
#     IMPORTANT: the directive name is `PerSourcePenalties` (not
#     `srclimit` as the earlier comment claimed). OpenSSH has used
#     `persourcepenalties` since the feature was introduced in 9.8 —
#     the `srclimit` keyword never existed. Confirmed by reading
#     openssh-portable/servconf.c keyword table for V_9_8 / V_10_0 /
#     V_10_3p1: only `persourcepenalties` and `persourcepenaltyexemptlist`
#     are registered. Writing `srclimit no` is treated as an unknown
#     directive; sshd fatals at parse time on strict builds or silently
#     ignores it on lenient ones — either way, the per-source penalty
#     stays ON because nothing disables it.
#
#     Probe strategy (revised after PR #14 windows-2022 failure): the
#     earlier single-probe approach (write `PerSourcePenalties no` to a
#     scratch config and grep sshd -T -f output for
#     `^persourcepenalties no\b`) has a false-positive bug on binaries
#     whose dump function emits `persourcepenalties no` for the
#     default-OFF state. Upstream OpenSSH 9.8's
#     `dump_config_func` emits that exact line whenever
#     `per_source_penalty.enabled == 0`, which is BOTH the default
#     state (no directive set) AND the state after an explicit
#     `PerSourcePenalties no`. The probe cannot distinguish the two
#     cases, so it always matched and always appended. Appending
#     `PerSourcePenalties no` to sshd_config on Win32-OpenSSH 10.0p2
#     broke every test connection with os error 10054 (PR #14);
#     PR #13 had no append and was green.
#
#     Corrected probe: run `sshd -T -f $SshdCfg` against the BASELINE
#     config (no override directive) and inspect the default dump
#     output.
#       - OpenSSH 10.0+ dump emits a long stats line beginning with
#         `persourcepenalties crash:` when enabled=1 (default ON).
#       - OpenSSH 9.8 dump emits `persourcepenalties no` when
#         enabled=0 (default OFF).
#     We only append `PerSourcePenalties no` when we observe the
#     default-ON line — i.e. when we genuinely need to override.
#     When the default already says `persourcepenalties no`, the
#     directive is a no-op and writing it triggered the Win32-OpenSSH
#     10.0p2 regression we just saw. We use the upgraded Win32-OpenSSH
#     sshd.exe for the probe (it's what the service runs), not the
#     inbox binary.
$SshdProbeBin = Join-Path $SshdBinDir 'sshd.exe'
if (-not (Test-Path $SshdProbeBin)) {
    # Fall back to whatever `sshd` resolves to in $env:PATH (inbox
    # binary). Worst case: probe below fails, we skip the patch, and
    # the runner falls back to the unpatched default — same as the
    # pre-fix state.
    $SshdProbeBin = 'sshd'
}
$defaultProbeOut = ''
$defaultProbeRc = 1
try {
    $defaultProbeOut = & $SshdProbeBin -T -f $SshdCfg 2>&1 | Out-String
    $defaultProbeRc = $LASTEXITCODE
} catch {
    # Probe failed entirely; leave the directive alone (same as the
    # pre-fix state). Better to keep the working config than to add
    # a directive we cannot verify.
}
if ($defaultProbeRc -eq 0 -and $defaultProbeOut -match '(?m)^persourcepenalties\s+crash:') {
    # Default-ON binary (OpenSSH 10.0+ dump format, observed on
    # Win32-OpenSSH 10.0p2 which the upgrade step installs above).
    # The directive parses and the override validates (sshd -T -f
    # flips the dump output to `persourcepenalties no` and drops the
    # `crash:` line), but writing `PerSourcePenalties no` to the
    # REAL sshd_config causes every test connection to fail with os
    # error 10054 (Winsock ECONNRESET) on the windows-2022 runner.
    # Observed end-to-end on PR #14 commit 63a2a82: the directive
    # correctly disabled the penalty in -T dump but broke the
    # daemon-mode connection path. We do NOT know whether this is a
    # Win32-OpenSSH 10.0p2 bug or a known limitation of the directive
    # on this binary, but PR #13 (no append) was green on the same
    # runner so we follow the same conservative approach here.
    # MaxStartups 50:100:200 already gives the test suite plenty of
    # headroom for the 30+ back-to-back connections from 127.0.0.1.
    Write-Host "    sshd default is ON (PerSourcePenalties active) -- NOT appending 'PerSourcePenalties no' to avoid Win32-OpenSSH 10.0p2 ECONNRESET regression (PR #14 commit 63a2a82); MaxStartups should cover"
} elseif ($defaultProbeRc -eq 0 -and $defaultProbeOut -match '(?m)^persourcepenalties[ \t]+no\b') {
    # Default-OFF binary (OpenSSH 9.8 dump format). The directive is
    # a no-op; do NOT append. This is the case PR #13's setup
    # effectively landed in (Win32-OpenSSH 10.0p2's default state
    # matches 9.8's `enabled = 0` default), and PR #13 was green on
    # windows-2022.
    Write-Host "    sshd default is OFF ('persourcepenalties no') -- no override needed"
} else {
    # Either sshd rejected `sshd -T -f` on our config (unlikely after
    # the `sshd -t` validation in step 8), or its dump output does
    # not mention `persourcepenalties` at all (binary predates the
    # feature; pre-9.8). Skip the patch -- same as the pre-fix state.
    Write-Host "    sshd dump output has no persourcepenalties line -- pre-9.8 binary or probe failed, keeping default"
}

# 9. Start sshd via the Windows service that the OpenSSH capability
#    installs. The service reads $SshdCfg by default (this is where the
#    installer expects it). Starting via the service avoids the
#    process-lifecycle quirks of `Start-Process` with -D (the daemon
#    mode the Windows sshd build does not reliably support).
$svc = Get-Service -Name sshd -ErrorAction Stop
Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Set-Service -Name sshd -StartupType Manual
# Start-Service under `$ErrorActionPreference = 'Stop'` raises a
# terminating error on failure, which would otherwise exit the script
# before the readiness / diagnostic paths below fire. Wrap explicitly
# to capture success/failure and emit the dump on failure.
$sshdStartupOk = $false
try {
    Start-Service -Name sshd -ErrorAction Stop
    $sshdStartupOk = $true
} catch {
    # Use Write-Host (not Write-Error) because $ErrorActionPreference =
    # 'Stop' elsewhere turns Write-Error into a terminating error,
    # which would re-exit the script before the diagnostic dump runs.
    Write-Host "Start-Service sshd threw: $_"
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
    Write-Host "Start-Service sshd failed; emitting diagnostic dump:"
} elseif (-not $ready) {
    Write-Host "sshd did not accept connections within 10s; emitting diagnostic dump:"
}

if (-not $sshdStartupOk -or -not $ready) {
    Write-Host "sshd did not accept connections within 10s."
    Write-Host "Service status:"
    Get-Service -Name sshd | Format-List | Out-String | Write-Host

    # Confirm the service really points to our upgraded binary. After
    # overwriting inbox binaries in-place the path stays the same, but
    # surface it so we know which sshd.exe was attempted.
    $svcPath = (Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue).PathName
    Write-Host "Service BinaryPathName: $svcPath"

    Write-Host "sc.exe qc sshd:"
    sc.exe qc sshd 2>&1 | ForEach-Object { Write-Host $_ }

    Write-Host "sshd.exe on disk reports version:"
    & (Join-Path $SshdBinDir 'sshd.exe') -V 2>&1 | ForEach-Object { Write-Host $_ }

    Write-Host "sshd -t -f ${SshdCfg}:"
    & sshd -t -f $SshdCfg 2>&1 | ForEach-Object { Write-Host $_ }

    Write-Host "sshd -ddd (debug):"
    & sshd -ddd 2>&1 | Out-String | Write-Host

    Write-Host "Recent sshd log entries:"
    if (Test-Path $SshdLog) { Get-Content $SshdLog -Tail 50 | Write-Host }

    Write-Host "Windows Event Log (sshd):"
    Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 20 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host $_.Message }
    Write-Host "Windows Event Log (System, sshd-related):"
    Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'sshd' -or $_.Message -match 'sshd' } |
        ForEach-Object { Write-Host $_.Message }
    Write-Host "Windows Event Log (Application, last 20):"
    Get-WinEvent -LogName Application -MaxEvents 20 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host $_.Message }
    exit 1
}

Write-Host "test sshd ready at ${ListenHost}:${Port} (service: sshd)"