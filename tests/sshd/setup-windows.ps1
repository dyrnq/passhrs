# Provision a real OpenSSH server on 127.0.0.1:22222 on a Windows runner.
#
# Targets GitHub-hosted windows-2022 runners. The OpenSSH server is
# installed as a Windows capability; we then create a local testuser,
# write a minimal sshd_config, and start the sshd service.
#
# Note: the default password 'PassTest1234#' already meets Windows
# password complexity (upper + lower + digit + special, 13 chars),
# so no Local Security Policy tweak is required.
[CmdletBinding()]
param(
    [string]$User = 'testuser',
    # PassTest1234# satisfies Windows password complexity (upper + lower
    # + digit + special, 13 chars). Same value used by every platform
    # setup script and the e2e tests so the test sshd authenticates
    # passhrs consistently across Linux, macOS and Windows runners.
    [string]$Pass = 'PassTest1234#',
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

# The inbox OpenSSH binaries live under %SystemRoot%\System32\OpenSSH
# and are protected: they default to owner=TrustedInstaller with a
# restricted DACL, so Administrator cannot overwrite them even when
# the sshd service is stopped. Re-acquire ownership and grant
# Administrators FullControl on each target before overwriting, which
# is sufficient to defeat Windows Resource Protection for files we
# ourselves will replace.
$InboxBinaries = @('sshd.exe','ssh.exe','ssh-keygen.exe','sftp-server.exe','scp.exe','sftp.exe')
foreach ($name in $InboxBinaries) {
    $dst = Join-Path $SshdBinDir $name
    if (-not (Test-Path $dst)) {
        continue
    }
    takeown /F $dst /A | Out-Null
    icacls $dst /grant 'Administrators:(F)' | Out-Null
}

foreach ($name in $InboxBinaries) {
    $src = Join-Path $ExtractedDir $name
    $dst = Join-Path $SshdBinDir $name
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force
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

# 6. Create testuser with a known password. The default $Pass value
#    ('PassTest1234#') already satisfies Windows password complexity
#    (upper + lower + digit + special, 13 chars), so no policy tweak
#    is required.
if (-not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
    $secure = ConvertTo-SecureString $Pass -AsPlainText -Force
    New-LocalUser -Name $User -Password $secure `
        -Description 'Passhrs e2e test user' `
        -PasswordNeverExpires `
        -UserMayNotChangePassword | Out-Null
}
# Always reset the password so re-runs are deterministic.
& net user $User $Pass | Out-Null

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

# 9. Start sshd via the Windows service that the OpenSSH capability
#    installs. The service reads $SshdCfg by default (this is where the
#    installer expects it). Starting via the service avoids the
#    process-lifecycle quirks of `Start-Process` with -D (the daemon
#    mode the Windows sshd build does not reliably support).
$svc = Get-Service -Name sshd -ErrorAction Stop
Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Set-Service -Name sshd -StartupType Manual
Start-Service -Name sshd
Start-Sleep -Seconds 1

# 10. Wait for port 22222 to accept connections.
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

if (-not $ready) {
    Write-Error "sshd did not accept connections within 10s."
    Write-Error "Service status:"
    Get-Service -Name sshd | Format-List | Out-String | Write-Error

    # Confirm the service really points to our upgraded binary. After
    # overwriting inbox binaries in-place the path stays the same, but
    # surface it so we know which sshd.exe was attempted.
    $svcPath = (Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue).PathName
    Write-Error "Service BinaryPathName: $svcPath"

    Write-Error "sc.exe qc sshd:"
    sc.exe qc sshd 2>&1 | ForEach-Object { Write-Error $_ }

    Write-Error "sshd.exe on disk reports version:"
    & (Join-Path $SshdBinDir 'sshd.exe') -V 2>&1 | ForEach-Object { Write-Error $_ }

    Write-Error "sshd -t -f $SshdCfg:"
    & sshd -t -f $SshdCfg 2>&1 | ForEach-Object { Write-Error $_ }

    Write-Error "sshd -ddd (debug):"
    & sshd -ddd 2>&1 | Out-String | Write-Error

    Write-Error "Recent sshd log entries:"
    if (Test-Path $SshdLog) { Get-Content $SshdLog -Tail 50 | Write-Error }

    Write-Error "Windows Event Log (sshd):"
    Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 20 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Error $_.Message }
    Write-Error "Windows Event Log (System, sshd-related):"
    Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'sshd' -or $_.Message -match 'sshd' } |
        ForEach-Object { Write-Error $_.Message }
    Write-Error "Windows Event Log (Application, last 20):"
    Get-WinEvent -LogName Application -MaxEvents 20 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Error $_.Message }
    exit 1
}

Write-Host "test sshd ready at ${ListenHost}:${Port} (service: sshd)"