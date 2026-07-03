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

# 1. Install OpenSSH Server capability if missing.
$sshdFeature = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction SilentlyContinue
if ($null -eq $sshdFeature -or $sshdFeature.State -ne 'Installed') {
    Write-Host 'Installing OpenSSH.Server capability...'
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
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

# 5. Generate host key if missing. -N '' passes an empty passphrase;
#    PowerShell's '""' would be the literal two-character string "".
if (-not (Test-Path $HostKey)) {
    & ssh-keygen -t ed25519 -f $HostKey -N '' -q
}

# 5b. Lock down the host key's NTFS DACL. ssh-keygen writes explicit
#     ACEs for BUILTIN\Users and Other; OpenSSH's portable source
#     treats any such permissive ACE as "too open" and refuses to
#     load the key ("Permissions ... are too open / no hostkeys
#     available -- exiting"). icacls /inheritance:r is not enough
#     because it only strips *inherited* ACEs — explicit ones written
#     by ssh-keygen survive. Use Set-Acl to assemble a clean DACL
#     from scratch with only the three SIDs that need read access:
#       SYSTEM                  — LocalSystem service context reading
#                                 the key when sshd starts
#       Administrators          — runner user (members of Administrators
#                                 group) running `sshd -t -f` for
#                                 config validation
#       NT SERVICE\sshd         — explicit service SID
# 5c. The sshd_config file is not secret, so only add the service SID
#     without stripping inheritance — preserving the inherited
#     Administrators ACE the runner user needs to pass `sshd -t`.
$keyAcl = Get-Acl -Path $HostKey
# SetAccessRuleProtection(true, false): block inheritance AND drop
# inherited ACEs without copying them to explicit rules. The explicit
# rules (including the troublesome BUILTIN\Users) that we just
# removed from will be re-added below.
$keyAcl.SetAccessRuleProtection($true, $false)
# Wipe whatever explicit rules ssh-keygen left behind.
$keyAcl.Access | ForEach-Object { $keyAcl.RemoveAccessRuleSpecific($_) }
$systemSid  = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$adminsSid  = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
$sshdSvcSid = (New-Object System.Security.Principal.NTAccount('NT SERVICE', 'sshd')
    ).Translate([System.Security.Principal.SecurityIdentifier])
foreach ($sid in @($systemSid, $adminsSid, $sshdSvcSid)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sid, 'Read', 'Allow')
    $keyAcl.AddAccessRule($rule)
}
Set-Acl -Path $HostKey -AclObject $keyAcl

icacls $SshdCfg /grant 'NT SERVICE\sshd:(R)' | Out-Null
icacls $SshRoot /grant 'NT SERVICE\sshd:(RX)' | Out-Null

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
#    offending line to stderr.
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
    Write-Error "Recent sshd log entries:"
    if (Test-Path $SshdLog) { Get-Content $SshdLog -Tail 50 | Write-Error }
    Write-Error "Windows Event Log (sshd):"
    Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 20 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Error $_.Message }
    Write-Error "Windows Event Log (System, sshd-related):"
    Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'sshd' -or $_.Message -match 'sshd' } |
        ForEach-Object { Write-Error $_.Message }
    exit 1
}

Write-Host "test sshd ready at ${ListenHost}:${Port} (service: sshd)"