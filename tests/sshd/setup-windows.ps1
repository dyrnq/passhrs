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

# 5b. Lock down the host key's NTFS DACL. The Windows OpenSSH build
#     refuses to load a private key whose DACL grants read access to
#     anyone outside the owner group ("Permissions ... are too open /
#     no hostkeys available -- exiting"). ssh-keygen leaves explicit
#     ACEs for BUILTIN\Users and related principals, AND those survive
#     `icacls /inheritance:r` because /inheritance:r only strips
#     *inherited* ACEs. We therefore both (a) re-take ownership so the
#     re-grant below lands cleanly, and (b) drop inheritance and add
#     only the three SIDs that actually need read access. We then dump
#     the resulting DACL so the next CI failure has the actual ACL on
#     stderr rather than relying on icacls prose.
takeown /F $HostKey /A | Out-Null

# (a) Disable inheritance AND drop inherited ACEs without copying.
# (b) Snapshot explicit rules into an array so the RemoveAccessRule*
#     loop does not mutate during enumeration.
# (c) Re-grant exactly the three SIDs we want. FullControl (F) on the
#     private key is the canonical ACL Microsoft's OpenSSH docs
#     recommend; we follow that instead of Read so the key file is
#     pristine. SYSTEM covers the LocalSystem service context;
#     Administrators covers the runner user (Administrator) that runs
#     the `sshd -t -f` validation step; NT SERVICE\sshd is the explicit
#     service SID so other service contexts cannot read the key.
# (d) Set the OWNER to SYSTEM. OpenSSH on Windows also rejects the
#     key if the owner is a regular user account (e.g. runneradmin);
#     SYSTEM or Administrators are the only accepted owners. We use
#     SYSTEM because the sshd service runs in the LocalSystem context.
$keyAcl = Get-Acl -Path $HostKey
$keyAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($keyAcl.Access)) {
    $keyAcl.RemoveAccessRuleSpecific($rule)
}
$systemSid  = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$adminsSid  = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
$sshdSvcSid = (New-Object System.Security.Principal.NTAccount('NT SERVICE', 'sshd')
    ).Translate([System.Security.Principal.SecurityIdentifier])
foreach ($sid in @($systemSid, $adminsSid, $sshdSvcSid)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sid, 'FullControl', 'Allow')
    $keyAcl.AddAccessRule($rule)
}
$keyAcl.SetOwner($systemSid)
Set-Acl -Path $HostKey -AclObject $keyAcl

# Diagnostic dump: ACL + owner + sshd binary location + sshd version,
# all on stdout so the next CI failure has the full context. icacls
# without /C still emits the canonical DACL; we add a separate owner
# query because icacls /C sometimes collapses it.
Write-Host "After lockdown, icacls ${HostKey}:"
icacls $HostKey | Out-Host
Write-Host "Owner: $((Get-Acl -Path $HostKey).Owner)"
Write-Host "sshd binary: $((Get-Command sshd -ErrorAction SilentlyContinue).Source)"
$sshdVer = & sshd -V 2>&1 | Out-String
Write-Host "sshd -V: $sshdVer"

# 5c. The sshd_config file is not secret — only add the service SID
#     without stripping inheritance (preserves the inherited
#     Administrators ACE the runner user needs to pass `sshd -t`).
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