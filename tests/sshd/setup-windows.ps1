# Provision a real OpenSSH server on 127.0.0.1:22222 on a Windows runner.
#
# Targets GitHub-hosted windows-2022 runners. The OpenSSH server is
# installed as a Windows capability; we then create a local testuser,
# write a minimal sshd_config, and start the sshd service.
#
# Note: Windows Local Security Policy may reject the test password
# `testpass` for not meeting complexity. We use secedit to relax
# `PasswordComplexity` during user creation, then restore it.
[CmdletBinding()]
param(
    [string]$User = 'testuser',
    [string]$Pass = 'testpass',
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
#    Windows sftp-server path. Windows OpenSSH ignores UsePAM (unknown
#    directive); leaving it in is harmless because the server only warns.
(Get-Content $SshdConfigTemplate -Raw) `
    -replace '__SFTP_SERVER_PATH__', ($SftpServer -replace '\\', '\\') `
    | Set-Content -Path $SshdCfg -Encoding ASCII

# 5. Generate host key if missing.
if (-not (Test-Path $HostKey)) {
    & ssh-keygen -t ed25519 -f $HostKey -N '""' -q
}

# 6. Create testuser with a known password. The Windows password
#    complexity policy rejects "testpass" by default, so we write a
#    minimal INF that explicitly disables both complexity and length
#    requirements, apply it via secedit, then restore the original
#    policy in the finally block. Using a from-scratch INF (rather
#    than mutating an exported one) is more robust across different
#    Windows builds whose exported INF layouts differ.
$exportDir = Join-Path $env:TEMP 'passhrs-test-sshd'
New-Item -ItemType Directory -Force -Path $exportDir | Out-Null
$secDb = Join-Path $exportDir 'secedit.sdb'

# Snapshot the live policy so we can restore it later.
& secedit /export /db $secDb /cfg (Join-Path $exportDir 'baseline.inf') /quiet | Out-Null

# Minimal relaxed-policy INF. The [Unicode] and [Version] sections
# are required by secedit; Unicode=yes enables UTF-16 output.
$relaxInfPath = Join-Path $exportDir 'relax.inf'
@"
[Unicode]
Unicode=yes

[System Access]
PasswordComplexity = 0
MinimumPasswordLength = 0
PasswordHistorySize = 0
ClearTextPassword = 0
"@ | Set-Content -Path $relaxInfPath -Encoding Unicode

try {
    & secedit /configure /db $secDb /cfg $relaxInfPath /quiet | Out-Null

    if (-not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
        $secure = ConvertTo-SecureString $Pass -AsPlainText -Force
        New-LocalUser -Name $User -Password $secure `
            -Description 'Passhrs e2e test user' `
            -PasswordNeverExpires `
            -UserMayNotChangePassword | Out-Null
    }
    # Always reset the password so re-runs are deterministic.
    & net user $User $Pass | Out-Null
}
finally {
    # Restore the original policy.
    $baselineInf = Join-Path $exportDir 'baseline.inf'
    if (Test-Path $baselineInf) {
        & secedit /configure /db $secDb /cfg $baselineInf /quiet | Out-Null
    }
}

# 7. Allow testuser to authenticate via sshd: add to the SSH users group
#    that Windows OpenSSH honours by default (Administrators + the
#    account's own ACL on the profile directory are also accepted).
$group = 'OpenSSH Users'
if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
    New-LocalGroup -Name $group | Out-Null
}
Add-LocalGroupMember -Group $group -Member $User -ErrorAction SilentlyContinue

# 8. Stop any existing sshd, then start with our config.
$svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($null -ne $svc) {
    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    # Point sshd at our config via the service's command-line override
    # is not exposed, so we run a foreground sshd bound to the port and
    # disable the service to free port 22222 for the test process.
    Set-Service -Name sshd -StartupType Disabled
}

# 9. Launch sshd in the background. We use the sshd binary directly so
#    we can pass -p 22222 and our -f config without touching the service
#    configuration file the Windows installer expects.
$sshdExe = (Get-Command sshd.exe -ErrorAction Stop).Source
$proc = Start-Process -FilePath $sshdExe `
    -ArgumentList @('-f', $SshdCfg, '-h', $HostKey, '-E', $SshdLog, '-p', $Port, '-D') `
    -PassThru -WindowStyle Hidden

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
    Write-Error "sshd did not start within 10s. Log:"
    if (Test-Path $SshdLog) { Get-Content $SshdLog -Tail 50 }
    exit 1
}

Write-Host "test sshd ready at ${ListenHost}:${Port} (pid=$($proc.Id))"