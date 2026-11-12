#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][uri]$Api,
    [Parameter(Mandatory=$true)][guid]$DeviceId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Api.Scheme -ne 'https' -or $Api.UserInfo -or $Api.Query -or $Api.Fragment -or $Api.AbsolutePath -ne '/') { throw 'Api must be an HTTPS origin without path, credentials, query or fragment.' }
$ServiceName = 'ServerGuardAgent'
$Destination = Join-Path $env:ProgramFiles 'CyberShieldDeviceAgent'
$State = Join-Path $env:ProgramData 'CyberShieldDeviceAgent'
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw 'Agent service already exists. Use documented renewal/upgrade procedure; do not overwrite its identity.' }
if ((Test-Path -LiteralPath $Destination) -or (Test-Path -LiteralPath $State)) { throw 'Installation/state directory already exists. Inspect the previous installation before retrying.' }
foreach ($File in @('ServerGuard.Agent.exe','Audit-Device.ps1')) {
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $File) -PathType Leaf)) { throw "Missing package file: $File" }
}
# Reject links before copying the self-contained publish package.
foreach ($Item in Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -Force) {
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package must not contain links.' }
}
foreach ($Directory in @($Destination,$State)) {
    New-Item -ItemType Directory -Path $Directory | Out-Null
    $Acl = New-Object Security.AccessControl.DirectorySecurity
    $Acl.SetAccessRuleProtection($true,$false)
    foreach ($Sid in @('S-1-5-18','S-1-5-32-544')) {
        $Identity = New-Object Security.Principal.SecurityIdentifier($Sid)
        $Rule = New-Object Security.AccessControl.FileSystemAccessRule($Identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $Acl.AddAccessRule($Rule)
    }
    Set-Acl -LiteralPath $Directory -AclObject $Acl
}
Get-ChildItem -LiteralPath $PSScriptRoot -Force | Where-Object { $_.Name -ne 'Install-Service.ps1' } | Copy-Item -Destination $Destination -Recurse
$TokenFile = Join-Path $State 'enrollment.token'
$Secret = Read-Host 'One-time enrollment token' -AsSecureString
$Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
try {
    $Plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer)
    if ($Plain -notmatch '^[A-Za-z0-9_-]{32,100}$') { throw 'Invalid enrollment token format' }
    [IO.File]::WriteAllText($TokenFile,$Plain,(New-Object Text.UTF8Encoding($false)))
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
    $Plain = $null
    $Secret.Dispose()
}
$Exe = Join-Path $Destination 'ServerGuard.Agent.exe'
$Audit = Join-Path $Destination 'Audit-Device.ps1'
$Arguments = '"{0}" --api "{1}" --server-id "{2}" --state-dir "{3}" --token-file "{4}" --device-audit-helper "{5}"' -f $Exe,$Api.GetLeftPart([UriPartial]::Authority),$DeviceId.ToString('D'),$State,$TokenFile,$Audit
# SCM starts enrollment under LocalSystem; never enroll as the interactive user.
New-Service -Name $ServiceName -BinaryPathName $Arguments -DisplayName 'CyberShield Device Agent' -StartupType Automatic -Description 'Signed CyberShield device enrollment, heartbeat and read-only security audit.' | Out-Null
Start-Service -Name $ServiceName
Write-Host 'Service started. Verify ONLINE in Device Management; Running alone does not prove enrollment.'
Write-Host 'After ONLINE, remove the enrollment.token file from the protected state directory.'
Write-Host 'No USB, account, firewall or disk-encryption policies were changed.'
