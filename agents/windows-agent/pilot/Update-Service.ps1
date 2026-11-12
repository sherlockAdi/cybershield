#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory=$true)][uri]$Api)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($Api.Scheme -ne 'https' -or $Api.AbsolutePath -ne '/' -or $Api.UserInfo -or $Api.Query -or $Api.Fragment){throw 'HTTPS origin required'}
$Install=Join-Path $env:ProgramFiles 'CyberShieldDeviceAgent'
$Root=Join-Path $env:ProgramData 'CyberShieldDeviceAgent'
$Service=Get-CimInstance Win32_Service -Filter "Name='ServerGuardAgent'"
$Exe=Join-Path $Install 'ServerGuard.Agent.exe'
if(-not $Service -or -not $Service.PathName.StartsWith(('"'+$Exe+'" '),[StringComparison]::OrdinalIgnoreCase) -or $Service.StartName -ne 'LocalSystem'){throw 'Expected existing LocalSystem device service'}
$Saved=Get-Content -Raw -LiteralPath (Join-Path $Root 'state.json') | ConvertFrom-Json
if($Saved.ApiOrigin -cne $Api.GetLeftPart([UriPartial]::Authority)){throw 'API origin differs from enrolled identity'}
foreach($File in @('ServerGuard.Agent.exe','Audit-Device.ps1','Device-Policy.ps1','AutoUpdate.ps1','Enable-Services.ps1','windows.ps1')){if(-not(Test-Path (Join-Path $PSScriptRoot $File) -PathType Leaf)){throw "Missing package file: $File"}}
if($PSScriptRoot -eq $Install){throw 'Run from the extracted new package, not the live installation'}
foreach($Item in Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -Force){if($Item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Package contains links'}}
$Backup=$Install+'.manual-backup'
if(Test-Path $Backup){throw 'Previous manual backup exists; inspect it before retrying'}
$OldPath=$Service.PathName
Stop-Service ServerGuardAgent
(Get-Service ServerGuardAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
Move-Item -LiteralPath $Install -Destination $Backup
try{
    New-Item -ItemType Directory -Path $Install | Out-Null
    Set-Acl -LiteralPath $Install -AclObject (Get-Acl -LiteralPath $Root)
    Get-ChildItem -LiteralPath $PSScriptRoot -Force | Copy-Item -Destination $Install -Recurse
    . (Join-Path $Install 'Enable-Services.ps1')
    Enable-DeviceServices $Api
    $Args='"{0}" --api "{1}" --server-id "{2}" --state-dir "{3}" --device-audit-helper "{4}" --device-policy-helper "{5}" --management-helper "{6}"' -f $Exe,$Saved.ApiOrigin,$Saved.ServerId,$Root,(Join-Path $Install 'Audit-Device.ps1'),(Join-Path $Install 'Device-Policy.ps1'),(Join-Path $Install 'windows.ps1')
    $Result=Invoke-CimMethod -InputObject $Service -MethodName Change -Arguments @{PathName=$Args}
    if($Result.ReturnValue -ne 0){throw 'Service configuration update failed'}
    Start-Service ServerGuardAgent
    Write-Host 'Agent upgraded using the SAME identity/state. Confirm ONLINE and new version in Device Management.'
    Write-Host 'Signed automatic update checks run every 15 minutes. Old binaries retained in .manual-backup.'
}catch{
    Stop-Service ServerGuardAgent -ErrorAction SilentlyContinue
    if(Test-Path $Install){Remove-Item -LiteralPath $Install -Recurse -Force}
    Move-Item -LiteralPath $Backup -Destination $Install
    Invoke-CimMethod -InputObject $Service -MethodName Change -Arguments @{PathName=$OldPath} | Out-Null
    Start-Service ServerGuardAgent
    throw
}
