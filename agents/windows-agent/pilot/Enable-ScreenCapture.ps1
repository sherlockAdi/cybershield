#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([string]$User=[Security.Principal.WindowsIdentity]::GetCurrent().Name)
$ErrorActionPreference='Stop'
$Sid=([Security.Principal.NTAccount]::new($User)).Translate([Security.Principal.SecurityIdentifier])
$Root=Join-Path $env:ProgramData 'CyberShieldScreenCapture'
if(Test-Path $Root){throw 'Screen helper already provisioned. Do not change its user without administrator review.'}
$Source=Join-Path $PSScriptRoot 'Start-ScreenSharing.ps1'
if(-not(Test-Path $Source)){throw 'Run this from the extracted agent package'}
New-Item -ItemType Directory -Path $Root | Out-Null
$Acl=[Security.AccessControl.DirectorySecurity]::new();$Acl.SetAccessRuleProtection($true,$false);$Acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
foreach($Identity in @('S-1-5-18','S-1-5-32-544')){$Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($Identity),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
$Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Sid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath $Root -AclObject $Acl
Copy-Item -LiteralPath $Source -Destination (Join-Path $Root 'Start-ScreenSharing.ps1')
$ScriptAcl=Get-Acl (Join-Path $Root 'Start-ScreenSharing.ps1');$ScriptAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));Set-Acl (Join-Path $Root 'Start-ScreenSharing.ps1') $ScriptAcl
$Frames=Join-Path $Root 'frames';New-Item -ItemType Directory -Path $Frames | Out-Null
$FramesAcl=Get-Acl $Frames
$FramesAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Sid,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl $Frames $FramesAcl
Write-Host "Consent helper provisioned for $User. It does not start capture."
Write-Host "As that logged-in user, run: powershell.exe -NoProfile -File `"$Root\Start-ScreenSharing.ps1`""
