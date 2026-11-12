#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true)]
param()
$ErrorActionPreference = 'Stop'
$Service = Get-CimInstance Win32_Service -Filter "Name='ServerGuardAgent'"
$Expected = '"' + (Join-Path $env:ProgramFiles 'CyberShieldDeviceAgent\ServerGuard.Agent.exe') + '" '
if (-not $Service) { throw 'Device service not found.' }
if (-not $Service.PathName.StartsWith($Expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Existing service is not the device package; refusing to remove it.' }
if ($PSCmdlet.ShouldProcess('ServerGuardAgent','Stop and remove Windows service')) {
    Stop-ScheduledTask -TaskName CyberShieldDeviceAutoUpdate -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName CyberShieldDeviceAutoUpdate -Confirm:$false -ErrorAction SilentlyContinue
    Stop-Service -Name ServerGuardAgent -ErrorAction Stop
    & "$env:SystemRoot\System32\sc.exe" delete ServerGuardAgent | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SCM service deletion failed.' }
    Write-Host 'Service removed. Revoke its credentials in the admin panel.'
    Write-Host 'Protected state and application files retained for administrator review; no policies were changed.'
}
