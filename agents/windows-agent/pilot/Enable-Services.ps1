# Dot-sourced only by the administrator installation/upgrade scripts.
function Enable-DeviceServices([uri]$Api) {
    $Root=Join-Path $env:ProgramData 'CyberShieldDeviceAgent'
    $Install=Join-Path $env:ProgramFiles 'CyberShieldDeviceAgent'
    $ManagementRoot=Join-Path $env:ProgramData 'ServerGuard'
    $ManagementFile=Join-Path $ManagementRoot 'management.json'
    if(-not(Test-Path $ManagementRoot)){
        New-Item -ItemType Directory -Path $ManagementRoot | Out-Null
        Set-Acl -LiteralPath $ManagementRoot -AclObject (Get-Acl -LiteralPath $Root)
    }
    if(-not(Test-Path $ManagementFile)){
        $Protected=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop -Unique)
        @{firewallEnabled=$true;protectedAddresses=$Protected;stopAllowlist=@()} | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath $ManagementFile
    }
    Copy-Item -LiteralPath (Join-Path $Install 'AutoUpdate.ps1') -Destination (Join-Path $Root 'AutoUpdate.ps1') -Force
    $Generation=Join-Path $Install 'release-generation.txt'
    if(Test-Path $Generation){
        $Clock=Join-Path $Root 'update-generation.txt'
        $New=[long](Get-Content -Raw $Generation)
        $Old=if(Test-Path $Clock){[long](Get-Content -Raw $Clock)}else{0}
        if($New -gt $Old){$New | Set-Content -LiteralPath $Clock}
    }
    $PowerShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $Arguments='-NoProfile -NonInteractive -File "{0}" -Api "{1}"' -f (Join-Path $Root 'AutoUpdate.ps1'),$Api.GetLeftPart([UriPartial]::Authority)
    $Action=New-ScheduledTaskAction -Execute $PowerShell -Argument $Arguments
    $Trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 15)
    $Principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $Settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'CyberShieldDeviceAutoUpdate' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
}
