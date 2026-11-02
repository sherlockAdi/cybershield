# Run by the Windows agent with --management-helper; fixed operations, JSON stdin only.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ConfigPath = Join-Path $env:ProgramData 'ServerGuard\management.json'
function Get-Applications($Config) {
    $Apps = [System.Collections.Generic.List[object]]::new()
    foreach ($Service in Get-CimInstance Win32_Service) {
        $Id = 'service:' + $Service.Name
        $Instance = [string]$Service.ProcessId
        if ($Service.ProcessId -gt 0) {
            try { $Instance += ':' + (Get-Process -Id $Service.ProcessId).StartTime.ToUniversalTime().Ticks } catch { $Instance += ':unknown' }
        }
        $Executable = if ($Service.PathName -match '^"([^"\r\n]+)"') { $Matches[1] } elseif ($Service.PathName -match '^(.+?\.exe)(?:\s|$)') { $Matches[1] } else { 'Not reported' }
        $Detail = "$($Service.DisplayName) | PID $($Service.ProcessId) | Start $($Service.StartMode) | Account $($Service.StartName) | $Executable"
        $Apps.Add(@{ id=$Id; kind='WINDOWS_SERVICE'; name=$Service.Name; state=$Service.State; instance=$Instance; details=$Detail.Substring(0,[Math]::Min(500,$Detail.Length)); stoppable=($Config.stopAllowlist -ccontains $Id) -and $Service.State -eq 'Running' })
    }
    if (Get-Module -ListAvailable WebAdministration) {
        Import-Module WebAdministration
        foreach ($Site in Get-Website) {
            $Id = 'iis-site:' + $Site.Name
            $Detail = "Bindings: $($Site.Bindings.Collection.bindingInformation -join ', ') | Path: $($Site.PhysicalPath) | Pool: $($Site.ApplicationPool)"
            $Apps.Add(@{ id=$Id; kind='IIS_SITE'; name=$Site.Name; state=[string]$Site.State; instance=[string]$Site.Id; details=$Detail.Substring(0,[Math]::Min(500,$Detail.Length)); stoppable=($Config.stopAllowlist -ccontains $Id) -and $Site.State -eq 'Started' })
        }
        foreach ($Pool in Get-ChildItem IIS:\AppPools) {
            $Id = 'iis-pool:' + $Pool.Name
            $Apps.Add(@{ id=$Id; kind='IIS_POOL'; name=$Pool.Name; state=[string]$Pool.State; instance=$Pool.Name; details="Runtime: $($Pool.managedRuntimeVersion) | Pipeline: $($Pool.managedPipelineMode)"; stoppable=($Config.stopAllowlist -ccontains $Id) -and $Pool.State -eq 'Started' })
        }
    }
    return @($Apps | Sort-Object kind,name)
}
function Get-Blocks {
    $Rules = @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Name -match '^CyberShield-[0-9a-f-]{36}$' -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    return @($Rules | ForEach-Object { $_.Description | ConvertFrom-Json })
}
function Invoke-HostRequest($Request) {
    $Config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
    $Firewall = [bool]$Config.firewallEnabled
    if ($Request.operation -eq 'INVENTORY') {
        $Apps = @(Get-Applications $Config)
        $Rules = @()
        $Errors = @()
        if ($Firewall) {
            try {
                if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count -gt 0) { throw 'A firewall profile is disabled' }
                $Rules = @(Get-Blocks)
            } catch { $Firewall = $false; $Errors += 'Windows Firewall is unavailable or a profile is disabled' }
        }
        return @{ applications=@($Apps | Select-Object -First 200); rules=@($Rules | Select-Object -First 200); firewall=$Firewall; errors=$Errors; truncated=($Apps.Count -gt 200 -or $Rules.Count -gt 200) }
    }
    $Guid = [guid]::Parse($Request.id)
    if ([DateTimeOffset]::Parse($Request.expiresAt) -le [DateTimeOffset]::UtcNow) { throw 'Command expired' }
    $Payload = $Request.payload
    switch ($Request.operation) {
        'STOP_APPLICATION' {
            $Target = $Payload.application
            $Current = @(Get-Applications $Config | Where-Object { $_.id -ceq $Target.id -and $_.instance -ceq $Target.instance -and $_.stoppable })
            if ($Current.Count -ne 1) { throw 'Application changed or stopping is not permitted on this host' }
            switch ($Current[0].kind) {
                'WINDOWS_SERVICE' { Get-Service | Where-Object { $_.Name -ceq $Current[0].name } | Stop-Service }
                'IIS_SITE' { $Manager = New-Object Microsoft.Web.Administration.ServerManager; try { ($Manager.Sites | Where-Object { $_.Name -ceq $Current[0].name }).Stop() | Out-Null } finally { $Manager.Dispose() } }
                'IIS_POOL' { $Manager = New-Object Microsoft.Web.Administration.ServerManager; try { ($Manager.ApplicationPools | Where-Object { $_.Name -ceq $Current[0].name }).Stop() | Out-Null } finally { $Manager.Dispose() } }
                default { throw 'Unsupported application type' }
            }
            $After = @(Get-Applications $Config | Where-Object { $_.id -ceq $Target.id -and $_.state -in @('Running','Started') })
            if ($After.Count) { throw 'Application is still running or was restarted' }
        }
        'BLOCK_IP' {
            if (-not $Firewall) { throw 'Firewall management is disabled on this host' }
            if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count -gt 0) { throw 'A firewall profile is disabled' }
            if (@(Get-Blocks).Count -ge 200) { throw 'Managed block limit reached' }
            $Address = [System.Net.IPAddress]::Parse($Payload.ip)
            if ($Address.IsIPv4MappedToIPv6) { $Address = $Address.MapToIPv4() }
            if ([System.Net.IPAddress]::IsLoopback($Address) -or $Address.ToString() -in @('0.0.0.0','::') -or $Address.IsIPv6Multicast -or ($Address.AddressFamily -eq 'InterNetwork' -and $Address.GetAddressBytes()[0] -ge 224)) { throw 'Address cannot be blocked' }
            foreach ($Protected in $Config.protectedAddresses) { if ($Address.Equals([System.Net.IPAddress]::Parse($Protected))) { throw 'Address is protected by the host administrator' } }
            if ($Payload.scope -notin @('LOGIN','TCP') -or @($Payload.ports).Count -gt 16 -or ($Payload.scope -eq 'LOGIN' -and @($Payload.ports).Count -eq 0)) { throw 'Invalid scope or ports' }
            foreach ($Port in $Payload.ports) { if ($Port -isnot [long] -and $Port -isnot [int]) { throw 'Invalid port' }; if ($Port -lt 1 -or $Port -gt 65535) { throw 'Invalid port' } }
            $RuleName = 'CyberShield-' + [guid]::Parse($Payload.id).ToString()
            $Ports = if (@($Payload.ports).Count) { @($Payload.ports | ForEach-Object { [string]$_ }) } else { @('Any') }
            New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Group 'CyberShield managed IP blocks' -Description ($Payload | ConvertTo-Json -Compress) -PolicyStore PersistentStore -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol TCP -RemoteAddress $Address.ToString() -LocalPort $Ports | Out-Null
            if (-not (Get-NetFirewallRule -PolicyStore ActiveStore -Name $RuleName -ErrorAction Stop)) { throw 'Rule is not effective in ActiveStore' }
        }
        'UNBLOCK_IP' {
            if (-not $Firewall) { throw 'Firewall management is disabled on this host' }
            $RuleName = 'CyberShield-' + [guid]::Parse($Payload.id).ToString()
            Get-NetFirewallRule -PolicyStore PersistentStore -Name $RuleName | Remove-NetFirewallRule
            if (Get-NetFirewallRule -PolicyStore ActiveStore -Name $RuleName -ErrorAction SilentlyContinue) { throw 'Rule is still effective' }
        }
        default { throw 'Unsupported operation' }
    }
    return @{ id=$Request.id; success=$true; message='Host action completed and verified' }
}
$Request = $null
try {
    $InputJson = [Console]::In.ReadToEnd()
    if ($InputJson.Length -gt 16384) { throw 'Request exceeds limit' }
    $Request = $InputJson | ConvertFrom-Json
    Invoke-HostRequest $Request | ConvertTo-Json -Depth 12 -Compress
} catch {
    if ($Request.id) { @{ id=$Request.id; success=$false; message='Host action failed; inspect host configuration, permissions and target state' } | ConvertTo-Json -Compress }
    else { @{ applications=@(); rules=@(); firewall=$false; errors=@('Management inventory unavailable; inspect host configuration and permissions'); truncated=$false } | ConvertTo-Json -Compress }
}
