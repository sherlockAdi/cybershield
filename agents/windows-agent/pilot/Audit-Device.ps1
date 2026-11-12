#requires -Version 5.1
#requires -RunAsAdministrator
<# Read-only pilot assessment. Emits JSON to stdout; does not change policies,
   install software, collect recovery keys, or upload the report. #>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Read-Section {
    param([scriptblock]$Collect)
    try {
        return @{ status = 'OBSERVED'; data = @(& $Collect); error = $null }
    } catch {
        # Missing cmdlets, unavailable providers and denied access are NOT passes.
        return @{ status = 'UNKNOWN'; data = @(); error = $_.Exception.GetType().Name }
    }
}

$Report = [ordered]@{
    schemaVersion = 1
    collectedAt = [DateTimeOffset]::UtcNow.ToString('o')
    mode = 'AUDIT_ONLY'
    computerName = $env:COMPUTERNAME
    employeeMapping = 'NOT_CONFIGURED'
    deviceIdentity = 'USE_SIGNED_AGENT_ENROLLMENT_NOT_HOSTNAME_OR_MAC'
    sections = [ordered]@{
        operatingSystem = Read-Section {
            Get-CimInstance Win32_OperatingSystem |
                Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime
        }
        firewall = Read-Section {
            Get-NetFirewallProfile -PolicyStore ActiveStore |
                Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
        }
        defender = Read-Section {
            Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled,
                RealTimeProtectionEnabled, AntivirusSignatureLastUpdated,
                AntivirusSignatureAge, IsTamperProtected
        }
        antivirusProducts = Read-Section {
            Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
                Select-Object displayName, productState
        }
        diskEncryption = Read-Section {
            # Deliberately excludes KeyProtector: never export recovery passwords.
            Get-BitLockerVolume | Select-Object MountPoint, VolumeType, VolumeStatus,
                ProtectionStatus, EncryptionPercentage, EncryptionMethod
        }
        recentHotfixes = Read-Section {
            Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID, InstalledOn
        }
        updateService = Read-Section {
            Get-CimInstance Win32_Service -Filter "Name='wuauserv'" |
                Select-Object Name, State, StartMode
        }
        machineScreenLock = Read-Section {
            $Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            $Value = Get-ItemProperty -LiteralPath $Path -Name InactivityTimeoutSecs
            [pscustomobject]@{ inactivityTimeoutSeconds = $Value.InactivityTimeoutSecs }
        }
        localUsers = Read-Section {
            Get-LocalUser | Select-Object Name, Enabled, SID, LastLogon, PasswordRequired
        }
        localAdministrators = Read-Section {
            Get-LocalGroupMember -SID 'S-1-5-32-544' |
                Select-Object Name, SID, ObjectClass, PrincipalSource
        }
        peripherals = Read-Section {
            Get-PnpDevice -PresentOnly | Where-Object {
                $_.InstanceId -match '^(USB|USBSTOR|BTH|SWD\\WPDBUSENUM)\\' -or
                $_.Class -in @('Keyboard', 'Mouse', 'Printer', 'PrintQueue', 'WPD', 'Bluetooth', 'Net', 'DiskDrive')
            } | Select-Object -First 100 Status, Class, FriendlyName, InstanceId
        }
        networkAddresses = Read-Section {
            Get-NetIPAddress | Select-Object -First 100 InterfaceAlias, AddressFamily, IPAddress, PrefixLength, AddressState
        }
        tcpConnections = Read-Section {
            Get-NetTCPConnection | Sort-Object State,RemoteAddress | Select-Object -First 100 LocalAddress,LocalPort,RemoteAddress,RemotePort,@{Name='State';Expression={[string]$_.State}},OwningProcess
        }
        udpEndpoints = Read-Section {
            Get-NetUDPEndpoint | Select-Object -First 100 LocalAddress,LocalPort,OwningProcess
        }
        processes = Read-Section {
            Get-Process | Sort-Object ProcessName | Select-Object -First 100 Id,ProcessName,CPU,WorkingSet64
        }
        disks = Read-Section {
            Get-Disk | Select-Object Number, FriendlyName, BusType, IsBoot, IsSystem, IsReadOnly
        }
        automaticUpdates = Read-Section {
            $Task=Get-ScheduledTask -TaskName CyberShieldDeviceAutoUpdate
            $Info=Get-ScheduledTaskInfo -TaskName CyberShieldDeviceAutoUpdate
            $StatusFile=Join-Path $env:ProgramData 'CyberShieldDeviceAgent\update-status.txt'
            $Status=if(Test-Path $StatusFile){Get-Content -Raw $StatusFile}else{'No update attempted yet'}
            [pscustomobject]@{State=[string]$Task.State;LastRunTime=$Info.LastRunTime;LastTaskResult=$Info.LastTaskResult;NextRunTime=$Info.NextRunTime;UpdateStatus=$Status}
        }
        agentService = Read-Section {
            Get-CimInstance Win32_Service -Filter "Name='ServerGuardAgent'" |
                Select-Object Name, State, StartMode, StartName
        }
        services = Read-Section {
            Get-CimInstance Win32_Service | Sort-Object Name |
                Select-Object -First 100 Name, DisplayName, State, StartMode
        }
        deviceInstallationPolicies = Read-Section {
            Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' |
                Select-Object DenyRemovableDevices, DenyUnspecified, AllowAdminInstall,
                    AllowDenyLayered, AllowInstanceIDs, DenyInstanceIDs
        }
        removableStoragePolicies = Read-Section {
            $Root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
            $Keys = @(Get-Item -LiteralPath $Root) + @(Get-ChildItem -LiteralPath $Root)
            foreach ($Key in $Keys) {
                $Values = Get-ItemProperty -LiteralPath $Key.PSPath
                $Row = [ordered]@{ class = $Key.PSChildName }
                foreach ($Name in @('Deny_All', 'Deny_Read', 'Deny_Write', 'Deny_Execute')) {
                    if ($Values.PSObject.Properties.Name -contains $Name) { $Row[$Name] = $Values.$Name }
                }
                [pscustomobject]$Row
            }
        }
    }
    limitations = @(
        'Snapshot only; not continuous monitoring or enforcement.',
        'Employee mapping must be approved in the control plane; local usernames are not verified employees.',
        'Recent hotfixes and service state do not prove Windows is fully patched.',
        'Missing policy/provider returns UNKNOWN; it does not establish compliance.',
        'Peripheral and service sections are limited to 100 entries each.',
        'Machine screen-lock policy does not cover every per-user or domain policy.',
        'Report contains account names and hardware identifiers; share only with the pilot administrator.'
    )
}
$Report | ConvertTo-Json -Depth 8 -Compress
