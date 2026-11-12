#requires -Version 5.1
#requires -RunAsAdministrator
# Fixed policy operations only. Never executes command text supplied by the server.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$StatePath=Join-Path $env:ProgramData 'CyberShieldDeviceAgent\policy-owned.json'
$Owned=@{}
if(Test-Path -LiteralPath $StatePath){
    $Saved=Get-Content -Raw -LiteralPath $StatePath | ConvertFrom-Json
    foreach($Property in $Saved.PSObject.Properties){$Owned[$Property.Name]=$Property.Value}
}
function Save-Owned {
    $Temp=$StatePath+'.tmp'
    $Owned | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath $Temp
    Move-Item -LiteralPath $Temp -Destination $StatePath -Force
}
function Read-Value($Path,$Name){
    $Item=Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if($null -ne $Item -and $Item.PSObject.Properties.Name -contains $Name){return $Item.$Name}
    return $null
}
function Set-OwnedValue($Path,$Name,$Desired){
    $Key=$Path+'|'+$Name
    $Current=Read-Value $Path $Name
    if(-not $Owned.ContainsKey($Key)){
        if($null -ne $Current){throw 'Existing administrator/GPO value detected; refusing to overwrite unmanaged policy.'}
        if($null -eq $Desired){return}
        $Owned[$Key]=[pscustomobject]@{last=$null;pending=$null}
    }
    $Entry=$Owned[$Key]
    if($null -ne $Current -and $Current -ne $Entry.last -and $Current -ne $Entry.pending){throw 'Policy changed outside CyberShield; manual reconciliation required.'}
    $Entry.pending=$Desired;Save-Owned
    if($null -eq $Desired){Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue}
    else{if(-not(Test-Path -LiteralPath $Path)){New-Item -Path $Path -Force | Out-Null};New-ItemProperty -LiteralPath $Path -Name $Name -Value ([int]$Desired) -PropertyType DWord -Force | Out-Null}
    if((Read-Value $Path $Name) -ne $Desired){throw 'Policy read-back failed.'}
    $Entry.last=$Desired;$Entry.pending=$null;Save-Owned
}
$Request=[Console]::In.ReadToEnd()
if($Request.Length -gt 16000){throw 'Policy input too large'}
$Policy=$Request | ConvertFrom-Json
if($Policy.revision -lt 1){throw 'Invalid revision'}
$Config=$Policy.config
$Results=[Collections.Generic.List[object]]::new()
function Result($Name,$Status,$Message){$Results.Add(@{name=$Name;status=$Status;message=$Message})}
$Edition=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
$DomainJoined=(Get-CimInstance Win32_ComputerSystem).PartOfDomain
try{
    if($Config.storage -eq 'ALLOWLIST'){Result 'storage' 'UNSUPPORTED' 'Per-device storage exceptions require a device-control provider; existing policy is retained.'}
    elseif($Config.storage -in @('AUDIT','BLOCK','READ_ONLY')){
        if($DomainJoined -or $Edition -match '^Core'){throw 'Storage policy needs a supported unmanaged Windows Pro/Enterprise pilot; domain/Home policy requires separate integration.'}
        $Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
        $Read=if($Config.storage -eq 'BLOCK'){1}else{$null}
        $Write=if($Config.storage -in @('BLOCK','READ_ONLY')){1}else{$null}
        Set-OwnedValue $Path 'Deny_Write' $Write
        Set-OwnedValue $Path 'Deny_Read' $Read
        if($Config.storage -eq 'AUDIT'){Result 'storage' 'NOT_MANAGED' 'CyberShield-owned storage restrictions removed; external policies can still restrict access.'}
        else{Result 'storage' 'PENDING_RESTART' 'Windows removable-disk policy written and read back. Reconnect storage/restart if needed; existing handles and USB fixed disks need native acceptance testing.'}
    }else{throw 'Unsupported storage mode'}
}catch{Result 'storage' 'FAILED' $_.Exception.Message}
try{
    $Minutes=[int]$Config.screenLockMinutes
    if($Minutes -lt 1 -or $Minutes -gt 60){throw 'Invalid lock interval'}
    if($DomainJoined -or $Edition -match '^Core'){throw 'Screen-lock policy requires a supported unmanaged Windows Pro/Enterprise pilot.'}
    Set-OwnedValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs' ($Minutes*60)
    Result 'screenLock' 'PENDING_RESTART' 'Machine inactivity policy configured. Verify on the employee session; sign-out/restart may be needed.'
}catch{Result 'screenLock' 'FAILED' $_.Exception.Message}
try{
    if($Config.requireFirewall){
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
        if(@(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {-not $_.Enabled}).Count){throw 'An effective firewall profile remains disabled.'}
        Result 'firewall' 'APPLIED' 'All Windows Firewall profiles verified enabled.'
    }else{Result 'firewall' 'NOT_MANAGED' 'Firewall is not disabled when this requirement is unchecked.'}
}catch{Result 'firewall' 'FAILED' $_.Exception.Message}
try{
    if($Config.requireAntivirus){
        $AV=Get-MpComputerStatus
        if(-not $AV.RealTimeProtectionEnabled){Set-MpPreference -DisableRealtimeMonitoring $false;$AV=Get-MpComputerStatus}
        if(-not $AV.AntivirusEnabled -or -not $AV.RealTimeProtectionEnabled){throw 'Defender real-time antivirus not active; check third-party AV/tamper protection.'}
        Result 'antivirus' 'VERIFIED' 'Microsoft Defender antivirus and real-time protection are active.'
    }else{Result 'antivirus' 'NOT_MANAGED' 'Antivirus is not disabled when this requirement is unchecked.'}
}catch{Result 'antivirus' 'FAILED' $_.Exception.Message}
try{
    if($Config.requireEncryption){
        $Disk=Get-BitLockerVolume -MountPoint $env:SystemDrive
        if([string]$Disk.ProtectionStatus -eq 'On'){Result 'encryption' 'VERIFIED' 'System drive BitLocker protection is on.'}
        else{Result 'encryption' 'UNSUPPORTED' 'Encryption is not enabled automatically: recovery-key escrow and owner verification are required.'}
    }else{Result 'encryption' 'NOT_MANAGED' 'Encryption is not disabled.'}
}catch{Result 'encryption' 'FAILED' $_.Exception.Message}
foreach($Name in @('bluetooth','mtp','printers','usbNetwork')){
    if($Config.$Name -eq 'BLOCK'){Result $Name 'UNSUPPORTED' 'Requires a tested peripheral-specific provider. No blanket device disabling performed.'}
    else{Result $Name 'NOT_MANAGED' 'Audit only.'}
}
$Bad=@($Results | Where-Object {$_.status -in @('FAILED','UNSUPPORTED','PENDING_RESTART')})
$Status=if($Bad.Count -eq 0){'APPLIED'}elseif($Bad.Count -eq $Results.Count){'FAILED'}else{'PARTIAL'}
@{revision=[int]$Policy.revision;status=$Status;controls=$Results.ToArray()} | ConvertTo-Json -Depth 8 -Compress
