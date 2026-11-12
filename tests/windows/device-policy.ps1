# Only for the disposable GitHub Windows runner, never a pilot/production laptop.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'This test requires a disposable GitHub Actions Windows runner'}
$Root=Join-Path $env:ProgramData 'CyberShieldDeviceAgent'
if(Test-Path $Root){throw 'Test refuses existing device state'}
New-Item -ItemType Directory -Path $Root | Out-Null
$Disk='HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
if(Test-Path $Disk){throw 'Test refuses existing storage policy'}
function Apply($Mode,$Revision){
    $Payload=@{revision=$Revision;config=@{storage=$Mode;screenLockMinutes=10;requireFirewall=$false;requireAntivirus=$false;requireEncryption=$false;bluetooth='AUDIT';mtp='AUDIT';printers='AUDIT';usbNetwork='AUDIT'}} | ConvertTo-Json -Depth 5 -Compress
    $Result=$Payload | & powershell.exe -NoProfile -NonInteractive -File agents/windows-agent/pilot/Device-Policy.ps1 | ConvertFrom-Json
    if($LASTEXITCODE -ne 0 -or $Result.revision -ne $Revision){throw 'Policy helper failed'}
    return $Result
}
try{
    $Result=Apply BLOCK 1
    if((Get-ItemProperty $Disk).Deny_Write -ne 1 -or (Get-ItemProperty $Disk).Deny_Read -ne 1){throw 'Storage block not written'}
    if(($Result.controls | Where-Object name -eq storage).status -ne 'PENDING_RESTART'){throw 'Storage must not claim immediate access enforcement'}
    $null=Apply READ_ONLY 2
    if((Get-ItemProperty $Disk).Deny_Write -ne 1 -or (Get-ItemProperty $Disk).PSObject.Properties.Name -contains 'Deny_Read'){throw 'Read-only policy failed'}
    # External change must not be overwritten on the next reconciliation.
    Set-ItemProperty $Disk Deny_Write 0
    $Result=Apply BLOCK 3
    if(($Result.controls | Where-Object name -eq storage).status -ne 'FAILED' -or (Get-ItemProperty $Disk).Deny_Write -ne 0){throw 'External policy conflict not preserved'}
    Set-ItemProperty $Disk Deny_Write 1
    $null=Apply AUDIT 4
    if((Get-ItemProperty $Disk).PSObject.Properties.Name -contains 'Deny_Write'){throw 'Owned storage policy not removed'}
    Write-Host 'Policy transition, conflict protection and acknowledgement checks passed'
}finally{
    $OwnedPath=Join-Path $Root 'policy-owned.json'
    if(Test-Path $OwnedPath){
        $Owned=Get-Content -Raw $OwnedPath | ConvertFrom-Json
        foreach($Entry in $Owned.PSObject.Properties){$Parts=$Entry.Name.Split('|');Remove-ItemProperty -LiteralPath $Parts[0] -Name $Parts[1] -ErrorAction SilentlyContinue}
    }
    Remove-Item -LiteralPath $Root -Recurse -Force
}
