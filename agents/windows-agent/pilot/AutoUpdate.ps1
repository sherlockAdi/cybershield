#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory=$true)][uri]$Api)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($Api.Scheme -ne 'https' -or $Api.AbsolutePath -ne '/' -or $Api.UserInfo -or $Api.Query -or $Api.Fragment){throw 'HTTPS origin required'}
$Root=Join-Path $env:ProgramData 'CyberShieldDeviceAgent'
$Install=Join-Path $env:ProgramFiles 'CyberShieldDeviceAgent'
$Backup=$Install+'.previous'
$PublicKey='<RSAKeyValue><Modulus>pP24D1qJu3bof9Zra/4v+3NMXV6U15fK/xo8ie46g6WKK69acPV839XE6NqOKimc522ugTcFjTRGAjircAIJjRePbOnNWeb18YCO8Pk/antcRbU0Zzd9auV0K7cVaOwksvn6QKzEvYmnzVt2Fw4fOH33mHOydlfyJdB9Squ6atfGhtMTmHVn2cfoyCWhyDTBfij4vRLQlfwDY9LhX3jp1WjItCHQod+0NidYZl0dlInCak5ZKEGykej4lGN1DetTdr8Y0LgN81RdC9xpUGdrTug9/EMMyKX4Al8vfTJt/UrCtU6AqJZioRhmElnoyYo2lKYzCCY0s6oBFnqEmAJPUPgm5K8Ot9UH+Ug4TO3znxDRqgXDeOIybY1D13QIQiCcbCebMZ+apL+FBZ9KmL0X8R3DfCSP/bZW+BwxG7LVcikEuJdDgSI0F6VFiYO+bGbQqPCP4TY3Y50VOSO78KbFSovRrbAdVuDEPpasFrZjmXf4BilaVB36QSrpozUQPE9h</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.IO.Compression.FileSystem
$Handler=New-Object Net.Http.HttpClientHandler
$Handler.AllowAutoRedirect=$false
$Client=New-Object Net.Http.HttpClient($Handler)
$Client.Timeout=[TimeSpan]::FromMinutes(3)
function Download($Url,$File,$Limit){
    $Response=$Client.GetAsync($Url,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    try{
        $Response.EnsureSuccessStatusCode() | Out-Null
        $Input=$Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $Output=[IO.File]::Open($File,[IO.FileMode]::CreateNew)
        try{$Buffer=New-Object byte[] 65536;$Total=0;while(($Count=$Input.Read($Buffer,0,$Buffer.Length)) -gt 0){$Total+=$Count;if($Total -gt $Limit){throw 'Download too large'};$Output.Write($Buffer,0,$Count)}}finally{$Output.Dispose();$Input.Dispose()}
    }finally{$Response.Dispose()}
}
$Stage=Join-Path $Root ('update-'+[guid]::NewGuid().ToString('N'))
$Moved=$false
try{
    $Service=Get-CimInstance Win32_Service -Filter "Name='ServerGuardAgent'"
    if(-not $Service -or -not $Service.PathName.StartsWith(('"'+(Join-Path $Install 'ServerGuard.Agent.exe')+'" '),[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected service path'}
    New-Item -ItemType Directory -Path $Stage | Out-Null
    $ManifestFile=Join-Path $Stage 'manifest.json'
    Download ([uri]::new($Api,'/api/agent/v1/releases/manifest.json')) $ManifestFile 12000
    $Envelope=Get-Content -Raw -LiteralPath $ManifestFile | ConvertFrom-Json
    $Payload=[Convert]::FromBase64String($Envelope.payload)
    $Signature=[Convert]::FromBase64String($Envelope.signature)
    $RSA=New-Object Security.Cryptography.RSACryptoServiceProvider
    try{$RSA.FromXmlString($PublicKey);if(-not $RSA.VerifyData($Payload,'SHA256',$Signature)){throw 'Update signature invalid'}}finally{$RSA.Dispose()}
    $Manifest=[Text.Encoding]::UTF8.GetString($Payload) | ConvertFrom-Json
    if($Manifest.version -notmatch '^[0-9a-f]{40}$' -or $Manifest.sha256 -notmatch '^[0-9a-f]{64}$' -or $Manifest.path -cne ('/api/agent/v1/releases/'+$Manifest.sha256+'.zip')){throw 'Invalid signed manifest'}
    $VersionFile=Join-Path $Install 'release-version.txt'
    if((Test-Path $VersionFile) -and (Get-Content -Raw $VersionFile).Trim() -eq $Manifest.version){return}
    $FailedFile=Join-Path $Root 'failed-update.txt'
    if((Test-Path $FailedFile) -and (Get-Content -Raw $FailedFile).Trim() -eq $Manifest.version){return}
    $Clock=Join-Path $Root 'update-generation.txt'
    if((Test-Path $Clock) -and [long]$Manifest.generation -le [long](Get-Content -Raw $Clock)){throw 'Update rollback/replay rejected'}
    if([long]$Manifest.generation -gt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+300){throw 'Update timestamp is in the future'}
    $Zip=Join-Path $Stage 'package.zip'
    Download ([uri]::new($Api,$Manifest.path)) $Zip 104857600
    if((Get-FileHash -LiteralPath $Zip -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Manifest.sha256){throw 'Update checksum invalid'}
    $Expanded=Join-Path $Stage 'package'
    $Archive=[IO.Compression.ZipFile]::OpenRead($Zip)
    try{
        $Size=0
        foreach($Entry in $Archive.Entries){
            $Name=$Entry.FullName.Replace('\','/')
            $Size+=$Entry.Length
            if($Name.StartsWith('/') -or $Name.Contains(':') -or $Name.Split('/') -contains '..' -or @($Name.Split('/') | Where-Object {$_ -and ($_ -eq '.' -or $_ -match '[. ]$')}).Count -gt 0 -or (($Entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000 -or $Size -gt 262144000){throw 'Unsafe package entry'}
        }
    }finally{$Archive.Dispose()}
    [IO.Compression.ZipFile]::ExtractToDirectory($Zip,$Expanded)
    foreach($Required in @('ServerGuard.Agent.exe','Device-Policy.ps1','Audit-Device.ps1','windows.ps1','AutoUpdate.ps1','release-version.txt','release-generation.txt')){if(-not(Test-Path -LiteralPath (Join-Path $Expanded $Required) -PathType Leaf)){throw 'Incomplete package'}}
    if((Get-Content -Raw (Join-Path $Expanded 'release-version.txt','release-generation.txt')).Trim() -cne $Manifest.version){throw 'Package version mismatch'}
    # Files inherit the administrator-only state ACL, including after the directory move.
    if(Test-Path $Backup){throw 'Previous backup still exists; administrator review required'}
    Stop-Service ServerGuardAgent
    (Get-Service ServerGuardAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    Move-Item -LiteralPath $Install -Destination $Backup
    $Moved=$true
    Move-Item -LiteralPath $Expanded -Destination $Install
    $Health=Join-Path $Root 'update-health.json'
    if(Test-Path $Health){Remove-Item -LiteralPath $Health}
    Start-Service ServerGuardAgent
    $Healthy=$false
    for($i=0;$i -lt 36;$i++){
        Start-Sleep -Seconds 5
        if(Test-Path $Health){try{$Ack=Get-Content -Raw $Health | ConvertFrom-Json;if($Ack.version -ceq $Manifest.version){$Healthy=$true;break}}catch{}}
    }
    if(-not $Healthy){throw 'Updated agent did not acknowledge a control-plane heartbeat'}
    [string]$Manifest.generation | Set-Content -LiteralPath $Clock
    Copy-Item -LiteralPath (Join-Path $Install 'AutoUpdate.ps1') -Destination (Join-Path $Root 'AutoUpdate.ps1') -Force
    Remove-Item -LiteralPath $Backup -Recurse -Force
    $Moved=$false
    'SUCCESS '+$Manifest.version | Set-Content (Join-Path $Root 'update-status.txt')
}catch{
    $Failure=$_.Exception.Message
    if($Moved){
        Stop-Service ServerGuardAgent -ErrorAction SilentlyContinue
        (Get-Service ServerGuardAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
        if(Test-Path $Install){Remove-Item -LiteralPath $Install -Recurse -Force}
        Move-Item -LiteralPath $Backup -Destination $Install
        Start-Service ServerGuardAgent
        $Manifest.version | Set-Content -LiteralPath (Join-Path $Root 'failed-update.txt')
    }
    ('FAILED '+$Failure) | Set-Content (Join-Path $Root 'update-status.txt')
    throw
}finally{
    $Client.Dispose();$Handler.Dispose()
    if(Test-Path $Stage){Remove-Item -LiteralPath $Stage -Recurse -Force}
}
