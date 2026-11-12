# Runs in trusted Windows CI after tests. Signing key is supplied only on main pushes.
param([string]$Project='agents/windows-agent/ServerGuard.Agent.csproj',[string]$Scripts='agents/windows-agent/pilot',[string]$Management='agents/management/windows.ps1')
$ErrorActionPreference='Stop'
$Version=$env:GITHUB_SHA
if($Version -notmatch '^[0-9a-f]{40}$'){throw 'Commit SHA required'}
$Generation=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
dotnet publish $Project -c Release -r win-x64 --self-contained true -o artifacts/windows-x64
if($LASTEXITCODE -ne 0){throw 'Publish failed'}
Copy-Item "$Scripts/*.ps1" artifacts/windows-x64/
Copy-Item $Management artifacts/windows-x64/windows.ps1
[IO.File]::WriteAllText((Join-Path $PWD 'artifacts/windows-x64/release-version.txt'),$Version)
[IO.File]::WriteAllText((Join-Path $PWD 'artifacts/windows-x64/release-generation.txt'),[string]$Generation)
New-Item -ItemType Directory -Force agent-release | Out-Null
Compress-Archive -Path artifacts/windows-x64/* -DestinationPath agent-release/package.zip
$Hash=(Get-FileHash agent-release/package.zip -Algorithm SHA256).Hash.ToLowerInvariant()
Move-Item agent-release/package.zip "agent-release/$Hash.zip"
if($env:DEVICE_UPDATE_SIGNING_KEY){
    $Manifest=@{version=$Version;generation=$Generation;sha256=$Hash;path="/api/agent/v1/releases/$Hash.zip"} | ConvertTo-Json -Compress
    $Bytes=[Text.Encoding]::UTF8.GetBytes($Manifest)
    $RSA=[Security.Cryptography.RSA]::Create()
    try{
        $RSA.ImportFromPem($env:DEVICE_UPDATE_SIGNING_KEY)
        $Signature=$RSA.SignData($Bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }finally{$RSA.Dispose()}
    @{payload=[Convert]::ToBase64String($Bytes);signature=[Convert]::ToBase64String($Signature)} | ConvertTo-Json -Compress | Set-Content -Encoding utf8 agent-release/manifest.json
}
