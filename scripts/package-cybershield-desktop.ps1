$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$payload = Join-Path $root 'artifacts/desktop-agent-payload'
$zip = Join-Path $root 'artifacts/desktop-agent.zip'
dotnet publish "$root/agents/windows-agent/ServerGuard.Agent.csproj" -c Release -r win-x64 --self-contained true -o $payload
if ($LASTEXITCODE) { exit $LASTEXITCODE }
Copy-Item "$root/agents/windows-agent/pilot/Audit-Device.ps1","$root/agents/windows-agent/pilot/Device-Policy.ps1","$root/agents/windows-agent/pilot/Start-ScreenSharing.ps1" $payload
Compress-Archive -Path "$payload/*" -DestinationPath $zip -Force
dotnet publish "$root/agents/windows-tray/CyberShield.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:AgentPackage="$zip" -o "$root/artifacts/CyberShieldDesktop"
exit $LASTEXITCODE
