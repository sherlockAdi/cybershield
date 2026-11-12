#requires -Version 5.1
# Run interactively as the configured user. Never run as a hidden/SYSTEM task.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class CaptureDesktop {
 [DllImport("user32.dll")] static extern IntPtr OpenInputDesktop(uint flags,bool inherit,uint access);
 [DllImport("user32.dll")] static extern bool SwitchDesktop(IntPtr desktop);
 [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr desktop);
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
 public static bool Unlocked(){var d=OpenInputDesktop(0,false,0x0100);if(d==IntPtr.Zero)return false;try{return SwitchDesktop(d);}finally{CloseDesktop(d);}}
}
'@
$Root=Join-Path $env:ProgramData 'CyberShieldScreenCapture'
$Frames=Join-Path $Root 'frames'
$Lock=[IO.File]::Open((Join-Path $Frames 'capture.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$FramePath=Join-Path $Frames 'latest.json'
$script:Consent=$false;$script:Next=[DateTimeOffset]::MinValue
$Form=[Windows.Forms.Form]::new();$Form.Text='CyberShield - visible screen sharing';$Form.Width=450;$Form.Height=220
$Label=[Windows.Forms.Label]::new();$Label.SetBounds(15,15,400,85);$Label.Text='Capture is OFF. Your primary screen can be shared with organization administrators only after you click Allow. Stop sharing at any time.'
$Allow=[Windows.Forms.Button]::new();$Allow.Text='Allow screen sharing';$Allow.SetBounds(15,110,190,35)
$Stop=[Windows.Forms.Button]::new();$Stop.Text='Stop sharing';$Stop.SetBounds(220,110,190,35)
$Form.Controls.AddRange(@($Label,$Allow,$Stop))
$Allow.Add_Click({$script:Consent=$true;$script:Next=[DateTimeOffset]::MinValue})
$Stop.Add_Click({$script:Consent=$false;$Label.Text='Sharing stopped locally. No further screenshots will be captured.';Remove-Item -LiteralPath $FramePath -ErrorAction SilentlyContinue})
$Tray=[Windows.Forms.NotifyIcon]::new();$Tray.Icon=[Drawing.SystemIcons]::Information;$Tray.Text='CyberShield screen sharing - OFF';$Tray.Visible=$true
$Tray.Add_DoubleClick({$Form.Show();$Form.WindowState='Normal';$Form.Activate()})
$Menu=[Windows.Forms.ContextMenuStrip]::new();$Item=$Menu.Items.Add('Stop sharing');$Item.Add_Click({$script:Consent=$false;$Label.Text='Sharing stopped locally.';Remove-Item -LiteralPath $FramePath -ErrorAction SilentlyContinue});$Tray.ContextMenuStrip=$Menu
$Timer=[Windows.Forms.Timer]::new();$Timer.Interval=1000
$Timer.Add_Tick({
 try{
    $Settings=Get-Content -Raw -LiteralPath (Join-Path $Root 'settings.json') | ConvertFrom-Json
    if(-not $Settings.enabled -or [DateTimeOffset]::Parse($Settings.validUntil) -lt [DateTimeOffset]::UtcNow){$script:Consent=$false;$Label.Text='Capture is disabled or the agent is offline. Ask the administrator to enable it, then click Allow.'}
    if(-not $script:Consent){$Tray.Text='CyberShield screen sharing - OFF';Remove-Item -LiteralPath $FramePath -ErrorAction SilentlyContinue;return}
    $Seconds=[int]$Settings.intervalSeconds
    if($Seconds -notin @(1,5,10,15)){throw 'Unsupported interval'}
    $Tray.Text="CyberShield CAPTURING every $Seconds seconds"
    $Label.Text="SCREEN SHARING ON - primary monitor every $Seconds seconds. Organization administrators can view the latest image. Click Stop to end sharing."
    if([Diagnostics.Process]::GetCurrentProcess().SessionId -ne [CaptureDesktop]::WTSGetActiveConsoleSessionId() -or -not [CaptureDesktop]::Unlocked()){Remove-Item -LiteralPath $FramePath -ErrorAction SilentlyContinue;return}
    if([DateTimeOffset]::UtcNow -lt $script:Next){return}
    $script:Next=[DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    $Bounds=[Windows.Forms.Screen]::PrimaryScreen.Bounds
    $Full=[Drawing.Bitmap]::new($Bounds.Width,$Bounds.Height)
    try{
      $Graphics=[Drawing.Graphics]::FromImage($Full)
      try{$Graphics.CopyFromScreen($Bounds.Location,[Drawing.Point]::Empty,$Bounds.Size)}finally{$Graphics.Dispose()}
      $Width=[Math]::Min(960,$Bounds.Width);$Height=[int]($Bounds.Height*$Width/$Bounds.Width)
      $Small=[Drawing.Bitmap]::new($Full,$Width,$Height)
      try{
        $Memory=[IO.MemoryStream]::new();$Encoder=[Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object MimeType -eq 'image/jpeg'
        $Parameters=[Drawing.Imaging.EncoderParameters]::new(1);$Parameters.Param[0]=[Drawing.Imaging.EncoderParameter]::new([Drawing.Imaging.Encoder]::Quality,[long]40)
        try{$Small.Save($Memory,$Encoder,$Parameters);$Bytes=$Memory.ToArray()}finally{$Memory.Dispose();$Parameters.Dispose()}
      }finally{$Small.Dispose()}
    }finally{$Full.Dispose()}
    if($Bytes.Length -gt 96000){$Label.Text='Frame is too large; no image uploaded.';return}
    $Frame=@{capturedAt=[DateTimeOffset]::UtcNow.ToString('o');revision=[int]$Settings.revision;jpeg=[Convert]::ToBase64String($Bytes)} | ConvertTo-Json -Compress
    $Temp=Join-Path $Frames ([guid]::NewGuid().ToString('N')+'.tmp')
    try{[IO.File]::WriteAllText($Temp,$Frame,[Text.UTF8Encoding]::new($false));Move-Item -LiteralPath $Temp -Destination $FramePath -Force}finally{if(Test-Path $Temp){Remove-Item -LiteralPath $Temp -ErrorAction SilentlyContinue}}
 }catch{$script:Consent=$false;$Label.Text='Waiting for the agent or capture is unavailable. No image captured.';$Tray.Text='CyberShield screen sharing - unavailable';Remove-Item -LiteralPath $FramePath -ErrorAction SilentlyContinue}
})
$Form.Add_FormClosing({$script:Consent=$false;$Timer.Stop();Remove-Item -LiteralPath $FramePath -ErrorAction SilentlyContinue})
try{$Timer.Start();[Windows.Forms.Application]::Run($Form)}finally{$Timer.Dispose();$Tray.Dispose();$Lock.Dispose();$Form.Dispose()}
