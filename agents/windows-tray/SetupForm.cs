using System.Diagnostics;
using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;

internal sealed class SetupForm : Form
{
    public SetupForm()
    {
        Text = "CyberShield device setup";
        Width = 550;
        Height = 300;
        var fields = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, Padding = new Padding(16), WrapContents = false };
        var id = new TextBox { Width = 470 };
        var token = new TextBox { Width = 470, UseSystemPasswordChar = true };
        var status = new Label { Width = 470, Height = 45 };
        var install = new Button { Text = "Register this device", AutoSize = true };
        var sharing = new Button { Text = "Install screen sharing controls", AutoSize = true };
        fields.Controls.AddRange([new Label { Text = "Device ID from Device Management", AutoSize = true }, id,
            new Label { Text = "One-time enrollment token", AutoSize = true }, token, install, sharing, status]);
        Controls.Add(fields);
        sharing.Click += (_, _) =>
        {
            try { Installer.ProvisionSharing(); status.Text = "Screen sharing controls installed. Open them from CyberShield."; }
            catch (Exception ex) { status.Text = ex.Message; }
        };
        install.Click += async (_, _) =>
        {
            var secret = token.Text.Trim();
            token.Clear();
            if (secret.Length == 86 && secret[..43] == secret[43..]) secret = secret[..43];
            if (!Guid.TryParse(id.Text, out var device) || !Regex.IsMatch(secret, @"\A[A-Za-z0-9_-]{43}\z"))
            {
                status.Text = "Enter the device UUID and a valid 43-character token.";
                return;
            }
            install.Enabled = false;
            try
            {
                await Task.Run(() => Installer.Register(device, secret));
                status.Text = "Service started. Check Devices for an ONLINE heartbeat.";
            }
            catch (Exception ex) { status.Text = ex.Message; }
            finally { install.Enabled = true; }
        };
    }
}

internal static class Installer
{
    private static readonly string Common = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    private static readonly string Install = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CyberShieldDeviceAgent");
    private static readonly string State = Path.Combine(Common, "CyberShieldDeviceAgent");

    internal static string ServiceStatus()
    {
        try
        {
            var (code, output) = Run("sc.exe", "query", Program.Service);
            if (code != 0) return "Agent not installed";
            return Regex.IsMatch(output, @"STATE\s*:\s*4\b") ? "Agent running" : "Agent not running";
        }
        catch { return "Agent status unavailable"; }
    }

    internal static void Register(Guid id, string token)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Administrator approval is required.");
        if (Run("sc.exe", "query", Program.Service).Code == 0 || Directory.Exists(State) || Directory.Exists(Install))
            throw new InvalidOperationException("This device already has an installation. Use its existing enrollment.");
        using var payload = typeof(Installer).Assembly.GetManifestResourceStream("AgentPackage")
            ?? throw new InvalidOperationException("The agent payload is missing from this build.");
        var createdService = false;
        var createdDirectories = new List<string>();
        try
        {
            foreach (var path in new[] { Install, State })
            {
                ProtectedDirectory(path);
                createdDirectories.Add(path);
            }
            using (var zip = new ZipArchive(payload, ZipArchiveMode.Read)) zip.ExtractToDirectory(Install);
            var exe = Path.Combine(Install, "ServerGuard.Agent.exe");
            var file = Path.Combine(State, "enrollment.token");
            File.WriteAllText(file, token);
            var audit = Path.Combine(Install, "Audit-Device.ps1");
            var policy = Path.Combine(Install, "Device-Policy.ps1");
            var command = $"\"{exe}\" --api \"{Program.Dashboard.TrimEnd('/')}\" --server-id {id:D} --state-dir \"{State}\" --token-file \"{file}\" --device-audit-helper \"{audit}\" --device-policy-helper \"{policy}\"";
            Check("sc.exe", "create", Program.Service, "binPath=", command, "start=", "auto", "DisplayName=", "CyberShield Device Agent");
            createdService = true;
            Check("sc.exe", "start", Program.Service);
        }
        catch
        {
            if (createdService) Run("sc.exe", "delete", Program.Service);
            foreach (var path in createdDirectories) Directory.Delete(path, recursive: true);
            throw;
        }
    }

    private static void ProtectedDirectory(string path)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { "S-1-5-18", "S-1-5-32-544" })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).Create(security);
    }

    internal static void ProvisionSharing()
    {
        var root = Path.Combine(Common, "CyberShieldScreenCapture");
        if (Directory.Exists(root))
            throw new InvalidOperationException("Screen sharing controls already exist.");
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator) || identity.User is null)
            throw new InvalidOperationException("Administrator approval is required.");
        using var payload = typeof(Installer).Assembly.GetManifestResourceStream("AgentPackage")!;
        using var zip = new ZipArchive(payload, ZipArchiveMode.Read);
        var entry = zip.GetEntry("Start-ScreenSharing.ps1") ?? throw new InvalidOperationException("Missing screen sharing helper.");
        var admins = new SecurityIdentifier("S-1-5-32-544");
        ProtectedDirectory(root);
        var directory = new DirectoryInfo(root);
        var acl = directory.GetAccessControl();
        acl.SetOwner(admins);
        acl.AddAccessRule(new FileSystemAccessRule(identity.User, FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(acl);
        var script = new FileInfo(Path.Combine(root, entry.Name));
        entry.ExtractToFile(script.FullName);
        var scriptAcl = script.GetAccessControl();
        scriptAcl.SetOwner(admins);
        script.SetAccessControl(scriptAcl);
        var frames = directory.CreateSubdirectory("frames");
        var framesAcl = frames.GetAccessControl();
        framesAcl.AddAccessRule(new FileSystemAccessRule(identity.User, FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        frames.SetAccessControl(framesAcl);
    }

    private static void Check(string executable, params string[] args)
    {
        var result = Run(executable, args);
        if (result.Code != 0) throw new InvalidOperationException($"Windows service operation failed ({result.Code}).");
    }

    private static (int Code, string Output) Run(string executable, params string[] args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, executable))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
        };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start Windows service tool.");
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output);
    }
}
