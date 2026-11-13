using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using System.Diagnostics;

internal static class Program
{
    internal const string Dashboard = "https://cybershield360.vvvitsolutions.online/";
    internal const string Service = "ServerGuardAgent";

    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        if (args is ["--setup"])
        {
            Application.Run(new SetupForm());
            return;
        }

        using var instance = new Mutex(true, @"Local\CyberShieldTray", out var first);
        if (!first) return;
        using var window = new Form { Text = "CyberShield", Width = 1280, Height = 850, Icon = SystemIcons.Shield };
        using var browser = new WebView2 { Dock = DockStyle.Fill };
        var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 44 };
        var status = new Label { AutoSize = true, Padding = new Padding(8, 8, 8, 0) };
        void Add(string text, Action action)
        {
            var button = new Button { Text = text, AutoSize = true };
            button.Click += (_, _) => action();
            toolbar.Controls.Add(button);
        }
        Add("Dashboard", () => browser.CoreWebView2?.Navigate(Dashboard));
        Add("Device setup", () => Launch(new ProcessStartInfo(Environment.ProcessPath!, "--setup") { UseShellExecute = true, Verb = "runas" }));
        Add("Screen sharing", OpenSharing);
        toolbar.Controls.Add(status);
        window.Controls.Add(browser);
        window.Controls.Add(toolbar);
        using var menu = new ContextMenuStrip();
        using var tray = new NotifyIcon { Icon = SystemIcons.Shield, Text = "CyberShield", Visible = true, ContextMenuStrip = menu };
        void ShowWindow() { window.Show(); window.WindowState = FormWindowState.Normal; window.Activate(); }
        menu.Items.Add("Open CyberShield", null, (_, _) => ShowWindow());
        menu.Items.Add("Screen sharing", null, (_, _) => OpenSharing());
        var exit = false;
        menu.Items.Add("Exit", null, (_, _) => { exit = true; window.Close(); });
        tray.DoubleClick += (_, _) => ShowWindow();
        window.FormClosing += (_, e) => { if (!exit && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; window.Hide(); } };
        using var timer = new System.Windows.Forms.Timer { Interval = 5000 };
        void RefreshStatus() => status.Text = Installer.ServiceStatus();
        timer.Tick += (_, _) => RefreshStatus();
        timer.Start();
        window.Shown += async (_, _) =>
        {
            RefreshStatus();
            try
            {
                var profile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CyberShield", "Dashboard");
                var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: profile);
                await browser.EnsureCoreWebView2Async(environment);
                bool Allowed(string url) => Uri.TryCreate(url, UriKind.Absolute, out var uri)
                    && uri.GetLeftPart(UriPartial.Authority).Equals(Dashboard.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
                browser.CoreWebView2.NavigationStarting += (_, e) => e.Cancel = !Allowed(e.Uri);
                browser.CoreWebView2.NewWindowRequested += (_, e) =>
                {
                    e.Handled = true;
                    if (Allowed(e.Uri)) browser.CoreWebView2.Navigate(e.Uri);
                };
                browser.CoreWebView2.Navigate(Dashboard);
            }
            catch (Exception ex) { MessageBox.Show(window, ex.Message, "Dashboard unavailable"); }
        };
        Application.Run(window);
    }

    private static void OpenSharing()
    {
        var helper = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CyberShieldScreenCapture", "Start-ScreenSharing.ps1");
        if (!File.Exists(helper))
        {
            MessageBox.Show("Open Device setup first to install the screen sharing helper.", "CyberShield");
            return;
        }
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in new[] { "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File", helper })
            start.ArgumentList.Add(argument);
        Launch(start);
    }

    private static void Launch(ProcessStartInfo start)
    {
        try { Process.Start(start)?.Dispose(); }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223) { }
        catch (Exception ex) { MessageBox.Show(ex.Message, "CyberShield"); }
    }
}
