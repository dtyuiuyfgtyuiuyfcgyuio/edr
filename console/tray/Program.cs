using System.Diagnostics;
using System.Windows.Forms;

namespace EdrTray;

internal static class Program
{
    private static NotifyIcon? tray;
    private static Form1? mainWindow;
    private static int? lastAlertCount;

    [STAThread]
    private static void Main()
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        var consoleUrl = Environment.GetEnvironmentVariable("EDR_CONSOLE_URL") ?? "http://localhost:8080";
        var apiKey = Environment.GetEnvironmentVariable("EDR_READ_API_KEY") ??
            Environment.GetEnvironmentVariable("EDR_API_KEY") ?? string.Empty;

        EdrApiClient apiClient;
        try
        {
            apiClient = new EdrApiClient(consoleUrl, apiKey);
        }
        catch (ArgumentException)
        {
            apiClient = new EdrApiClient("http://localhost:8080", apiKey);
        }

        using (apiClient)
        using (mainWindow = new Form1(apiClient))
        {
            InitializeTray();
            mainWindow.SnapshotChanged += MainWindow_SnapshotChanged;
            mainWindow.Show();
            Application.Run();
        }

        if (tray is not null)
        {
            tray.Visible = false;
            tray.Dispose();
            tray = null;
        }
    }

    private static void InitializeTray()
    {
        tray = new NotifyIcon
        {
            Text = "EDR 终端安全 - 正在启动",
            Visible = true,
            Icon = SystemIcons.Shield,
            ContextMenuStrip = new ContextMenuStrip()
        };

        var openItem = tray.ContextMenuStrip.Items.Add("打开终端状态");
        openItem.Font = new Font(openItem.Font, FontStyle.Bold);
        openItem.Click += (_, _) => mainWindow?.ShowWindow();

        var dashboardItem = tray.ContextMenuStrip.Items.Add("打开管理控制台");
        dashboardItem.Click += (_, _) => OpenDashboard();

        tray.ContextMenuStrip.Items.Add(new ToolStripSeparator());
        var statusItem = tray.ContextMenuStrip.Items.Add("状态：正在检查");
        statusItem.Enabled = false;
        statusItem.Name = "statusItem";

        var refreshItem = tray.ContextMenuStrip.Items.Add("立即刷新");
        refreshItem.Click += async (_, _) =>
        {
            if (mainWindow is not null)
            {
                await mainWindow.RefreshNowAsync();
            }
        };

        var settingsItem = tray.ContextMenuStrip.Items.Add("连接设置");
        settingsItem.Click += (_, _) =>
        {
            mainWindow?.ShowWindow();
            mainWindow?.ShowConnectionSettings();
        };

        tray.ContextMenuStrip.Items.Add(new ToolStripSeparator());
        var exitItem = tray.ContextMenuStrip.Items.Add("退出托盘程序");
        exitItem.Click += (_, _) => ExitApplication();

        tray.DoubleClick += (_, _) => mainWindow?.ShowWindow();
        tray.BalloonTipClicked += (_, _) => mainWindow?.ShowWindow();
    }

    private static void MainWindow_SnapshotChanged(object? sender, SnapshotChangedEventArgs e)
    {
        if (tray is null || tray.ContextMenuStrip?.Items["statusItem"] is not ToolStripItem statusItem)
        {
            return;
        }

        if (!e.Connected || e.Snapshot is null)
        {
            tray.Text = "EDR 终端安全 - 控制台离线";
            statusItem.Text = "状态：控制台离线";
            return;
        }

        var currentCount = e.Snapshot.Stats.Total;
        tray.Text = $"EDR 终端安全 - {currentCount} 条告警";
        statusItem.Text = $"状态：在线，{currentCount} 条告警";

        if (lastAlertCount.HasValue && currentCount > lastAlertCount.Value)
        {
            var newCount = currentCount - lastAlertCount.Value;
            var importantCount = e.Snapshot.Stats.SeverityCount("critical") +
                e.Snapshot.Stats.SeverityCount("high");
            tray.ShowBalloonTip(
                6000,
                $"EDR 检测到 {newCount} 条新告警",
                importantCount > 0 ? $"当前严重和高危告警共 {importantCount} 条。" : "打开终端状态查看详情。",
                importantCount > 0 ? ToolTipIcon.Warning : ToolTipIcon.Info);
        }
        lastAlertCount = currentCount;
    }

    private static void OpenDashboard()
    {
        if (mainWindow is null)
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = mainWindow.ConsoleAddress.ToString(),
                UseShellExecute = true
            });
        }
        catch
        {
            mainWindow.ShowWindow();
        }
    }

    private static void ExitApplication()
    {
        mainWindow?.PrepareToExit();
        if (tray is not null)
        {
            tray.Visible = false;
        }
        Application.Exit();
    }
}
