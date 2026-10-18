using System.Diagnostics;
using System.Text.Json;

namespace EdrTray;

public partial class Form1 : Form
{
    private static readonly Color CanvasColor = Color.FromArgb(244, 247, 249);
    private static readonly Color TextColor = Color.FromArgb(24, 35, 46);
    private static readonly Color MutedColor = Color.FromArgb(93, 107, 120);
    private static readonly Color BorderColor = Color.FromArgb(216, 223, 229);
    private static readonly Color HealthyColor = Color.FromArgb(5, 150, 105);
    private static readonly Color WarningColor = Color.FromArgb(202, 138, 4);
    private static readonly Color DangerColor = Color.FromArgb(220, 38, 38);
    private static readonly string[] SeverityValues = ["", "critical", "high", "medium", "low", "info"];

    private readonly EdrApiClient apiClient;
    private readonly CancellationTokenSource lifetime = new();
    private readonly System.Windows.Forms.Timer refreshTimer = new() { Interval = 10_000 };

    private Label connectionBadge = null!;
    private Label protectionTitle = null!;
    private Label protectionSubtitle = null!;
    private Label agentStateLabel = null!;
    private Label consoleStateLabel = null!;
    private Label syncStateLabel = null!;
    private Panel protectionAccent = null!;
    private PictureBox protectionIcon = null!;
    private Label totalAlertsValue = null!;
    private Label importantAlertsValue = null!;
    private Label processesValue = null!;
    private Label eventsValue = null!;
    private Label alertsCountLabel = null!;
    private Label lastUpdatedLabel = null!;
    private ComboBox severityFilter = null!;
    private Button refreshButton = null!;
    private DataGridView alertsGrid = null!;

    private EndpointSnapshot? lastSnapshot;
    private bool isRefreshing;
    private bool allowClose;
    private bool agentRunning;

    internal Form1(EdrApiClient apiClient)
    {
        this.apiClient = apiClient;
        InitializeComponent();
        BuildInterface();

        Load += (_, _) => FitToWorkingArea();
        refreshTimer.Tick += async (_, _) => await RefreshNowAsync();
        Shown += async (_, _) =>
        {
            refreshTimer.Start();
            await RefreshNowAsync();
        };
    }

    internal event EventHandler<SnapshotChangedEventArgs>? SnapshotChanged;

    internal Uri ConsoleAddress => apiClient.BaseAddress;

    internal async Task RefreshNowAsync()
    {
        if (isRefreshing || lifetime.IsCancellationRequested)
        {
            return;
        }

        isRefreshing = true;
        refreshButton.Enabled = false;
        refreshButton.Text = "正在刷新...";
        agentRunning = IsAgentRunning();
        UpdateProtectionState(false, "正在连接管理控制台...");
        connectionBadge.Text = "正在连接";
        connectionBadge.BackColor = Color.FromArgb(226, 232, 240);
        connectionBadge.ForeColor = MutedColor;

        try
        {
            var snapshot = await apiClient.GetSnapshotAsync(lifetime.Token);
            lastSnapshot = snapshot;
            RenderSnapshot(snapshot);
            UpdateProtectionState(true, string.Empty);
            SnapshotChanged?.Invoke(this, new SnapshotChangedEventArgs(snapshot, true, string.Empty));
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
            return;
        }
        catch (EndpointApiException exception)
        {
            UpdateProtectionState(false, exception.Message);
            SnapshotChanged?.Invoke(this, new SnapshotChangedEventArgs(null, false, exception.Message));
        }
        catch (HttpRequestException)
        {
            const string message = "无法连接管理控制台。";
            UpdateProtectionState(false, message);
            SnapshotChanged?.Invoke(this, new SnapshotChangedEventArgs(null, false, message));
        }
        catch (TaskCanceledException)
        {
            const string message = "连接管理控制台超时。";
            UpdateProtectionState(false, message);
            SnapshotChanged?.Invoke(this, new SnapshotChangedEventArgs(null, false, message));
        }
        finally
        {
            isRefreshing = false;
            refreshButton.Enabled = true;
            refreshButton.Text = "刷新";
        }
    }

    internal void ShowConnectionSettings()
    {
        using var dialog = new ConnectionSettingsForm(apiClient.BaseAddress, apiClient.ApiKey);
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        try
        {
            apiClient.Configure(dialog.ConsoleAddress, dialog.ApiKey);
            _ = RefreshNowAsync();
        }
        catch (ArgumentException exception)
        {
            MessageBox.Show(this, exception.Message, "连接设置", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    internal void ShowWindow()
    {
        if (!Visible)
        {
            Show();
        }
        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }
        ShowInTaskbar = true;
        Activate();
        BringToFront();
    }

    internal void PrepareToExit()
    {
        allowClose = true;
        refreshTimer.Stop();
        lifetime.Cancel();
    }

    private void BuildInterface()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            BackColor = CanvasColor,
            Padding = new Padding(20, 16, 20, 14),
            ColumnCount = 1,
            RowCount = 5
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 66));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 154));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 102));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));

        root.Controls.Add(CreateHeader(), 0, 0);
        root.Controls.Add(CreateProtectionPanel(), 0, 1);
        root.Controls.Add(CreateMetricsPanel(), 0, 2);
        root.Controls.Add(CreateAlertsPanel(), 0, 3);
        root.Controls.Add(CreateFooter(), 0, 4);
        Controls.Add(root);
    }

    private void FitToWorkingArea()
    {
        var workingArea = Screen.FromControl(this).WorkingArea;
        var availableWidth = Math.Max(760, workingArea.Width - 32);
        var availableHeight = Math.Max(560, workingArea.Height - 32);
        var targetSize = new Size(
            Math.Min(Width, availableWidth),
            Math.Min(Height, availableHeight));

        MinimumSize = new Size(
            Math.Min(MinimumSize.Width, targetSize.Width),
            Math.Min(MinimumSize.Height, targetSize.Height));
        Size = targetSize;
        Location = new Point(
            workingArea.Left + Math.Max(0, (workingArea.Width - Width) / 2),
            workingArea.Top + Math.Max(0, (workingArea.Height - Height) / 2));
    }

    private Control CreateHeader()
    {
        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            Margin = Padding.Empty
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));

        var identity = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = Padding.Empty
        };
        identity.Controls.Add(new PictureBox
        {
            Image = SystemIcons.Shield.ToBitmap(),
            SizeMode = PictureBoxSizeMode.Zoom,
            Size = new Size(40, 40),
            Margin = new Padding(0, 4, 12, 0)
        });
        var titles = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 2,
            Margin = Padding.Empty
        };
        titles.Controls.Add(new Label
        {
            Text = "EDR 终端安全",
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 17F),
            ForeColor = TextColor,
            Margin = Padding.Empty
        });
        titles.Controls.Add(new Label
        {
            Text = Environment.MachineName,
            AutoSize = true,
            ForeColor = MutedColor,
            Margin = new Padding(1, 2, 0, 0)
        });
        identity.Controls.Add(titles);

        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            Padding = new Padding(0, 5, 0, 0),
            Margin = Padding.Empty
        };
        var settingsButton = CreateSecondaryButton("连接设置");
        settingsButton.Click += (_, _) => ShowConnectionSettings();
        connectionBadge = new Label
        {
            Text = "尚未连接",
            AutoSize = true,
            TextAlign = ContentAlignment.MiddleCenter,
            Padding = new Padding(10, 7, 10, 7),
            BackColor = Color.FromArgb(226, 232, 240),
            ForeColor = MutedColor,
            Margin = new Padding(0, 1, 10, 0)
        };
        actions.Controls.Add(settingsButton);
        actions.Controls.Add(connectionBadge);

        header.Controls.Add(identity, 0, 0);
        header.Controls.Add(actions, 1, 0);
        return header;
    }

    private Control CreateProtectionPanel()
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Margin = new Padding(0, 0, 0, 12)
        };
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            Padding = new Padding(22, 16, 22, 14),
            Margin = Padding.Empty
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 64));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));

        protectionIcon = new PictureBox
        {
            Image = SystemIcons.Shield.ToBitmap(),
            SizeMode = PictureBoxSizeMode.Zoom,
            Dock = DockStyle.Top,
            Height = 48,
            Margin = new Padding(0, 8, 14, 0)
        };
        layout.Controls.Add(protectionIcon, 0, 0);

        var summary = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Margin = Padding.Empty
        };
        summary.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        summary.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        protectionTitle = new Label
        {
            Text = "正在检查防护状态",
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 19F),
            ForeColor = TextColor,
            Margin = new Padding(0, 7, 12, 3)
        };
        protectionSubtitle = new Label
        {
            Text = "正在检查本地 EDR 引擎和管理控制台连接。",
            AutoEllipsis = true,
            Dock = DockStyle.Fill,
            ForeColor = MutedColor,
            Margin = new Padding(1, 3, 24, 0)
        };
        summary.Controls.Add(protectionTitle, 0, 0);
        summary.Controls.Add(protectionSubtitle, 0, 1);
        layout.Controls.Add(summary, 1, 0);

        var stateTable = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 3,
            Margin = new Padding(8, 2, 0, 0)
        };
        stateTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46));
        stateTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 54));
        stateTable.RowStyles.Add(new RowStyle(SizeType.Percent, 33));
        stateTable.RowStyles.Add(new RowStyle(SizeType.Percent, 33));
        stateTable.RowStyles.Add(new RowStyle(SizeType.Percent, 34));
        stateTable.Controls.Add(StateCaption("本地引擎"), 0, 0);
        stateTable.Controls.Add(StateCaption("管理控制台"), 0, 1);
        stateTable.Controls.Add(StateCaption("同步状态"), 0, 2);
        agentStateLabel = StateValue("检查中");
        consoleStateLabel = StateValue("检查中");
        syncStateLabel = StateValue("尚未同步");
        stateTable.Controls.Add(agentStateLabel, 1, 0);
        stateTable.Controls.Add(consoleStateLabel, 1, 1);
        stateTable.Controls.Add(syncStateLabel, 1, 2);
        layout.Controls.Add(stateTable, 2, 0);

        protectionAccent = new Panel
        {
            Dock = DockStyle.Left,
            Width = 5,
            BackColor = WarningColor
        };
        panel.Controls.Add(layout);
        panel.Controls.Add(protectionAccent);
        return panel;
    }

    private Control CreateMetricsPanel()
    {
        var metrics = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 4,
            Margin = Padding.Empty
        };
        for (var i = 0; i < 4; i++)
        {
            metrics.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        }

        metrics.Controls.Add(CreateMetricCard("告警总数", out totalAlertsValue, new Padding(0, 0, 8, 12)), 0, 0);
        metrics.Controls.Add(CreateMetricCard("严重 / 高危", out importantAlertsValue, new Padding(4, 0, 4, 12)), 1, 0);
        metrics.Controls.Add(CreateMetricCard("受监控进程", out processesValue, new Padding(4, 0, 4, 12)), 2, 0);
        metrics.Controls.Add(CreateMetricCard("安全事件", out eventsValue, new Padding(8, 0, 0, 12)), 3, 0);
        return metrics;
    }

    private Control CreateAlertsPanel()
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            CellBorderStyle = TableLayoutPanelCellBorderStyle.Single,
            ColumnCount = 1,
            RowCount = 2,
            Margin = Padding.Empty
        };
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            ColumnCount = 2,
            Padding = new Padding(14, 8, 9, 6),
            Margin = Padding.Empty
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var heading = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = Padding.Empty
        };
        heading.Controls.Add(new Label
        {
            Text = "最近告警",
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 12F),
            ForeColor = TextColor,
            Margin = new Padding(0, 3, 8, 0)
        });
        alertsCountLabel = new Label
        {
            Text = "0 条",
            AutoSize = true,
            ForeColor = MutedColor,
            Margin = new Padding(0, 6, 0, 0)
        };
        heading.Controls.Add(alertsCountLabel);

        var tools = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = Padding.Empty
        };
        severityFilter = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 108,
            Margin = new Padding(0, 0, 8, 0)
        };
        severityFilter.Items.AddRange(["全部级别", "严重", "高危", "中危", "低危", "信息"]);
        severityFilter.SelectedIndex = 0;
        severityFilter.SelectedIndexChanged += (_, _) => RenderAlerts();
        refreshButton = CreateSecondaryButton("刷新");
        refreshButton.Click += async (_, _) => await RefreshNowAsync();
        tools.Controls.Add(severityFilter);
        tools.Controls.Add(refreshButton);

        header.Controls.Add(heading, 0, 0);
        header.Controls.Add(tools, 1, 0);
        panel.Controls.Add(header, 0, 0);

        alertsGrid = new DataGridView
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            MultiSelect = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            RowHeadersVisible = false,
            AutoGenerateColumns = false,
            BorderStyle = BorderStyle.None,
            BackgroundColor = Color.White,
            GridColor = Color.FromArgb(232, 237, 241),
            ColumnHeadersHeight = 36,
            ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
            EnableHeadersVisualStyles = false,
            ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableWithoutHeaderText
        };
        alertsGrid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(247, 249, 251);
        alertsGrid.ColumnHeadersDefaultCellStyle.ForeColor = MutedColor;
        alertsGrid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Color.FromArgb(247, 249, 251);
        alertsGrid.ColumnHeadersDefaultCellStyle.SelectionForeColor = MutedColor;
        alertsGrid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 9F);
        alertsGrid.DefaultCellStyle.BackColor = Color.White;
        alertsGrid.DefaultCellStyle.ForeColor = TextColor;
        alertsGrid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(224, 242, 241);
        alertsGrid.DefaultCellStyle.SelectionForeColor = TextColor;
        alertsGrid.DefaultCellStyle.Padding = new Padding(4, 0, 4, 0);
        alertsGrid.RowTemplate.Height = 34;
        alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Time", HeaderText = "时间", Width = 168 });
        alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Severity", HeaderText = "级别", Width = 78 });
        alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Rule", HeaderText = "检测规则", FillWeight = 35, AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Type", HeaderText = "事件类型", Width = 132 });
        alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Process", HeaderText = "进程 / 输出", FillWeight = 45, AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        alertsGrid.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0)
            {
                ShowAlertDetails(alertsGrid.Rows[e.RowIndex].Tag as EndpointAlert);
            }
        };
        alertsGrid.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter && alertsGrid.CurrentRow?.Tag is EndpointAlert alert)
            {
                e.SuppressKeyPress = true;
                ShowAlertDetails(alert);
            }
        };
        alertsGrid.Paint += (_, e) =>
        {
            if (alertsGrid.Rows.Count != 0)
            {
                return;
            }
            using var brush = new SolidBrush(MutedColor);
            var message = lastSnapshot is null ? "等待控制台数据" : "当前筛选条件下没有告警";
            var size = e.Graphics.MeasureString(message, Font);
            e.Graphics.DrawString(message, Font, brush,
                (alertsGrid.ClientSize.Width - size.Width) / 2,
                Math.Max(24, (alertsGrid.ClientSize.Height - size.Height) / 2));
        };
        panel.Controls.Add(alertsGrid, 0, 1);
        return panel;
    }

    private Control CreateFooter()
    {
        var footer = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            Padding = new Padding(0, 10, 0, 0),
            Margin = Padding.Empty
        };
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        lastUpdatedLabel = new Label
        {
            Text = "尚未同步",
            AutoSize = true,
            ForeColor = MutedColor,
            Margin = new Padding(0, 8, 0, 0)
        };

        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = Padding.Empty
        };
        var dashboardButton = CreatePrimaryButton("打开管理控制台");
        dashboardButton.Click += (_, _) => OpenDashboard();
        var hideButton = CreateSecondaryButton("隐藏到托盘");
        hideButton.Click += (_, _) => HideToTray();
        buttons.Controls.Add(dashboardButton);
        buttons.Controls.Add(hideButton);
        footer.Controls.Add(lastUpdatedLabel, 0, 0);
        footer.Controls.Add(buttons, 1, 0);
        return footer;
    }

    private Panel CreateMetricCard(string title, out Label valueLabel, Padding margin)
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Margin = margin,
            Padding = new Padding(16, 11, 12, 8)
        };
        valueLabel = new Label
        {
            Text = "--",
            Dock = DockStyle.Top,
            Height = 34,
            Font = new Font("Segoe UI Semibold", 20F),
            ForeColor = TextColor
        };
        panel.Controls.Add(new Label
        {
            Text = title,
            Dock = DockStyle.Bottom,
            Height = 22,
            ForeColor = MutedColor
        });
        panel.Controls.Add(valueLabel);
        return panel;
    }

    private static Label StateCaption(string text)
    {
        return new Label
        {
            Text = text,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = MutedColor,
            AutoEllipsis = true
        };
    }

    private static Label StateValue(string text)
    {
        return new Label
        {
            Text = text,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = TextColor,
            Font = new Font("Segoe UI Semibold", 9.5F),
            AutoEllipsis = true
        };
    }

    private static Button CreateSecondaryButton(string text)
    {
        var button = new Button
        {
            Text = text,
            AutoSize = true,
            MinimumSize = new Size(76, 32),
            Padding = new Padding(9, 2, 9, 2),
            BackColor = Color.White,
            ForeColor = TextColor,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderColor = BorderColor;
        return button;
    }

    private static Button CreatePrimaryButton(string text)
    {
        var button = CreateSecondaryButton(text);
        button.BackColor = Color.FromArgb(15, 118, 110);
        button.ForeColor = Color.White;
        button.FlatAppearance.BorderSize = 0;
        button.Margin = new Padding(0, 0, 8, 0);
        return button;
    }

    private void RenderSnapshot(EndpointSnapshot snapshot)
    {
        totalAlertsValue.Text = snapshot.Stats.Total.ToString("N0");
        importantAlertsValue.Text = (snapshot.Stats.SeverityCount("critical") +
            snapshot.Stats.SeverityCount("high")).ToString("N0");
        importantAlertsValue.ForeColor = snapshot.Stats.SeverityCount("critical") > 0 ||
            snapshot.Stats.SeverityCount("high") > 0 ? DangerColor : TextColor;
        processesValue.Text = snapshot.Stats.Processes.ToString("N0");
        eventsValue.Text = snapshot.Stats.Events.ToString("N0");
        lastUpdatedLabel.Text = $"上次同步：{snapshot.FetchedAt:yyyy-MM-dd HH:mm:ss}";
        RenderAlerts();
    }

    private void RenderAlerts()
    {
        if (alertsGrid is null)
        {
            return;
        }

        var selectedSeverity = severityFilter.SelectedIndex >= 0 && severityFilter.SelectedIndex < SeverityValues.Length
            ? SeverityValues[severityFilter.SelectedIndex]
            : string.Empty;
        var alerts = lastSnapshot?.Alerts ?? [];
        var filtered = string.IsNullOrEmpty(selectedSeverity)
            ? alerts
            : alerts.Where(alert => string.Equals(alert.Severity, selectedSeverity, StringComparison.OrdinalIgnoreCase)).ToList();

        alertsGrid.Rows.Clear();
        foreach (var alert in filtered)
        {
            var timestamp = alert.Timestamp == default
                ? "未知"
                : alert.Timestamp.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss");
            var rowIndex = alertsGrid.Rows.Add(
                timestamp,
                TranslateSeverity(alert.Severity),
                string.IsNullOrWhiteSpace(alert.Rule) ? "未命名规则" : alert.Rule,
                string.IsNullOrWhiteSpace(alert.EventType) ? "-" : alert.EventType,
                string.IsNullOrWhiteSpace(alert.Process) ? "-" : alert.Process);
            var row = alertsGrid.Rows[rowIndex];
            row.Tag = alert;
            row.Cells[1].Style.ForeColor = SeverityColor(alert.Severity);
            row.Cells[1].Style.Font = new Font("Segoe UI Semibold", 9F);
            row.Cells[4].ToolTipText = alert.Process;
        }
        alertsCountLabel.Text = $"{filtered.Count:N0} 条";
        alertsGrid.Invalidate();
    }

    private void UpdateProtectionState(bool consoleConnected, string connectionMessage)
    {
        agentStateLabel.Text = agentRunning ? "运行中" : "未检测到";
        agentStateLabel.ForeColor = agentRunning ? HealthyColor : DangerColor;
        consoleStateLabel.Text = consoleConnected ? "已连接" : "未连接";
        consoleStateLabel.ForeColor = consoleConnected ? HealthyColor : WarningColor;
        syncStateLabel.Text = consoleConnected && lastSnapshot is not null
            ? lastSnapshot.FetchedAt.ToString("HH:mm:ss")
            : "等待同步";

        connectionBadge.Text = consoleConnected ? "控制台在线" : "控制台离线";
        connectionBadge.BackColor = consoleConnected
            ? Color.FromArgb(209, 250, 229)
            : Color.FromArgb(254, 243, 199);
        connectionBadge.ForeColor = consoleConnected ? Color.FromArgb(4, 120, 87) : Color.FromArgb(146, 64, 14);

        if (!agentRunning)
        {
            protectionTitle.Text = "需要检查 EDR 防护";
            protectionSubtitle.Text = "未检测到本机 edr.exe 进程，请确认 EDR Agent 服务已经启动。";
            protectionTitle.ForeColor = DangerColor;
            protectionAccent.BackColor = DangerColor;
            return;
        }

        if (!consoleConnected)
        {
            protectionTitle.Text = "本地防护正在运行";
            protectionSubtitle.Text = string.IsNullOrWhiteSpace(connectionMessage)
                ? "EDR 引擎正常，正在连接管理控制台。"
                : $"EDR 引擎正常；{connectionMessage}";
            protectionTitle.ForeColor = WarningColor;
            protectionAccent.BackColor = WarningColor;
            return;
        }

        protectionTitle.Text = "此设备受到保护";
        protectionSubtitle.Text = "本地 EDR 引擎正在运行，检测数据已连接到管理控制台。";
        protectionTitle.ForeColor = HealthyColor;
        protectionAccent.BackColor = HealthyColor;
    }

    private void ShowAlertDetails(EndpointAlert? alert)
    {
        if (alert is null)
        {
            return;
        }

        var details = new Form
        {
            Text = "告警详情",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(760, 600),
            MinimumSize = new Size(560, 420),
            Font = Font,
            BackColor = CanvasColor,
            ShowInTaskbar = false
        };
        var header = new Label
        {
            Text = $"{TranslateSeverity(alert.Severity)} · {(string.IsNullOrWhiteSpace(alert.Rule) ? "未命名规则" : alert.Rule)}",
            Dock = DockStyle.Top,
            Height = 54,
            Padding = new Padding(16, 15, 16, 0),
            Font = new Font("Segoe UI Semibold", 12F),
            ForeColor = SeverityColor(alert.Severity)
        };
        var body = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            WordWrap = false,
            ScrollBars = ScrollBars.Both,
            BackColor = Color.White,
            ForeColor = TextColor,
            Font = new Font("Cascadia Mono", 9F),
            BorderStyle = BorderStyle.FixedSingle,
            Text = JsonSerializer.Serialize(alert.Raw, new JsonSerializerOptions { WriteIndented = true })
        };
        var closeButton = CreatePrimaryButton("关闭");
        closeButton.DialogResult = DialogResult.OK;
        var footer = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 52,
            FlowDirection = FlowDirection.RightToLeft,
            Padding = new Padding(12, 9, 12, 0),
            BackColor = CanvasColor
        };
        footer.Controls.Add(closeButton);
        details.Controls.Add(body);
        details.Controls.Add(header);
        details.Controls.Add(footer);
        details.AcceptButton = closeButton;
        details.CancelButton = closeButton;
        details.ShowDialog(this);
        details.Dispose();
    }

    private void OpenDashboard()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = apiClient.BaseAddress.ToString(),
                UseShellExecute = true
            });
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, $"无法打开管理控制台：{exception.Message}", "EDR 终端安全",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void HideToTray()
    {
        ShowInTaskbar = false;
        Hide();
    }

    private static bool IsAgentRunning()
    {
        try
        {
            var processes = Process.GetProcessesByName("edr");
            try
            {
                return processes.Any(process => !process.HasExited);
            }
            finally
            {
                foreach (var process in processes)
                {
                    process.Dispose();
                }
            }
        }
        catch
        {
            return false;
        }
    }

    private static string TranslateSeverity(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "critical" => "严重",
            "high" => "高危",
            "medium" => "中危",
            "low" => "低危",
            "info" => "信息",
            _ => string.IsNullOrWhiteSpace(severity) ? "未知" : severity
        };
    }

    private static Color SeverityColor(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "critical" => Color.FromArgb(185, 28, 28),
            "high" => Color.FromArgb(220, 38, 38),
            "medium" => Color.FromArgb(180, 83, 9),
            "low" => Color.FromArgb(3, 105, 161),
            _ => MutedColor
        };
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!allowClose && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            HideToTray();
            return;
        }
        base.OnFormClosing(e);
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        refreshTimer.Stop();
        refreshTimer.Dispose();
        lifetime.Cancel();
        lifetime.Dispose();
        base.OnFormClosed(e);
    }
}

internal sealed class SnapshotChangedEventArgs : EventArgs
{
    public SnapshotChangedEventArgs(EndpointSnapshot? snapshot, bool connected, string message)
    {
        Snapshot = snapshot;
        Connected = connected;
        Message = message;
    }

    public EndpointSnapshot? Snapshot { get; }
    public bool Connected { get; }
    public string Message { get; }
}
