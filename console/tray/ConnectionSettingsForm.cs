namespace EdrTray;

internal sealed class ConnectionSettingsForm : Form
{
    private readonly TextBox addressTextBox = new();
    private readonly TextBox apiKeyTextBox = new();
    private readonly Label errorLabel = new();

    public ConnectionSettingsForm(Uri currentAddress, string currentApiKey)
    {
        Text = "连接设置";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(520, 292);
        Font = new Font("Segoe UI", 9.5F);
        BackColor = Color.FromArgb(247, 249, 251);
        AutoScaleMode = AutoScaleMode.Dpi;

        addressTextBox.Text = currentAddress.GetLeftPart(UriPartial.Authority) +
            currentAddress.AbsolutePath.TrimEnd('/');
        addressTextBox.Dock = DockStyle.Fill;
        addressTextBox.AccessibleName = "控制台地址";

        apiKeyTextBox.Text = currentApiKey;
        apiKeyTextBox.Dock = DockStyle.Fill;
        apiKeyTextBox.UseSystemPasswordChar = true;
        apiKeyTextBox.AccessibleName = "只读 API 密钥";

        var showKey = new CheckBox
        {
            Text = "显示密钥",
            AutoSize = true,
            Margin = new Padding(0, 6, 0, 0)
        };
        showKey.CheckedChanged += (_, _) => apiKeyTextBox.UseSystemPasswordChar = !showKey.Checked;

        errorLabel.AutoSize = true;
        errorLabel.ForeColor = Color.FromArgb(185, 28, 28);
        errorLabel.Margin = new Padding(0, 3, 0, 0);

        var cancelButton = new Button
        {
            Text = "取消",
            DialogResult = DialogResult.Cancel,
            AutoSize = true,
            Padding = new Padding(12, 4, 12, 4)
        };
        var applyButton = new Button
        {
            Text = "应用并连接",
            AutoSize = true,
            Padding = new Padding(12, 4, 12, 4),
            BackColor = Color.FromArgb(15, 118, 110),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        applyButton.FlatAppearance.BorderSize = 0;
        applyButton.Click += ApplyButton_Click;

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 0)
        };
        buttons.Controls.Add(applyButton);
        buttons.Controls.Add(cancelButton);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(24, 20, 24, 18),
            ColumnCount = 1,
            RowCount = 9
        };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        layout.Controls.Add(new Label
        {
            Text = "连接到 EDR 管理控制台",
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 13F),
            ForeColor = Color.FromArgb(22, 32, 42),
            Margin = new Padding(0, 0, 0, 12)
        }, 0, 0);
        layout.Controls.Add(FieldLabel("控制台地址"), 0, 1);
        layout.Controls.Add(addressTextBox, 0, 2);
        layout.Controls.Add(FieldLabel("只读 API 密钥"), 0, 3);
        layout.Controls.Add(apiKeyTextBox, 0, 4);
        layout.Controls.Add(showKey, 0, 5);
        layout.Controls.Add(new Label
        {
            Text = "密钥只保存在当前进程内，退出托盘程序后会清除。",
            AutoSize = true,
            ForeColor = Color.FromArgb(91, 104, 117),
            Margin = new Padding(0, 8, 0, 0)
        }, 0, 6);
        layout.Controls.Add(errorLabel, 0, 7);
        layout.Controls.Add(buttons, 0, 8);

        Controls.Add(layout);
        AcceptButton = applyButton;
        CancelButton = cancelButton;
    }

    public string ConsoleAddress => addressTextBox.Text.Trim();
    public string ApiKey => apiKeyTextBox.Text.Trim();

    private static Label FieldLabel(string text)
    {
        return new Label
        {
            Text = text,
            AutoSize = true,
            ForeColor = Color.FromArgb(56, 69, 82),
            Margin = new Padding(0, 0, 0, 4)
        };
    }

    private void ApplyButton_Click(object? sender, EventArgs e)
    {
        if (!Uri.TryCreate(ConsoleAddress, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            errorLabel.Text = "请输入有效的 HTTP 或 HTTPS 地址。";
            addressTextBox.Focus();
            return;
        }

        DialogResult = DialogResult.OK;
        Close();
    }
}
