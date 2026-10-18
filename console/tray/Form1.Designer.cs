#nullable enable

namespace EdrTray;

partial class Form1
{
    private System.ComponentModel.IContainer? components;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            components?.Dispose();
        }
        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        components = new System.ComponentModel.Container();
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        BackColor = Color.FromArgb(244, 247, 249);
        ClientSize = new Size(1024, 700);
        Font = new Font("Segoe UI", 9.5F);
        Icon = SystemIcons.Shield;
        MinimumSize = new Size(820, 610);
        Name = "EndpointStatusForm";
        StartPosition = FormStartPosition.CenterScreen;
        Text = "EDR 终端安全";
        ResumeLayout(false);
    }
}
