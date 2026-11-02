using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;
using WF = System.Windows.Forms;

namespace ClaudeIpGuard.UI;

/// <summary>System tray icon. Its color shows the state: green allowed, red blocked, amber paused, grey checking.</summary>
public sealed class TrayIcon : IDisposable
{
    readonly WF.NotifyIcon _icon;
    readonly GuardEngine _engine;
    readonly Action _open;
    readonly Action _exit;
    readonly System.Windows.Threading.Dispatcher _dispatcher;
    readonly Dictionary<GuardState, (Icon Icon, IntPtr Handle)> _icons = new();

    public TrayIcon(GuardEngine engine, Action open, Action exit)
    {
        _engine = engine;
        _open = open;
        _exit = exit;
        _dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;

        _icons[GuardState.Allowed] = MakeIcon(Color.FromArgb(22, 163, 74), Mark.Check);
        _icons[GuardState.Blocked] = MakeIcon(Color.FromArgb(220, 38, 38), Mark.Cross);
        _icons[GuardState.Paused] = MakeIcon(Color.FromArgb(217, 119, 6), Mark.Pause);
        _icons[GuardState.Starting] = MakeIcon(Color.FromArgb(100, 116, 139), Mark.Dots);

        _icon = new WF.NotifyIcon { Visible = true };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == WF.MouseButtons.Left) _open();
        };
        BuildMenu();
        Update();

        engine.StateChanged += () => _dispatcher.BeginInvoke(Update);
        Loc.Instance.LanguageChanged += () =>
        {
            BuildMenu();
            Update();
        };
    }

    void BuildMenu()
    {
        var L = Loc.Instance;
        var menu = new WF.ContextMenuStrip
        {
            RightToLeft = L.IsPersian ? WF.RightToLeft.Yes : WF.RightToLeft.No,
        };
        menu.Items.Add(L["Tray_Open"], null, (_, _) => _open());
        menu.Items.Add(L["Tray_CheckNow"], null, (_, _) => _engine.CheckNow());
        menu.Items.Add(new WF.ToolStripSeparator());
        menu.Items.Add(L["Tray_Exit"], null, (_, _) => _exit());
        var old = _icon.ContextMenuStrip;
        _icon.ContextMenuStrip = menu;
        old?.Dispose();
    }

    void Update()
    {
        var L = Loc.Instance;
        var state = _engine.State;
        var r = _engine.LastResult;
        var where = r != null ? $"{r.CountryName} ({r.CountryCode})" : "?";
        var text = state switch
        {
            GuardState.Allowed => L.Format("Tray_Allowed", where),
            GuardState.Blocked => L.Format("Tray_Blocked", where),
            GuardState.Paused => L["Tray_Paused"],
            _ => L["Tray_Checking"],
        };
        text = "Claude IP Guard - " + text;
        _icon.Text = text.Length > 63 ? text[..63] : text;
        _icon.Icon = _icons[state].Icon;
    }

    enum Mark { Check, Cross, Pause, Dots }

    static (Icon, IntPtr) MakeIcon(Color color, Mark mark)
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using var path = new GraphicsPath();
            path.AddLine(16, 1, 29, 6);
            path.AddLine(29, 6, 29, 15);
            path.AddBezier(29, 15, 29, 23, 23, 28, 16, 31);
            path.AddBezier(16, 31, 9, 28, 3, 23, 3, 15);
            path.AddLine(3, 15, 3, 6);
            path.CloseFigure();
            using (var fill = new SolidBrush(color)) g.FillPath(fill, path);

            using var pen = new Pen(Color.White, 3.2f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
            switch (mark)
            {
                case Mark.Check:
                    g.DrawLines(pen, new[] { new PointF(10, 16), new PointF(14.5f, 20.5f), new PointF(22, 11) });
                    break;
                case Mark.Cross:
                    g.DrawLine(pen, 11, 10, 21, 20);
                    g.DrawLine(pen, 21, 10, 11, 20);
                    break;
                case Mark.Pause:
                    g.DrawLine(pen, 12.5f, 10, 12.5f, 20);
                    g.DrawLine(pen, 19.5f, 10, 19.5f, 20);
                    break;
                default:
                    using (var dot = new SolidBrush(Color.White))
                    {
                        g.FillEllipse(dot, 8, 13, 4.5f, 4.5f);
                        g.FillEllipse(dot, 14, 13, 4.5f, 4.5f);
                        g.FillEllipse(dot, 20, 13, 4.5f, 4.5f);
                    }
                    break;
            }
        }
        var handle = bmp.GetHicon();
        return (Icon.FromHandle(handle), handle);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.ContextMenuStrip?.Dispose();
        _icon.Dispose();
        foreach (var (icon, handle) in _icons.Values)
        {
            icon.Dispose();
            DestroyIcon(handle);
        }
    }

    [DllImport("user32.dll")]
    static extern bool DestroyIcon(IntPtr handle);
}
