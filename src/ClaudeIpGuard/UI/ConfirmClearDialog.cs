using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using ClaudeIpGuard.Localization;

namespace ClaudeIpGuard.UI;

/// <summary>One block of the confirmation: a heading and its lines (items to clear, or sites).</summary>
public sealed record ConfirmSection(string Header, IReadOnlyList<string> Lines, bool IsWarning);

/// <summary>
/// Final question before browser data is deleted. Shows what will be cleared and, in red, every website
/// you would be signed out of. Long site lists scroll.
/// </summary>
public static class ConfirmClearDialog
{
    public static bool Show(Window owner, string title, string intro, IReadOnlyList<ConfirmSection> sections, string okText, string cancelText)
    {
        var L = Loc.Instance;
        Brush Res(string key, string fallback) =>
            Application.Current?.TryFindResource(key) as Brush ?? new SolidColorBrush((Color)ColorConverter.ConvertFromString(fallback));

        var win = new Window
        {
            Title = title,
            Owner = owner,
            Width = 640,
            Height = 600,
            MinWidth = 420,
            MinHeight = 320,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ShowInTaskbar = false,
            FlowDirection = L.FlowDirection,
            FontFamily = new FontFamily("Segoe UI"),
            Background = Res("BgBrush", "#F1F5F9"),
        };

        var ok = new Button { Content = okText, Margin = new Thickness(0, 0, 8, 0), MinWidth = 110 };
        var cancel = new Button { Content = cancelText, IsCancel = true, IsDefault = true, MinWidth = 110 };
        if (Application.Current?.TryFindResource("PrimaryButton") is Style primary) ok.Style = primary;
        if (Application.Current?.TryFindResource("SecondaryButton") is Style secondary) cancel.Style = secondary;
        var result = false;
        ok.Click += (_, _) => { result = true; win.Close(); };

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 14, 0, 0) };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);

        var list = new StackPanel();
        foreach (var s in sections)
        {
            var box = new StackPanel();
            box.Children.Add(new TextBlock
            {
                Text = s.Header,
                FontWeight = FontWeights.SemiBold,
                FontSize = 13.5,
                TextWrapping = TextWrapping.Wrap,
                Foreground = s.IsWarning ? Res("DangerBrush", "#DC2626") : Res("TextBrush", "#0F172A"),
                Margin = new Thickness(0, 0, 0, 6),
            });
            box.Children.Add(new TextBlock
            {
                Text = string.Join(Environment.NewLine, s.Lines.Select(l => "• " + l)),
                FontSize = 13,
                TextWrapping = TextWrapping.Wrap,
                Foreground = Res("TextBrush", "#0F172A"),
            });
            var card = new Border
            {
                Child = box,
                Background = s.IsWarning ? new SolidColorBrush(Color.FromRgb(0xFE, 0xF2, 0xF2)) : Brushes.White,
                BorderBrush = s.IsWarning ? new SolidColorBrush(Color.FromRgb(0xFC, 0xA5, 0xA5)) : Res("LineBrush", "#E2E8F0"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(14, 10, 14, 12),
                Margin = new Thickness(0, 0, 0, 10),
            };
            list.Children.Add(card);
        }

        var root = new DockPanel { Margin = new Thickness(20) };
        DockPanel.SetDock(buttons, Dock.Bottom);
        root.Children.Add(buttons);
        var header = new TextBlock { Text = intro, TextWrapping = TextWrapping.Wrap, FontSize = 14, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 12) };
        DockPanel.SetDock(header, Dock.Top);
        root.Children.Add(header);
        root.Children.Add(new ScrollViewer { Content = list, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        win.Content = root;
        win.ShowDialog();
        return result;
    }
}
