using System.Windows;
using System.Windows.Threading;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;

namespace ClaudeIpGuard.UI;

public partial class PasswordDialog : Window
{
    readonly bool _create;
    readonly Func<string, bool>? _check;
    readonly Action? _onWrong;

    PasswordDialog(bool create, string titleKey, string descriptionKey, Func<string, bool>? check, Action? onWrong)
    {
        _create = create;
        _check = check;
        _onWrong = onWrong;
        InitializeComponent();
        Title = Loc.Instance["AppTitle"];
        TitleText.Text = Loc.Instance[titleKey];
        DescriptionText.Text = Loc.Instance[descriptionKey];
        ConfirmPanel.Visibility = create ? Visibility.Visible : Visibility.Collapsed;
        Loaded += (_, _) => Password1.Focus();
    }

    public string Password { get; private set; } = "";

    /// <summary>Asks for a new password (typed twice). Returns null if cancelled.</summary>
    public static string? ShowCreate(Window? owner, bool isChange = false)
    {
        var dlg = new PasswordDialog(true,
            isChange ? "Pwd_NewTitle" : "Pwd_CreateTitle",
            isChange ? "Pwd_NewDesc" : "Pwd_CreateDesc", null, null);
        Attach(dlg, owner);
        return dlg.ShowDialog() == true ? dlg.Password : null;
    }

    /// <summary>Asks for the current password until it is right or the user cancels.</summary>
    public static bool ShowVerify(Window? owner, string reasonKey, Func<string, bool> check, Action? onWrong)
    {
        var dlg = new PasswordDialog(false, "Pwd_EnterTitle", reasonKey, check, onWrong);
        Attach(dlg, owner);
        return dlg.ShowDialog() == true;
    }

    static void Attach(Window dlg, Window? owner)
    {
        if (owner != null && owner.IsVisible)
        {
            dlg.Owner = owner;
            dlg.WindowStartupLocation = WindowStartupLocation.CenterOwner;
        }
        else
        {
            dlg.Topmost = true;
        }
    }

    void Ok_Click(object sender, RoutedEventArgs e)
    {
        var pwd = Password1.Password;
        if (_create)
        {
            if (pwd.Length < PasswordHasher.MinLength)
            {
                ShowError("Pwd_TooShort");
                return;
            }
            if (pwd != Password2.Password)
            {
                ShowError("Pwd_Mismatch");
                return;
            }
            Password = pwd;
            DialogResult = true;
            return;
        }

        if (_check!(pwd))
        {
            DialogResult = true;
            return;
        }

        _onWrong?.Invoke();
        ShowError("Pwd_Wrong");
        Password1.Clear();
        // Slow down guessing.
        OkButton.IsEnabled = false;
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            OkButton.IsEnabled = true;
            Password1.Focus();
        };
        timer.Start();
    }

    void ShowError(string key)
    {
        ErrorText.Text = Loc.Instance[key];
        ErrorText.Visibility = Visibility.Visible;
    }
}
