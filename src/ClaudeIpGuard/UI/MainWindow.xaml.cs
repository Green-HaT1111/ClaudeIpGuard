using System.ComponentModel;
using System.Windows;
using ClaudeIpGuard.Localization;

namespace ClaudeIpGuard.UI;

public partial class MainWindow : Window
{
    readonly MainViewModel _vm;
    readonly IAppHost _host;

    public MainWindow(MainViewModel vm, IAppHost host)
    {
        _vm = vm;
        _host = host;
        InitializeComponent();
        DataContext = vm;
        (Loc.Instance.IsPersian ? LangFa : LangEn).IsChecked = true;
    }

    /// <summary>Set by the app when it really exits; otherwise closing only hides the window.</summary>
    public bool AllowClose { get; set; }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!AllowClose)
        {
            e.Cancel = true;
            Hide();
        }
        base.OnClosing(e);
    }

    void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (PageDashboard == null || PageActivity == null || PageSettings == null) return;
        var tag = (string)((FrameworkElement)sender).Tag;
        PageDashboard.Visibility = tag == "dash" ? Visibility.Visible : Visibility.Collapsed;
        PageActivity.Visibility = tag == "activity" ? Visibility.Visible : Visibility.Collapsed;
        PageSettings.Visibility = tag == "settings" ? Visibility.Visible : Visibility.Collapsed;
        if (tag == "settings") _vm.Editor.LoadFrom(_host.Settings);
    }

    void Lang_Checked(object sender, RoutedEventArgs e)
    {
        var lang = (string)((FrameworkElement)sender).Tag;
        if (lang == Loc.Instance.Language) return;
        Loc.Instance.Language = lang;
        _host.SaveLanguage(lang);
    }

    void CheckNow_Click(object sender, RoutedEventArgs e) => _vm.Engine.CheckNow();

    void PauseResume_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.Engine.IsPaused)
            _vm.Engine.Resume();
        else if (_host.VerifyPassword(this, "Pwd_Reason_Pause"))
            _vm.Engine.Pause();
    }

    void Hide_Click(object sender, RoutedEventArgs e) => Hide();

    void PrivacyCenter_Click(object sender, RoutedEventArgs e)
    {
        var window = new PrivacyCenterWindow { Owner = this };
        window.ShowDialog();
    }

    void Exit_Click(object sender, RoutedEventArgs e) => _host.RequestExit(this);

    void ClearActivity_Click(object sender, RoutedEventArgs e) => _vm.ClearActivity();

    void ResetEurope_Click(object sender, RoutedEventArgs e) => _vm.Editor.Picker.SelectEuropeOnly();

    void SelectAll_Click(object sender, RoutedEventArgs e) => _vm.Editor.Picker.SetVisible(true);

    void ClearAll_Click(object sender, RoutedEventArgs e) => _vm.Editor.Picker.SetVisible(false);

    void Revert_Click(object sender, RoutedEventArgs e) => _vm.Editor.LoadFrom(_host.Settings);

    void Save_Click(object sender, RoutedEventArgs e)
    {
        _vm.Editor.ClearMessage();
        if (!_vm.Editor.TryBuild(_host.Settings, out var updated)) return;
        if (!_host.VerifyPassword(this, "Pwd_Reason_Save")) return;
        _host.SaveSettings(updated);
        _vm.Editor.LoadFrom(_host.Settings);
        _vm.Editor.ShowMessage(false, "Msg_Saved");
        _vm.Refresh();
    }

    void ChangePassword_Click(object sender, RoutedEventArgs e)
    {
        _vm.Editor.ClearMessage();
        if (_host.ChangePassword(this)) _vm.Editor.ShowMessage(false, "Msg_PasswordChanged");
    }
}
