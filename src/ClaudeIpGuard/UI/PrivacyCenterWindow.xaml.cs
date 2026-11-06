using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;

namespace ClaudeIpGuard.UI;

public sealed class PrivacyFindingRow
{
    public PrivacyFindingRow(PrivacyFinding finding, bool persian)
    {
        Severity = persian ? finding.Severity switch { "High" => "زیاد", "Warning" => "هشدار", _ => "اطلاعات" } : finding.Severity.ToUpperInvariant();
        Title = persian ? finding.TitleFa : finding.TitleEn;
        Details = persian ? finding.DetailsFa : finding.DetailsEn;
        Advice = persian ? finding.AdviceFa : finding.AdviceEn;
        SeverityBrush = finding.Severity switch { "High" => Brushes.Firebrick, "Warning" => Brushes.DarkOrange, _ => Brushes.SeaGreen };
    }
    public string Severity { get; }
    public string Title { get; }
    public string Details { get; }
    public string Advice { get; }
    public Brush SeverityBrush { get; }
}

public partial class PrivacyCenterWindow : Window
{
    PrivacyAuditReport? _report;
    readonly ObservableCollection<PrivacyFindingRow> _rows = new();

    public PrivacyCenterWindow()
    {
        InitializeComponent();
        FindingsList.ItemsSource = _rows;
        UpdateLanguage();
        Loc.Instance.LanguageChanged += OnLanguageChanged;
        Loaded += async (_, _) => await ScanAsync();
        Closed += (_, _) => Loc.Instance.LanguageChanged -= OnLanguageChanged;
    }

    void OnLanguageChanged() => Dispatcher.Invoke(UpdateLanguage);

    void UpdateLanguage()
    {
        var fa = Loc.Instance.IsPersian;
        FlowDirection = fa ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;
        Title = fa ? "مرکز حریم خصوصی Claude" : "Claude Privacy Center";
        HeaderTitle.Text = fa ? "مرکز حریم خصوصی Claude" : "Claude Privacy Center";
        HeaderDescription.Text = fa
            ? "مسیرهای قابل‌کنترل تشخیص موقعیت را بررسی می‌کند. هیچ ابزار نرم‌افزاری نمی‌تواند ناشناس‌ماندن مطلق را تضمین کند."
            : "Audits controllable location-disclosure paths. No software can guarantee absolute anonymity.";
        AdapterLabel.Text = fa ? "رابط تونل VPN فعال" : "Active VPN tunnel interface";
        ProfileLabel.Text = fa ? "پروفایل OpenVPN" : "OpenVPN profile";
        FindingsTitle.Text = fa ? "یافته‌ها و توضیحات" : "Findings and explanations";
        ScanButton.Content = fa ? "بررسی دوباره" : "Scan again";
        ApplyButton.Content = fa ? "اعمال اصلاحات امن" : "Apply safe fixes";
        EnableKillSwitchButton.Content = fa ? "فعال‌سازی Kill Switch کامل" : "Enable full kill switch";
        RestoreFirewallButton.Content = fa ? "بازگردانی فایروال" : "Restore firewall";
        RestoreLocationButton.Content = fa ? "بازگردانی تنظیمات مکان" : "Restore location settings";
        CloseButton.Content = fa ? "بستن" : "Close";
        StatusText.Text = fa ? "در حال آماده‌سازی بررسی…" : "Preparing privacy audit…";
        StatusDetail.Text = fa
            ? "قفل Location ویندوز روی همه برنامه‌های ویندوز اثر می‌گذارد. Kill Switch نیز در حالت فعال تمام برنامه‌ها را فقط از تونل VPN عبور می‌دهد."
            : "Windows Location lockdown affects all Windows apps. The kill switch, when enabled, restricts all applications to the VPN tunnel.";
        RefreshRows();
    }

    void RefreshRows()
    {
        if (_report == null) return;
        var fa = Loc.Instance.IsPersian;
        _rows.Clear();
        foreach (var finding in _report.Findings) _rows.Add(new PrivacyFindingRow(finding, fa));
    }

    async Task ScanAsync()
    {
        ScanButton.IsEnabled = false;
        StatusText.Text = Loc.Instance.IsPersian ? "در حال بررسی تنظیمات ویندوز، Claude و OpenVPN…" : "Checking Windows, Claude and OpenVPN settings…";
        try
        {
            _report = await PrivacyAuditService.ScanAsync();
            AdapterBox.ItemsSource = _report.VpnAdapters;
            ProfileBox.ItemsSource = _report.OpenVpnConfigs;
            if (AdapterBox.Items.Count == 1) AdapterBox.SelectedIndex = 0;
            if (ProfileBox.Items.Count == 1) ProfileBox.SelectedIndex = 0;
            RefreshRows();
            var fa = Loc.Instance.IsPersian;
            StatusText.Text = _report.KillSwitchActive
                ? (fa ? "Kill Switch سراسری فعال است." : "The system-wide VPN kill switch is active.")
                : (fa ? "Kill Switch سراسری فعال نیست." : "The system-wide VPN kill switch is not active.");
            StatusDetail.Text = fa
                ? $"سیستم‌عامل: {_report.OsCaption} | آداپتورهای VPN: {_report.VpnAdapters.Count} | پروفایل‌ها: {_report.OpenVpnConfigs.Count}"
                : $"OS: {_report.OsCaption} | VPN adapters: {_report.VpnAdapters.Count} | profiles: {_report.OpenVpnConfigs.Count}";
            EnableKillSwitchButton.IsEnabled = _report.CanEnableKillSwitch && !_report.KillSwitchActive;
            RestoreFirewallButton.IsEnabled = _report.KillSwitchActive;
        }
        catch (Exception ex)
        {
            StatusText.Text = Loc.Instance.IsPersian ? "بررسی کامل نشد." : "The audit could not be completed.";
            StatusDetail.Text = ex.Message;
            _rows.Clear();
            EnableKillSwitchButton.IsEnabled = false;
            RestoreFirewallButton.IsEnabled = false;
        }
        finally { ScanButton.IsEnabled = true; }
    }

    async void Scan_Click(object sender, RoutedEventArgs e) => await ScanAsync();

    async void Apply_Click(object sender, RoutedEventArgs e)
    {
        var fa = Loc.Instance.IsPersian;
        var message = fa
            ? "این اقدام Location را برای همه برنامه‌های ویندوز مسدود می‌کند، DNS Cache را خالی می‌کند و فقط کش موقت Claude را در صورت بسته‌بودن آن پاک می‌کند. کوکی‌ها، نشست‌ها، توکن‌ها و داده حساب حذف نمی‌شوند. ادامه می‌دهی؟"
            : "This blocks Windows Location access for all Windows apps, flushes DNS cache, and clears only temporary Claude caches when Claude is closed. Cookies, sessions, tokens and account data are preserved. Continue?";
        if (MessageBox.Show(this, message, fa ? "تأیید اصلاحات" : "Confirm remediation", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunElevatedScriptAsync("Apply-PrivacyHardening.ps1", Array.Empty<string>());
        await ScanAsync();
    }

    async void EnableKillSwitch_Click(object sender, RoutedEventArgs e)
    {
        var fa = Loc.Instance.IsPersian;
        if (AdapterBox.SelectedItem is not string adapter || ProfileBox.SelectedItem is not string profile)
        {
            MessageBox.Show(this, fa ? "یک رابط VPN و یک پروفایل OpenVPN انتخاب کن." : "Select an active VPN interface and an OpenVPN profile.",
                fa ? "اطلاعات ناقص" : "Selection required", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var message = fa
            ? "این Kill Switch برای کل ویندوز است، نه فقط Claude. فقط ترافیک از رابط VPN مجاز می‌شود؛ با قطع VPN اینترنت سایر برنامه‌ها نیز مسدود می‌شود. قوانین خروجی فعلی پشتیبان‌گیری و موقتاً غیرفعال می‌شوند. ادامه می‌دهی؟"
            : "This kill switch applies to all Windows apps, not only Claude. Only traffic through the selected VPN interface is allowed; if VPN disconnects, all other internet traffic is blocked. Existing outbound allow rules will be backed up and temporarily disabled. Continue?";
        if (MessageBox.Show(this, message, fa ? "تأیید Kill Switch" : "Confirm kill switch", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunElevatedScriptAsync("Enable-VpnKillSwitch.ps1", new[] { "-VpnInterfaceAlias", adapter, "-ConfigPath", profile });
        await ScanAsync();
    }

    async void RestoreFirewall_Click(object sender, RoutedEventArgs e)
    {
        var fa = Loc.Instance.IsPersian;
        if (MessageBox.Show(this, fa ? "تنظیمات قبلی فایروال و وضعیت قوانین خروجی از نسخه پشتیبان بازیابی شود؟" : "Restore the previous firewall defaults and outbound rule states from backup?",
            fa ? "بازیابی فایروال" : "Restore firewall", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunElevatedScriptAsync("Restore-VpnKillSwitch.ps1", Array.Empty<string>());
        await ScanAsync();
    }

    async void RestoreLocation_Click(object sender, RoutedEventArgs e)
    {
        var fa = Loc.Instance.IsPersian;
        if (MessageBox.Show(this, fa ? "مقادیر قبلی سرویس و سیاست‌های مکان ویندوز از نسخه پشتیبان بازیابی شوند؟" : "Restore the previous Windows location service and policy values from backup?",
            fa ? "بازیابی تنظیمات مکان" : "Restore location settings", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunElevatedScriptAsync("Restore-PrivacyHardening.ps1", Array.Empty<string>());
        await ScanAsync();
    }

    async Task RunElevatedScriptAsync(string fileName, IEnumerable<string> arguments)
    {
        var script = Path.Combine(AppContext.BaseDirectory, "Tools", fileName);
        if (!File.Exists(script))
        {
            MessageBox.Show(this, Loc.Instance.IsPersian ? $"فایل اسکریپت پیدا نشد: {script}" : $"Script file not found: {script}",
                "Claude IP Guard", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden
            };
            foreach (var arg in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script }) psi.ArgumentList.Add(arg);
            foreach (var argument in arguments) psi.ArgumentList.Add(argument);
            using var process = Process.Start(psi);
            if (process == null) return;
            await process.WaitForExitAsync();
            if (process.ExitCode != 0)
                MessageBox.Show(this, Loc.Instance.IsPersian
                    ? "عملیات با خطا پایان یافت. گزارش را در %ProgramData%\\ClaudeIpGuard بررسی کن."
                    : "The operation failed. Check the log under %ProgramData%\\ClaudeIpGuard.",
                    "Claude IP Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            MessageBox.Show(this, Loc.Instance.IsPersian ? "درخواست دسترسی مدیریتی لغو شد؛ تغییری اعمال نشد." : "The elevation request was cancelled; no change was made.",
                "Claude IP Guard", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Claude IP Guard", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    void Close_Click(object sender, RoutedEventArgs e) => Close();
}
