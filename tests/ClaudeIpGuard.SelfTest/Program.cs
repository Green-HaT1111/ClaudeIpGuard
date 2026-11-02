// Self-test for Claude IP Guard. Never touches Claude: the kill tests target Notepad.
//   dotnet run --project tests\ClaudeIpGuard.SelfTest [-- <folder for UI screenshots>]
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using ClaudeIpGuard.Core;
using ClaudeIpGuard.Localization;
using ClaudeIpGuard.UI;

int failures = 0;
void Check(bool ok, string name)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}");
    if (!ok) failures++;
}

var tempData = Path.Combine(Path.GetTempPath(), "ClaudeIpGuardSelfTest");
AppPaths.DataDirectory = tempData;

// 1. Settings + password
{
    var store = new SettingsStore("t.json", tempData);
    var s = new AppSettings();
    PasswordHasher.SetPassword(s, "secret1");
    store.Save(s);
    var loaded = store.Load();
    Check(PasswordHasher.Verify(loaded, "secret1"), "password verifies after save/load");
    Check(!PasswordHasher.Verify(loaded, "wrong"), "wrong password rejected");
    Check(!File.ReadAllText(store.FilePath).Contains("secret1"), "password not stored in plain text");
    Check(loaded.AllowedCountries.Contains("DE") && !loaded.AllowedCountries.Contains("US"), "default list is Europe");
    var all = Countries.Regions.SelectMany(r => r.Countries).ToList();
    Console.WriteLine($"      country list: {all.Count} countries in {Countries.Regions.Count} regions");
    Check(all.Count >= 245 && all.Select(c => c.Code).Distinct().Count() == all.Count, "full world list, no duplicate codes");
    Check(EuropeCountries.Default.Length == 53, "Europe region has 53 entries");

    var picker = new CountryPicker();
    picker.SetSelection(new[] { "GB", "US", "CA", "DE" });
    Check(picker.SelectedCodes.SequenceEqual(new[] { "CA", "DE", "GB", "US" }), "picker: pick UK, USA, Canada, Germany");
    var na = picker.Regions.First(r => r.Countries.Any(c => c.Code == "US"));
    Check(na.IsChecked == null && na.CountText == "2/6", "picker: region shows partial selection");
    na.IsChecked = true;
    Check(na.IsChecked == true && picker.SelectedCodes.Contains("MX"), "picker: ticking a region selects all its countries");
    na.IsChecked = false;
    Check(!picker.SelectedCodes.Contains("US") && picker.SelectedCodes.Contains("GB"), "picker: unticking a region clears only that region");
    picker.SearchText = "japan";
    Check(picker.Regions.Count(r => r.Visibility == Visibility.Visible) == 1, "picker: search filters to matching region");
    picker.SetVisible(true);
    picker.SearchText = "";
    Check(picker.SelectedCodes.SequenceEqual(new[] { "DE", "GB", "JP" }), "picker: select all applies to search results only");
}

// 2. Classification of Claude processes
Check(ProcessGuard.IsDesktopPath(@"C:\Program Files\WindowsApps\Claude_4.4212.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe"), "Store desktop path detected");
Check(ProcessGuard.IsDesktopPath(@"C:\Users\x\AppData\Local\AnthropicClaude\app-1.0\claude.exe"), "classic desktop path detected");
Check(!ProcessGuard.IsDesktopPath(@"C:\Users\x\.local\bin\claude.exe"), "CLI path is not desktop");
Check(ProcessGuard.IsClaudeCliCommandLine(@"node C:\npm\node_modules\@anthropic-ai\claude-code\cli.js"), "npm CLI command line detected");

// 3. Live IP lookup
using (var geo = new GeoIpService())
{
    try
    {
        var r = await geo.LocateAsync(CancellationToken.None);
        Console.WriteLine($"      live result: {r.Ip} -> {r.CountryName} ({r.CountryCode}), {r.City}, via {r.Provider}");
        Check(r.CountryCode.Length == 2, "live IP + country lookup");
        var sw = Stopwatch.StartNew();
        await geo.LocateAsync(CancellationToken.None);
        Console.WriteLine($"      second (cached country) lookup took {sw.ElapsedMilliseconds} ms");
    }
    catch (Exception ex)
    {
        Check(false, "live IP + country lookup: " + ex.Message);
    }
}

// 4. Engine against Notepad
async Task<bool> NotepadAliveAfter(GuardEngine engine, int ms)
{
    await Task.Delay(ms);
    return Process.GetProcessesByName("notepad").Length > 0;
}
void KillNotepads()
{
    foreach (var p in Process.GetProcessesByName("notepad")) { try { p.Kill(); } catch { } }
    Thread.Sleep(300);
}

KillNotepads();
// The user's example: only UK, USA, Canada and Germany are allowed.
var settings = new AppSettings { AllowedCountries = new() { "GB", "US", "CA", "DE" } };
var locator = new SimulatedLocator("FR", false);
var engine = new GuardEngine(() => settings, locator, new ProcessGuard(new[] { "notepad" }));
var log = new List<string>();
engine.Activity += e => log.Add(Loc.Instance.Format(e.Key, e.Args));

Process.Start("notepad.exe");
await Task.Delay(800);
engine.Start();
Check(!await NotepadAliveAfter(engine, 3000), "France (not picked): target closed");
Process.Start("notepad.exe");
Check(!await NotepadAliveAfter(engine, 2500), "relaunched target closed again while blocked");

locator.Country = "US";
engine.CheckNow();
await Task.Delay(1000);
Process.Start("notepad.exe");
Check(await NotepadAliveAfter(engine, 3000), "United States (picked): target left running");

locator.Country = "CA";
engine.CheckNow();
Check(await NotepadAliveAfter(engine, 2500), "Canada (picked): target left running");

locator.Country = "DE";
engine.CheckNow();
Check(await NotepadAliveAfter(engine, 2500), "Germany (picked): target left running");

locator.Fail = true;
engine.CheckNow();
Check(!await NotepadAliveAfter(engine, 3000), "lookup failure + fail-safe: target closed");

settings.FailSafeBlock = false;
Process.Start("notepad.exe");
Check(await NotepadAliveAfter(engine, 2500), "lookup failure without fail-safe: target left running");
settings.FailSafeBlock = true;

engine.Pause();
Check(await NotepadAliveAfter(engine, 2500), "paused: target left running");
engine.Resume();
Check(!await NotepadAliveAfter(engine, 2500), "resumed: target closed");
Check(engine.KillCount >= 4, $"kill counter = {engine.KillCount}");
engine.Dispose();
KillNotepads();
Console.WriteLine("      activity log:");
foreach (var line in log) Console.WriteLine("        " + line);

// 5. Render the dashboard (English + Persian) to PNG files
var shotDir = args.Length > 0 ? args[0] : null;
if (shotDir != null)
{
    var thread = new Thread(() =>
    {
        try
        {
            var app = new ClaudeIpGuard.App();
            app.InitializeComponent();
            var uiSettings = new AppSettings { AllowedCountries = new() { "GB", "US", "CA", "DE" } };
            var host = new FakeHost(uiSettings);
            var uiEngine = new GuardEngine(() => uiSettings, new SimulatedLocator("DE", false), new ProcessGuard(new[] { "no-such-process" }));
            var vm = new MainViewModel(uiEngine, host, testMode: false);
            var win = new MainWindow(vm, host) { Left = -20000, Top = -20000, ShowActivated = false, Width = 1040, Height = 700 };
            win.Show();
            uiEngine.Start();
            Pump(2500);
            Save(win, Path.Combine(shotDir, "dashboard-en.png"));
            win.NavSettings.IsChecked = true;
            Pump(300);
            foreach (var r in vm.Editor.Picker.Regions.Take(2)) r.IsExpanded = true;
            Pump(300);
            win.PageSettings.ScrollToVerticalOffset(330);
            Pump(300);
            Save(win, Path.Combine(shotDir, "settings-en.png"));
            vm.Editor.Picker.SearchText = "korea";
            Pump(300);
            Save(win, Path.Combine(shotDir, "settings-search.png"));
            vm.Editor.Picker.SearchText = "";
            Loc.Instance.Language = "fa";
            Pump(400);
            Save(win, Path.Combine(shotDir, "settings-fa.png"));
            Loc.Instance.Language = "en";
            win.NavActivity.IsChecked = true;
            Pump(300);
            Save(win, Path.Combine(shotDir, "activity-en.png"));
            Loc.Instance.Language = "fa";
            win.NavDashboard.IsChecked = true;
            uiEngine.Pause();
            Pump(500);
            Save(win, Path.Combine(shotDir, "dashboard-fa-paused.png"));
            Loc.Instance.Language = "en";
            uiEngine.Dispose();
            win.AllowClose = true;
            win.Close();
            Console.WriteLine("PASS  UI rendered to " + shotDir);
        }
        catch (Exception ex)
        {
            Console.WriteLine("FAIL  UI render: " + ex);
            failures++;
        }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    thread.Join();
}

Console.WriteLine(failures == 0 ? "ALL TESTS PASSED" : $"{failures} TEST(S) FAILED");
return failures == 0 ? 0 : 1;

static void Pump(int ms)
{
    var end = DateTime.Now.AddMilliseconds(ms);
    while (DateTime.Now < end)
    {
        var frame = new System.Windows.Threading.DispatcherFrame();
        System.Windows.Threading.Dispatcher.CurrentDispatcher.BeginInvoke(
            System.Windows.Threading.DispatcherPriority.Background, new Action(() => frame.Continue = false));
        System.Windows.Threading.Dispatcher.PushFrame(frame);
        Thread.Sleep(30);
    }
}

static void Save(Window win, string path)
{
    var content = (FrameworkElement)win.Content;
    var dpi = VisualTreeHelper.GetDpi(content);
    var rtb = new RenderTargetBitmap((int)(content.ActualWidth * dpi.DpiScaleX), (int)(content.ActualHeight * dpi.DpiScaleY),
        dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
    content.UpdateLayout();
    rtb.Render(content);
    BitmapSource img = rtb;
    // RenderTargetBitmap draws right-to-left content mirrored; flip it back.
    if (win.FlowDirection == FlowDirection.RightToLeft)
        img = new TransformedBitmap(rtb, new ScaleTransform(-1, 1));
    var enc = new PngBitmapEncoder();
    enc.Frames.Add(BitmapFrame.Create(img));
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    using var fs = File.Create(path);
    enc.Save(fs);
}

sealed class FakeHost : IAppHost
{
    public FakeHost(AppSettings s) => Settings = s;
    public AppSettings Settings { get; }
    public bool VerifyPassword(Window? owner, string reasonKey) => true;
    public bool ChangePassword(Window? owner) => true;
    public void SaveSettings(AppSettings settings) { }
    public void SaveLanguage(string language) { }
    public void RequestExit(Window? owner) { }
}
