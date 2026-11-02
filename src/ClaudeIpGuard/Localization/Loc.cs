using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Markup;

namespace ClaudeIpGuard.Localization;

/// <summary>English / Persian strings. Bind with {loc:T Key}; switching Language updates the UI live.</summary>
public sealed class Loc : INotifyPropertyChanged
{
    public static Loc Instance { get; } = new();

    string _language = "en";

    public event PropertyChangedEventHandler? PropertyChanged;
    public event Action? LanguageChanged;

    public string Language
    {
        get => _language;
        set
        {
            var lang = value == "fa" ? "fa" : "en";
            if (lang == _language) return;
            _language = lang;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
            LanguageChanged?.Invoke();
        }
    }

    public bool IsPersian => _language == "fa";

    public FlowDirection FlowDirection => IsPersian ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;

    public string this[string key]
    {
        get
        {
            var table = IsPersian ? Strings.Fa : Strings.En;
            if (table.TryGetValue(key, out var s)) return s;
            return Strings.En.TryGetValue(key, out var en) ? en : key;
        }
    }

    public string Format(string key, params object[] args)
    {
        try { return string.Format(CultureInfo.InvariantCulture, this[key], args); }
        catch (FormatException) { return this[key]; }
    }
}

/// <summary>XAML markup extension: Text="{loc:T Nav_Dashboard}".</summary>
[MarkupExtensionReturnType(typeof(object))]
public sealed class TExtension : MarkupExtension
{
    public TExtension() { }
    public TExtension(string key) { Key = key; }

    [ConstructorArgument("key")]
    public string Key { get; set; } = "";

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        var binding = new Binding($"[{Key}]") { Source = Loc.Instance, Mode = BindingMode.OneWay };
        return binding.ProvideValue(serviceProvider);
    }
}
