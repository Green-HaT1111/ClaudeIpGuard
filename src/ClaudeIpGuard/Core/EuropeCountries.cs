namespace ClaudeIpGuard.Core;

public sealed record CountryInfo(string Code, string Name, string RegionKey);

public sealed record RegionInfoGroup(string Key, IReadOnlyList<CountryInfo> Countries);

/// <summary>Every country and territory (ISO 3166-1 alpha-2, plus Kosovo), grouped by world region.</summary>
public static class Countries
{
    static readonly (string Region, string Data)[] Raw =
    {
        ("Region_Europe",
            "AD Andorra|AL Albania|AT Austria|AX Åland Islands|BA Bosnia and Herzegovina|BE Belgium|BG Bulgaria|" +
            "BY Belarus|CH Switzerland|CY Cyprus|CZ Czechia|DE Germany|DK Denmark|EE Estonia|ES Spain|FI Finland|" +
            "FO Faroe Islands|FR France|GB United Kingdom|GG Guernsey|GI Gibraltar|GR Greece|HR Croatia|HU Hungary|" +
            "IE Ireland|IM Isle of Man|IS Iceland|IT Italy|JE Jersey|LI Liechtenstein|LT Lithuania|LU Luxembourg|" +
            "LV Latvia|MC Monaco|MD Moldova|ME Montenegro|MK North Macedonia|MT Malta|NL Netherlands|NO Norway|" +
            "PL Poland|PT Portugal|RO Romania|RS Serbia|RU Russia|SE Sweden|SI Slovenia|SJ Svalbard and Jan Mayen|" +
            "SK Slovakia|SM San Marino|UA Ukraine|VA Vatican City|XK Kosovo"),
        ("Region_NorthAmerica",
            "US United States|CA Canada|MX Mexico|GL Greenland|BM Bermuda|PM Saint Pierre and Miquelon"),
        ("Region_CentralAmerica",
            "BZ Belize|CR Costa Rica|SV El Salvador|GT Guatemala|HN Honduras|NI Nicaragua|PA Panama|" +
            "AG Antigua and Barbuda|AI Anguilla|AW Aruba|BB Barbados|BL Saint Barthélemy|BQ Caribbean Netherlands|" +
            "BS Bahamas|CU Cuba|CW Curaçao|DM Dominica|DO Dominican Republic|GD Grenada|GP Guadeloupe|HT Haiti|" +
            "JM Jamaica|KN Saint Kitts and Nevis|KY Cayman Islands|LC Saint Lucia|MF Saint Martin|MQ Martinique|" +
            "MS Montserrat|PR Puerto Rico|SX Sint Maarten|TC Turks and Caicos Islands|TT Trinidad and Tobago|" +
            "VC Saint Vincent and the Grenadines|VG British Virgin Islands|VI U.S. Virgin Islands"),
        ("Region_SouthAmerica",
            "AR Argentina|BO Bolivia|BR Brazil|CL Chile|CO Colombia|EC Ecuador|FK Falkland Islands|" +
            "GF French Guiana|GY Guyana|PE Peru|PY Paraguay|SR Suriname|UY Uruguay|VE Venezuela"),
        ("Region_MiddleEast",
            "AE United Arab Emirates|AM Armenia|AZ Azerbaijan|BH Bahrain|GE Georgia|IL Israel|IQ Iraq|IR Iran|" +
            "JO Jordan|KW Kuwait|LB Lebanon|OM Oman|PS Palestine|QA Qatar|SA Saudi Arabia|SY Syria|TR Türkiye|YE Yemen"),
        ("Region_CentralSouthAsia",
            "AF Afghanistan|BD Bangladesh|BT Bhutan|IN India|IO British Indian Ocean Territory|KG Kyrgyzstan|" +
            "KZ Kazakhstan|LK Sri Lanka|MV Maldives|NP Nepal|PK Pakistan|TJ Tajikistan|TM Turkmenistan|UZ Uzbekistan"),
        ("Region_EastAsia",
            "CN China|HK Hong Kong|JP Japan|KP North Korea|KR South Korea|MN Mongolia|MO Macao|TW Taiwan|" +
            "BN Brunei|KH Cambodia|ID Indonesia|LA Laos|MM Myanmar|MY Malaysia|PH Philippines|SG Singapore|" +
            "TH Thailand|TL Timor-Leste|VN Vietnam"),
        ("Region_Africa",
            "DZ Algeria|AO Angola|BJ Benin|BW Botswana|BF Burkina Faso|BI Burundi|CV Cape Verde|CM Cameroon|" +
            "CF Central African Republic|TD Chad|KM Comoros|CG Congo (Brazzaville)|CD Congo (Kinshasa)|" +
            "CI Côte d'Ivoire|DJ Djibouti|EG Egypt|GQ Equatorial Guinea|ER Eritrea|SZ Eswatini|ET Ethiopia|" +
            "GA Gabon|GM Gambia|GH Ghana|GN Guinea|GW Guinea-Bissau|KE Kenya|LS Lesotho|LR Liberia|LY Libya|" +
            "MG Madagascar|MW Malawi|ML Mali|MR Mauritania|MU Mauritius|YT Mayotte|MA Morocco|MZ Mozambique|" +
            "NA Namibia|NE Niger|NG Nigeria|RE Réunion|RW Rwanda|SH Saint Helena|ST São Tomé and Príncipe|" +
            "SN Senegal|SC Seychelles|SL Sierra Leone|SO Somalia|ZA South Africa|SS South Sudan|SD Sudan|" +
            "TZ Tanzania|TG Togo|TN Tunisia|UG Uganda|EH Western Sahara|ZM Zambia|ZW Zimbabwe"),
        ("Region_Oceania",
            "AU Australia|NZ New Zealand|AS American Samoa|CC Cocos (Keeling) Islands|CK Cook Islands|" +
            "CX Christmas Island|FJ Fiji|FM Micronesia|GU Guam|KI Kiribati|MH Marshall Islands|" +
            "MP Northern Mariana Islands|NC New Caledonia|NF Norfolk Island|NR Nauru|NU Niue|PF French Polynesia|" +
            "PG Papua New Guinea|PN Pitcairn Islands|PW Palau|SB Solomon Islands|TK Tokelau|TO Tonga|TV Tuvalu|" +
            "UM U.S. Outlying Islands|VU Vanuatu|WF Wallis and Futuna|WS Samoa"),
        ("Region_Other",
            "AQ Antarctica|BV Bouvet Island|GS South Georgia and South Sandwich Islands|" +
            "HM Heard and McDonald Islands|TF French Southern Territories"),
    };

    public static readonly IReadOnlyList<RegionInfoGroup> Regions = Raw
        .Select(r => new RegionInfoGroup(r.Region, r.Data.Split('|')
            .Select(e => new CountryInfo(e[..2], e[3..], r.Region))
            .OrderBy(c => c.Name, StringComparer.InvariantCulture)
            .ToList()))
        .ToList();

    public static readonly IReadOnlyDictionary<string, CountryInfo> ByCode = Regions
        .SelectMany(r => r.Countries)
        .ToDictionary(c => c.Code, StringComparer.OrdinalIgnoreCase);
}

/// <summary>Default allow-list: every European country and territory.</summary>
public static class EuropeCountries
{
    public static readonly string[] Default = Countries.Regions
        .First(r => r.Key == "Region_Europe").Countries.Select(c => c.Code).OrderBy(c => c).ToArray();
}

public static class CountryNames
{
    public static string Get(string code)
    {
        if (Countries.ByCode.TryGetValue(code, out var info)) return info.Name;
        try { return new System.Globalization.RegionInfo(code).EnglishName; }
        catch (ArgumentException) { return code.ToUpperInvariant(); }
    }
}
