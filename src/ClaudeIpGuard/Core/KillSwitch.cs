using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace ClaudeIpGuard.Core;

/// <param name="On">The filters were added (state file present).</param>
/// <param name="Programs">VPN programs allowed through the real adapters.</param>
/// <param name="Adapters">Real adapters (Wi-Fi, Ethernet) that are blocked for everything else.</param>
/// <param name="OldRules">Firewall rules of the first kill switch version are still there (Turn on/off removes them).</param>
public sealed record KillSwitchState(bool On, IReadOnlyList<string> Programs, IReadOnlyList<string> Adapters, bool OldRules = false);

/// <summary>One filter the kill switch adds (kept separate so tests can check it without admin rights).</summary>
public sealed record PlannedFilter(bool IPv6, bool Permit, byte Weight, string Kind, IReadOnlyList<string> Values);

/// <summary>
/// VPN kill switch that works with any VPN (tunnel or proxy mode). It uses Windows Filtering Platform, the engine under
/// Windows Firewall, without changing any firewall setting:
///   block new connections on the real adapters (Wi-Fi, Ethernet)
///   except the VPN programs and the local network (router, DNS, DHCP).
/// Traffic that goes through a VPN adapter or to a local proxy never uses a real adapter, so it is not affected.
/// So when the VPN drops, nothing reaches the internet with the real IP, whatever the VPN server is.
/// The filters are persistent (survive a reboot) and have fixed IDs, so "off" always removes all of them.
/// Adding/removing needs admin: the app runs itself elevated with --kill-switch (see App).
/// </summary>
public static class KillSwitch
{
    static readonly Guid SubLayerKey = new("6c3f8a2e-4b1d-4e7a-9a52-1f0d7c3b9e00");
    static Guid FilterKey(int i) => new($"6c3f8a2e-4b1d-4e7a-9a52-1f0d7c3b9e{i + 1:x2}");
    const int FilterCount = 6; // 3 per IP version

    static readonly Guid LayerConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    static readonly Guid LayerConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid CondLocalInterface = new("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
    static readonly Guid CondAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid CondRemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");

    // Local network, never blocked: private ranges, link-local, CGNAT, multicast, broadcast.
    static readonly string[] LanV4 = { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32" };
    static readonly string[] LanV6 = { "fe80::/10", "fc00::/7", "ff00::/8" };

    static string StateFile => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ClaudeIpGuard", "killswitch.json");
    // Every VPN program ever allowed. Kept when the kill switch is turned off, so switching back to an earlier
    // VPN app (e.g. v2ray -> OpenVPN -> v2ray) needs no turning off again.
    static string KnownFile => Path.Combine(Path.GetDirectoryName(StateFile)!, "killswitch-known.json");

    /// <summary>VPN programs allowed at some point (no admin needed).</summary>
    public static IReadOnlyList<string> KnownPrograms()
    {
        try { return File.Exists(KnownFile) ? JsonSerializer.Deserialize<List<string>>(File.ReadAllText(KnownFile))! : new List<string>(); }
        catch { return new List<string>(); }
    }

    sealed record StateData(List<string> Programs, List<string> Adapters);

    // The first kill switch (before v2) used Windows Firewall rules with these names. They block Wi-Fi except old
    // OpenVPN servers, so they must go when the kill switch is turned off or replaced.
    static readonly string[] LegacyRules = { "Claude IP Guard kill switch (IPv4)", "Claude IP Guard kill switch (IPv6)" };

    /// <summary>Firewall rule by name, or null. A missing rule comes back as an error (0x80070002, file not found).</summary>
    static object? FindLegacyRule(dynamic policy, string name)
    {
        try { return policy.Rules.Item(name); }
        catch (Exception ex) when (ex.HResult == unchecked((int)0x80070002)) { return null; }
    }

    static bool LegacyRulePresent()
    {
        try
        {
            dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!)!;
            return LegacyRules.Any(name => FindLegacyRule(policy, name) != null);
        }
        catch (Exception ex)
        {
            CrashLog.Write("Kill switch: could not read old firewall rules", ex);
            return false;
        }
    }

    /// <summary>Removes the first kill switch's firewall rules (all copies). Needs admin.</summary>
    static void RemoveLegacyRules()
    {
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!)!;
        foreach (var name in LegacyRules)
            for (int i = 0; i < 20 && FindLegacyRule(policy, name) != null; i++)
                policy.Rules.Remove(name);
    }

    /// <summary>Reads the state (no admin needed). Old firewall rules from the first version are reported, not counted as "on".</summary>
    public static KillSwitchState Read()
    {
        try
        {
            if (!File.Exists(StateFile))
                return new KillSwitchState(false, Array.Empty<string>(), Array.Empty<string>(), LegacyRulePresent());
            var s = JsonSerializer.Deserialize<StateData>(File.ReadAllText(StateFile))!;
            return new KillSwitchState(true, s.Programs, s.Adapters);
        }
        catch (Exception ex)
        {
            CrashLog.Write("Kill switch: could not read its state", ex);
            return new KillSwitchState(false, Array.Empty<string>(), Array.Empty<string>());
        }
    }

    /// <summary>The filters for these VPN programs and real adapters (adapter names are shown, LUIDs are used).</summary>
    public static List<PlannedFilter> Plan(IReadOnlyList<string> programs, IReadOnlyList<NetAdapter> adapters)
    {
        var list = new List<PlannedFilter>();
        foreach (var v6 in new[] { false, true })
        {
            list.Add(new PlannedFilter(v6, false, 1, "adapters", adapters.Select(a => a.Name).ToList()));
            list.Add(new PlannedFilter(v6, true, 10, "programs", programs.ToList()));
            list.Add(new PlannedFilter(v6, true, 10, "lan", v6 ? LanV6 : LanV4));
        }
        return list;
    }

    /// <summary>Adds (or replaces) the filters. Needs admin. All or nothing: one transaction.</summary>
    public static void Apply(IReadOnlyList<string> programs)
    {
        if (programs.Count == 0) throw new InvalidOperationException("No VPN program to allow. Connect the VPN first.");
        var missing = programs.Where(p => !File.Exists(p)).ToList();
        if (missing.Count > 0) throw new InvalidOperationException("VPN program not found: " + string.Join(", ", missing));
        var adapters = VpnDetector.Adapters().Where(a => a.Hardware).ToList();
        if (adapters.Count == 0) throw new InvalidOperationException("No Wi-Fi or Ethernet adapter found.");
        RemoveLegacyRules();

        using var engine = Engine.Open();
        engine.Begin();
        try
        {
            RemoveAll(engine);
            engine.AddSubLayer(SubLayerKey, "Claude IP Guard kill switch");
            var plan = Plan(programs, adapters);
            for (int i = 0; i < plan.Count; i++)
            {
                var f = plan[i];
                var conditions = f.Kind switch
                {
                    "adapters" => adapters.Select(a => Condition.Luid(CondLocalInterface, a.Luid)).ToList(),
                    "programs" => programs.Select(p => Condition.AppId(CondAppId, p)).ToList(),
                    _ => f.Values.Select(r => Condition.Address(CondRemoteAddress, r)).ToList(),
                };
                try
                {
                    engine.AddFilter(FilterKey(i), f.IPv6 ? LayerConnectV6 : LayerConnectV4, f.Permit, f.Weight,
                        $"Claude IP Guard kill switch ({(f.Permit ? "allow" : "block")} {f.Kind}, IPv{(f.IPv6 ? 6 : 4)})", conditions);
                }
                finally
                {
                    foreach (var c in conditions) c.Dispose();
                }
            }
            engine.Commit();
        }
        catch
        {
            engine.Abort(); // nothing is left half done
            throw;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(StateFile)!);
        File.WriteAllText(StateFile, JsonSerializer.Serialize(new StateData(programs.ToList(), adapters.Select(a => a.Name).ToList())));
        File.WriteAllText(KnownFile, JsonSerializer.Serialize(
            KnownPrograms().Concat(programs).Distinct(StringComparer.OrdinalIgnoreCase).ToList()));
    }

    /// <summary>Removes every filter of the kill switch. Needs admin.</summary>
    public static void Remove()
    {
        RemoveLegacyRules();
        using var engine = Engine.Open();
        engine.Begin();
        try
        {
            RemoveAll(engine);
            engine.Commit();
        }
        catch
        {
            engine.Abort();
            throw;
        }
        // Remember the programs that were allowed, so turning on again later still includes them.
        var allowed = Read().Programs;
        if (allowed.Count > 0)
            File.WriteAllText(KnownFile, JsonSerializer.Serialize(
                KnownPrograms().Concat(allowed).Distinct(StringComparer.OrdinalIgnoreCase).ToList()));
        File.Delete(StateFile);
    }

    static void RemoveAll(Engine engine)
    {
        for (int i = 0; i < FilterCount; i++) engine.DeleteFilter(FilterKey(i));
        engine.DeleteSubLayer(SubLayerKey);
    }

    // ---------- run elevated ----------

    /// <summary>
    /// Starts this app as admin (Windows asks) to turn the kill switch on or off. Returns null on success,
    /// "cancelled" when the user said no to Windows, or the error text.
    /// </summary>
    public static string? RunElevated(bool on, IReadOnlyList<string> programs)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("App path unknown");
        var packed = Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("\n", programs)));
        var args = on ? $"--kill-switch on {packed}" : "--kill-switch off";
        try
        {
            File.Delete(HelperErrorFile);
            using var p = Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true, Verb = "runas" })!;
            p.WaitForExit();
            if (p.ExitCode == 0) return null;
            // The helper leaves its error message here (same user, same temp folder).
            var message = File.Exists(HelperErrorFile) ? File.ReadAllText(HelperErrorFile).Trim() : "";
            return message.Length > 0 ? message : $"exit code {p.ExitCode}";
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return "cancelled";
        }
    }

    /// <summary>The elevated side: "--kill-switch on PROGRAMS" or "--kill-switch off". Returns the exit code.</summary>
    public static int RunHelper(string[] args)
    {
        try
        {
            if (args.Length >= 3 && args[1] == "on")
                Apply(Encoding.UTF8.GetString(Convert.FromBase64String(args[2])).Split('\n', StringSplitOptions.RemoveEmptyEntries));
            else if (args.Length >= 2 && args[1] == "off") Remove();
            else return 2;
            return 0;
        }
        catch (Exception ex)
        {
            CrashLog.Write("Kill switch helper failed", ex);
            try { File.WriteAllText(HelperErrorFile, ex.Message); } catch { }
            return 1;
        }
    }

    static string HelperErrorFile => Path.Combine(Path.GetTempPath(), "ClaudeIpGuard-killswitch-error.txt");

    // ---------- Windows Filtering Platform (fwpuclnt.dll) ----------
    // Struct layouts match the Windows SDK on x64 (FWPM_FILTER0 = 200 bytes, FWPM_FILTER_CONDITION0 = 40, FWPM_SUBLAYER0 = 72).

    const uint FWP_UINT8 = 1, FWP_UINT64 = 4, FWP_BYTE_BLOB_TYPE = 12, FWP_V4_ADDR_MASK = 0x100, FWP_V6_ADDR_MASK = 0x101;
    const uint FWP_ACTION_BLOCK = 0x1001, FWP_ACTION_PERMIT = 0x1002, PERSISTENT = 1;
    const uint FWP_E_FILTER_NOT_FOUND = 0x80320003, FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;

    /// <summary>A filter condition with its value in unmanaged memory (freed by Dispose).</summary>
    sealed class Condition : IDisposable
    {
        public readonly Guid Field;
        public readonly uint Type;
        public IntPtr Value;
        readonly bool _wfpOwned;

        Condition(Guid field, uint type, IntPtr value, bool wfpOwned) { Field = field; Type = type; Value = value; _wfpOwned = wfpOwned; }

        public static Condition Luid(Guid field, ulong luid)
        {
            var p = Marshal.AllocHGlobal(8);
            Marshal.WriteInt64(p, (long)luid);
            return new Condition(field, FWP_UINT64, p, false);
        }

        public static Condition AppId(Guid field, string path)
        {
            Check(FwpmGetAppIdFromFileName0(path, out var blob), $"app id of {path}");
            return new Condition(field, FWP_BYTE_BLOB_TYPE, blob, true);
        }

        /// <summary>"192.168.0.0/16" or "fe80::/10".</summary>
        public static Condition Address(Guid field, string cidr)
        {
            var slash = cidr.IndexOf('/');
            var ip = IPAddress.Parse(cidr[..slash]);
            var bits = int.Parse(cidr[(slash + 1)..]);
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                // FWP_V4_ADDR_AND_MASK: address and mask in host byte order.
                var b = ip.GetAddressBytes();
                var p = Marshal.AllocHGlobal(8);
                Marshal.WriteInt32(p, 0, b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
                Marshal.WriteInt32(p, 4, bits == 0 ? 0 : unchecked((int)(uint.MaxValue << (32 - bits))));
                return new Condition(field, FWP_V4_ADDR_MASK, p, false);
            }
            // FWP_V6_ADDR_AND_MASK: 16 address bytes + prefix length.
            var p6 = Marshal.AllocHGlobal(17);
            Marshal.Copy(ip.GetAddressBytes(), 0, p6, 16);
            Marshal.WriteByte(p6, 16, (byte)bits);
            return new Condition(field, FWP_V6_ADDR_MASK, p6, false);
        }

        public void Dispose()
        {
            if (Value == IntPtr.Zero) return;
            if (_wfpOwned) FwpmFreeMemory0(ref Value);
            else Marshal.FreeHGlobal(Value);
            Value = IntPtr.Zero;
        }
    }

    sealed class Engine : IDisposable
    {
        IntPtr _handle;

        public static Engine Open()
        {
            Check(FwpmEngineOpen0(null, 10 /* RPC_C_AUTHN_WINNT */, IntPtr.Zero, IntPtr.Zero, out var h), "open filtering engine");
            return new Engine { _handle = h };
        }

        public void Begin() => Check(FwpmTransactionBegin0(_handle, 0), "begin");
        public void Commit() => Check(FwpmTransactionCommit0(_handle), "commit");
        public void Abort() => FwpmTransactionAbort0(_handle);

        public void AddSubLayer(Guid key, string name)
        {
            var s = new FWPM_SUBLAYER0 { subLayerKey = key, name = name, description = name, flags = PERSISTENT, weight = 0x100 };
            Check(FwpmSubLayerAdd0(_handle, ref s, IntPtr.Zero), "add sublayer");
        }

        public void AddFilter(Guid key, Guid layer, bool permit, byte weight, string name, IReadOnlyList<Condition> conditions)
        {
            var size = Marshal.SizeOf<FWPM_FILTER_CONDITION0>();
            var array = Marshal.AllocHGlobal(size * conditions.Count);
            try
            {
                for (int i = 0; i < conditions.Count; i++)
                    Marshal.StructureToPtr(new FWPM_FILTER_CONDITION0
                    {
                        fieldKey = conditions[i].Field, matchType = 0 /* FWP_MATCH_EQUAL */,
                        valueType = conditions[i].Type, value = conditions[i].Value,
                    }, array + i * size, false);
                var f = new FWPM_FILTER0
                {
                    filterKey = key, name = name, description = name, flags = PERSISTENT,
                    layerKey = layer, subLayerKey = SubLayerKey,
                    weightType = FWP_UINT8, weightValue = weight,
                    numFilterConditions = (uint)conditions.Count, filterCondition = array,
                    actionType = permit ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK,
                };
                Check(FwpmFilterAdd0(_handle, ref f, IntPtr.Zero, out _), $"add filter \"{name}\"");
            }
            finally
            {
                Marshal.FreeHGlobal(array);
            }
        }

        public void DeleteFilter(Guid key)
        {
            var r = FwpmFilterDeleteByKey0(_handle, ref key);
            if (r != 0 && r != FWP_E_FILTER_NOT_FOUND) Check(r, "delete filter");
        }

        public void DeleteSubLayer(Guid key)
        {
            var r = FwpmSubLayerDeleteByKey0(_handle, ref key);
            if (r != 0 && r != FWP_E_SUBLAYER_NOT_FOUND) Check(r, "delete sublayer");
        }

        public void Dispose()
        {
            if (_handle != IntPtr.Zero) FwpmEngineClose0(_handle);
            _handle = IntPtr.Zero;
        }
    }

    static void Check(uint result, string what)
    {
        if (result != 0) throw new InvalidOperationException($"Windows Filtering Platform: {what} failed (0x{result:X8}).");
    }

    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
    struct FWPM_FILTER_CONDITION0
    {
        [FieldOffset(0)] public Guid fieldKey;
        [FieldOffset(16)] public uint matchType;
        [FieldOffset(24)] public uint valueType;     // FWP_CONDITION_VALUE0.type
        [FieldOffset(32)] public IntPtr value;       // FWP_CONDITION_VALUE0 union (pointer to the value)
    }

    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode, Size = 200)]
    struct FWPM_FILTER0
    {
        [FieldOffset(0)] public Guid filterKey;
        [FieldOffset(16), MarshalAs(UnmanagedType.LPWStr)] public string name;
        [FieldOffset(24), MarshalAs(UnmanagedType.LPWStr)] public string description;
        [FieldOffset(32)] public uint flags;
        [FieldOffset(40)] public IntPtr providerKey;
        [FieldOffset(48)] public uint providerDataSize;
        [FieldOffset(56)] public IntPtr providerData;
        [FieldOffset(64)] public Guid layerKey;
        [FieldOffset(80)] public Guid subLayerKey;
        [FieldOffset(96)] public uint weightType;    // FWP_VALUE0.type
        [FieldOffset(104)] public ulong weightValue; // FWP_VALUE0 union (uint8 weight)
        [FieldOffset(112)] public uint numFilterConditions;
        [FieldOffset(120)] public IntPtr filterCondition;
        [FieldOffset(128)] public uint actionType;
        [FieldOffset(132)] public Guid actionFilterType;
        [FieldOffset(152)] public Guid providerContextKey;
        [FieldOffset(168)] public IntPtr reserved;
        [FieldOffset(176)] public ulong filterId;
        [FieldOffset(184)] public uint effectiveWeightType;
        [FieldOffset(192)] public ulong effectiveWeightValue;
    }

    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode, Size = 72)]
    struct FWPM_SUBLAYER0
    {
        [FieldOffset(0)] public Guid subLayerKey;
        [FieldOffset(16), MarshalAs(UnmanagedType.LPWStr)] public string name;
        [FieldOffset(24), MarshalAs(UnmanagedType.LPWStr)] public string description;
        [FieldOffset(32)] public uint flags;
        [FieldOffset(40)] public IntPtr providerKey;
        [FieldOffset(48)] public uint providerDataSize;
        [FieldOffset(56)] public IntPtr providerData;
        [FieldOffset(64)] public ushort weight;
    }

    /// <summary>For tests: the struct sizes must match Windows (200, 40, 72 on x64).</summary>
    public static (int Filter, int Condition, int SubLayer) StructSizes() =>
        (Marshal.SizeOf<FWPM_FILTER0>(), Marshal.SizeOf<FWPM_FILTER_CONDITION0>(), Marshal.SizeOf<FWPM_SUBLAYER0>());

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engineHandle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engineHandle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engineHandle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr p);
}
