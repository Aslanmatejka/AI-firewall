using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using AiShield.Core.Models;

namespace AiShield.Core.Monitor;

public sealed class NetworkMonitor : IDisposable
{
    private readonly Timer _timer;
    private readonly HashSet<string> _aiDomains;
    private readonly HashSet<string> _seen = new();

    public List<NetworkConnection> AiConnections { get; private set; } = new();
    public event Action<NetworkConnection>? AiConnectionDetected;

    public NetworkMonitor(string configPath)
    {
        var json = File.ReadAllText(configPath);
        using var doc = JsonDocument.Parse(json);
        _aiDomains = doc.RootElement.GetProperty("ai_domains")
            .EnumerateArray()
            .Select(d => d.GetString()!.ToLower())
            .ToHashSet();

        _timer = new Timer(Scan, null, 0, 2000);
    }

    private static bool IsAiDomain(string host, HashSet<string> domains)
    {
        host = host.ToLower().TrimEnd('.');
        return domains.Any(d => host == d || host.EndsWith("." + d));
    }

    private void Scan(object? _)
    {
        var found = new List<NetworkConnection>();
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        var connections = properties.GetActiveTcpConnections();

        foreach (var conn in connections)
        {
            if (conn.State != TcpState.Established)
                continue;

            var remoteIp = conn.RemoteEndPoint.Address.ToString();
            string remoteHost;
            try
            {
                remoteHost = Dns.GetHostEntry(conn.RemoteEndPoint.Address).HostName;
            }
            catch
            {
                remoteHost = remoteIp;
            }

            if (!IsAiDomain(remoteHost, _aiDomains) && !IsAiDomain(remoteIp, _aiDomains))
                continue;

            var pid = GetPidForConnection(conn);
            var procName = "unknown";
            if (pid > 0)
            {
                try { procName = Process.GetProcessById(pid).ProcessName; }
                catch { /* access denied */ }
            }

            var nc = new NetworkConnection(
                pid, procName,
                conn.LocalEndPoint.ToString(),
                conn.RemoteEndPoint.ToString(),
                remoteHost, conn.State.ToString(), true);
            found.Add(nc);

            var key = $"{pid}:{conn.RemoteEndPoint}";
            if (_seen.Add(key))
                AiConnectionDetected?.Invoke(nc);
        }

        AiConnections = found;
    }

    private static int GetPidForConnection(System.Net.NetworkInformation.TcpConnectionInformation conn)
    {
        try
        {
            var table = TcpTableHelper.GetTcpTable();
            return table.FirstOrDefault(
                t => t.LocalPort == conn.LocalEndPoint.Port
                     && t.RemotePort == conn.RemoteEndPoint.Port
                     && t.RemoteAddress.Equals(conn.RemoteEndPoint.Address))
                .ProcessId;
        }
        catch
        {
            return 0;
        }
    }

    public void Dispose() => _timer.Dispose();
}

/// <summary>Minimal TCP owner-PID table via GetExtendedTcpTable.</summary>
internal static class TcpTableHelper
{
    [System.Runtime.InteropServices.DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, int reserved);

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    internal readonly record struct TcpRow(IPAddress RemoteAddress, int RemotePort, int LocalPort, int ProcessId);

    internal static List<TcpRow> GetTcpTable()
    {
        var rows = new List<TcpRow>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(ptr, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return rows;

            var count = System.Runtime.InteropServices.Marshal.ReadInt32(ptr);
            var offset = ptr + 4;
            for (var i = 0; i < count; i++)
            {
                var rowPtr = offset + (i * 24);
                var localAddr = new byte[4];
                var remoteAddr = new byte[4];
                System.Runtime.InteropServices.Marshal.Copy(rowPtr + 8, localAddr, 0, 4);
                System.Runtime.InteropServices.Marshal.Copy(rowPtr + 12, remoteAddr, 0, 4);
                var localPort = Swap(System.Net.IPAddress.NetworkToHostOrder(
                    (short)System.Runtime.InteropServices.Marshal.ReadInt16(rowPtr + 16)));
                var remotePort = Swap(System.Net.IPAddress.NetworkToHostOrder(
                    (short)System.Runtime.InteropServices.Marshal.ReadInt16(rowPtr + 18)));
                var pid = System.Runtime.InteropServices.Marshal.ReadInt32(rowPtr + 20);
                rows.Add(new TcpRow(new IPAddress(remoteAddr), remotePort, localPort, pid));
            }
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(ptr);
        }
        return rows;
    }

    private static int Swap(int port) => ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
}
