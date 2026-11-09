using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using AiShield.Core.Ipc;
using AiShield.Core.Windows;
using AiShield.TamperProbe;
using Microsoft.Win32;

// Usage:
//   as-basic-user <mode> [args]      run a mode as this user without admin rights, at medium integrity
//   whoami                           print whether this process is an administrator, and its integrity
//   attack <install dir>             try everything an AI app running as the user might, expect all to fail
//   client <op> [json args]          send one request to the service and print the reply
//   consent-isolation <desktop>      while a prompt is open, try to reach its desktop and process
return args.FirstOrDefault() switch
{
    "as-basic-user" => BasicUser.Run(args[1..]),
    "whoami" => Print(new { admin = Identity.IsAdmin(), integrity = Identity.IntegrityRid() }),
    "attack" when args.Length > 1 => Attack.Run(args[1]),
    "client" when args.Length > 1 => await Client.RunAsync(args[1], args.Length > 2 ? args[2] : null),
    "consent-isolation" when args.Length > 1 => ConsentIsolation.Run(args[1]),
    _ => Usage(),
};

static int Usage()
{
    Console.Error.WriteLine("usage: AiShield.TamperProbe as-basic-user|whoami|attack|client|consent-isolation ...");
    return 2;
}

static int Print(object value)
{
    Console.WriteLine(JsonSerializer.Serialize(value, PipeProtocol.Json));
    return 0;
}

internal sealed record CheckResult(string Name, bool Blocked, string Detail);

internal static class Attack
{
    public static int Run(string installDir)
    {
        var results = new List<CheckResult>
        {
            new("running without admin rights", !Identity.IsAdmin() && Identity.IntegrityRid() <= 0x2000,
                $"admin={Identity.IsAdmin()}, integrity=0x{Identity.IntegrityRid():x}"),
        };

        var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AiShield");
        var dashboardDir = Path.Combine(installDir, "dashboard");

        foreach (var (right, name) in new[] { (0x20u, "stop"), (0x2u, "change config"), (0x40000u, "change permissions"), (0x10000u, "delete") })
            results.Add(Expect($"service: {name}", () => Native.OpenServiceWithRights(PipeProtocol.ServiceName, right)));

        var servicePid = ServiceQuery.GetProcessId(PipeProtocol.ServiceName);
        results.Add(servicePid is null
            ? new CheckResult("service is running", false, "no service process")
            : Expect("service process: terminate or inject", () => Native.OpenProcessWithRights(servicePid.Value, 0x1 | 0x2 | 0x20 | 0x8)));

        results.Add(Expect("data folder: list", () => Directory.EnumerateFiles(dataDir).Count()));
        results.Add(Expect("data folder: read policy database", () => File.ReadAllBytes(Path.Combine(dataDir, "policy.db"))));
        results.Add(Expect("data folder: plant a file", () => File.WriteAllText(Path.Combine(dataDir, "planted.txt"), "x")));
        results.Add(Expect("data folder: change the test answer to allow", () =>
            File.Open(Path.Combine(dataDir, "test", "consent-decision.txt"), FileMode.Open, FileAccess.Write).Dispose()));

        results.Add(Expect("install folder: plant a DLL", () => File.WriteAllText(Path.Combine(dashboardDir, "version.dll"), "x")));
        results.Add(Expect("install folder: overwrite the desktop app", () =>
            File.Open(Path.Combine(dashboardDir, "AiShield.Dashboard.exe"), FileMode.Open, FileAccess.ReadWrite).Dispose()));
        results.Add(Expect("install folder: overwrite the secure prompt", () =>
            File.Open(Path.Combine(installDir, "consent", "AiShield.Consent.exe"), FileMode.Open, FileAccess.ReadWrite).Dispose()));
        results.Add(Expect("install folder: change the shipped defaults", () =>
            File.AppendAllText(Path.Combine(installDir, "config", "default.json"), " ")));

        results.Add(Expect("registry: change the service entry", () =>
            Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + PipeProtocol.ServiceName, writable: true)
                ?? throw new InvalidOperationException("key missing")));

        results.Add(Expect("pipe: open a rogue instance", () =>
            new NamedPipeServerStream(PipeProtocol.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances).Dispose()));

        results.Add(UntrustedRequest("pipe: ask from an unknown program", Environment.ProcessPath!));
        results.Add(SpoofedCopy());

        foreach (var result in results)
            Console.WriteLine($"{(result.Blocked ? "BLOCKED" : "ALLOWED")}  {result.Name}: {result.Detail}");
        return results.All(r => r.Blocked) ? 0 : 1;
    }

    /// <summary>The attempt passes the check only if Windows refuses it.</summary>
    private static CheckResult Expect(string name, Func<object?> attempt)
    {
        try
        {
            attempt();
            return new CheckResult(name, false, "succeeded");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException
            || (ex is System.ComponentModel.Win32Exception { NativeErrorCode: 5 }))
        {
            return new CheckResult(name, true, "access denied");
        }
        catch (Exception ex)
        {
            return new CheckResult(name, false, $"failed for another reason: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static CheckResult Expect(string name, Action attempt) => Expect(name, () =>
    {
        attempt();
        return null;
    });

    private static CheckResult UntrustedRequest(string name, string fromPath)
    {
        var response = new ShieldPipeClient().SendAsync(PipeOps.Status).GetAwaiter().GetResult();
        return response switch
        {
            null => new CheckResult(name, false, "couldn't reach the service at all"),
            { Ok: false, Error: PipeErrors.UntrustedClient } => new CheckResult(name, true, $"refused {fromPath}"),
            _ => new CheckResult(name, false, $"answered: ok={response.Ok} error={response.Error}"),
        };
    }

    /// <summary>A copy of a program named like the desktop app, run from somewhere else, must not be trusted.</summary>
    private static CheckResult SpoofedCopy()
    {
        const string name = "pipe: ask from a copy named AiShield.Dashboard.exe";
        var folder = Path.Combine(Path.GetTempPath(), "aishield-spoof-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var copy = Path.Combine(folder, "AiShield.Dashboard.exe");
        File.Copy(Environment.ProcessPath!, copy);
        using var process = Process.Start(new ProcessStartInfo(copy, $"client {PipeOps.Status}")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        })!;
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output.Contains(PipeErrors.UntrustedClient, StringComparison.Ordinal)
            ? new CheckResult(name, true, "refused")
            : new CheckResult(name, false, $"answered: {output.Trim()}");
    }
}

internal static class Client
{
    public static async Task<int> RunAsync(string op, string? json)
    {
        object? args = json is null ? null : JsonDocument.Parse(json).RootElement;
        var response = await new ShieldPipeClient().SendAsync(op, args, TimeSpan.FromMinutes(4)).ConfigureAwait(false);
        Console.WriteLine(response is null ? "null" : JsonSerializer.Serialize(response, PipeProtocol.Json));
        return response is null ? 3 : 0;
    }
}

internal static class ConsentIsolation
{
    public static int Run(string desktopName)
    {
        var results = new List<CheckResult>
        {
            Check($"desktop {desktopName}: open with full access", Native.TryOpenDesktop(desktopName, 0x10000000)),
            Check($"desktop {desktopName}: read its windows", Native.TryOpenDesktop(desktopName, 0x0001)),
            Check($"desktop {desktopName}: hook or send input", Native.TryOpenDesktop(desktopName, 0x0008 | 0x0020 | 0x0080)),
            Check($"desktop {desktopName}: switch to it", Native.TryOpenDesktop(desktopName, 0x0100)),
        };

        var prompts = Process.GetProcessesByName("AiShield.Consent");
        results.Add(new CheckResult("a secure prompt is running", prompts.Length > 0, $"{prompts.Length} found"));
        foreach (var prompt in prompts)
        {
            results.Add(Check($"prompt process {prompt.Id}: inject, read or terminate",
                Native.TryOpenProcess(prompt.Id, 0x1 | 0x2 | 0x8 | 0x10 | 0x20)));
            prompt.Dispose();
        }

        foreach (var result in results)
            Console.WriteLine($"{(result.Blocked ? "BLOCKED" : "ALLOWED")}  {result.Name}: {result.Detail}");
        return results.All(r => r.Blocked) ? 0 : 1;
    }

    private static CheckResult Check(string name, int? error)
        => error == 5 ? new CheckResult(name, true, "access denied") : new CheckResult(name, false, error is null ? "succeeded" : $"error {error}");
}

internal static class Identity
{
    public static bool IsAdmin() => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public static int IntegrityRid() => Native.IntegrityRid();
}
