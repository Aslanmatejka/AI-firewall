using System.IO.Pipes;
using System.Security.AccessControl;
using System.Text.Json;
using AiShield.Core.Broker;
using AiShield.Core.Ipc;
using AiShield.Core.Security;
using AiShield.Core.Windows;
using Microsoft.Win32;

namespace AiShield.Service.Ipc;

/// <summary>Works out who is connecting, from what Windows reports rather than what the caller claims.</summary>
internal sealed class ClientVerifier(ServiceLayout layout)
{
    public PipeCaller Identify(NamedPipeServerStream pipe)
    {
        var pid = NativeProcess.GetPipeClientProcessId(pipe.SafePipeHandle) ?? 0;
        var session = NativeProcess.GetPipeClientSessionId(pipe.SafePipeHandle) ?? -1;
        var image = pid > 0 ? NativeProcess.TryGetImagePath(pid) : null;

        // Trust needs a protected install, so nobody but an administrator can swap the trusted program's files.
        var trusted = layout.InstallProtected
            && session > 0
            && image is not null
            && layout.TrustedClientImages.Contains(Path.GetFullPath(image), StringComparer.OrdinalIgnoreCase);
        return new PipeCaller(pid, session, image, trusted);
    }
}

/// <summary>
/// Serves the pipe under a random name it publishes for the desktop app. Unknown programs get a small,
/// separate budget of connections and bytes, so flooding the pipe can't starve the desktop app or
/// exhaust the service's memory.
/// </summary>
internal sealed class PipeServer(ShieldBroker broker, ClientVerifier verifier, ServiceLayout layout, ILogger<PipeServer> log) : CriticalService(log)
{
    private const int Listeners = 4;
    private const int MaxTrustedConnections = 32;
    private const int MaxUntrustedConnections = 8;
    private const int MaxInstances = Listeners + MaxTrustedConnections + MaxUntrustedConnections + 8;
    private const int BufferBytes = 4 * 1024;
    private static readonly TimeSpan RequestReadTimeout = TimeSpan.FromSeconds(5);

    private readonly string _pipeName = PipeProtocol.NewPipeName();
    private int _trusted;
    private int _untrusted;
    private long _lastRefusalLog;

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        // The name is new and random, so nobody can have taken it first. Refuse to share it anyway.
        var first = CreateInstance(firstInstance: true);
        Publish(_pipeName);
        log.LogInformation("Listening on pipe {Pipe}", _pipeName);
        try
        {
            var loops = Enumerable.Range(0, Listeners)
                .Select(i => ListenAsync(i == 0 ? first : null, stoppingToken))
                .ToArray();
            await Task.WhenAll(loops).ConfigureAwait(false);
        }
        finally
        {
            Publish(null);
        }
    }

    /// <summary>Tells clients where to connect. Only SYSTEM and administrators can change this key.</summary>
    private void Publish(string? name)
    {
        try
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hive.CreateSubKey(PipeProtocol.RegistryKey, writable: true);
            if (name is null)
                key.DeleteValue(PipeProtocol.RegistryValue, throwOnMissingValue: false);
            else
                key.SetValue(PipeProtocol.RegistryValue, name, RegistryValueKind.String);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            // Run from a console without admin rights, the name only appears in the log.
            log.LogWarning("Couldn't publish the pipe name {Pipe}: {Reason}", name, ex.Message);
        }
    }

    private async Task ListenAsync(NamedPipeServerStream? initial, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream server;
            try
            {
                server = initial ?? CreateInstance(firstInstance: false);
            }
            catch (IOException)
            {
                // Every instance is busy. Wait for one to free up rather than fail.
                await Task.Delay(TimeSpan.FromMilliseconds(250), ct).ConfigureAwait(false);
                continue;
            }
            initial = null;
            try
            {
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await server.DisposeAsync().ConfigureAwait(false);
                return;
            }
            catch (IOException ex)
            {
                log.LogDebug(ex, "A pipe connection failed before it started");
                await server.DisposeAsync().ConfigureAwait(false);
                continue;
            }
            _ = Task.Run(() => ServeAsync(server, ct), CancellationToken.None);
        }
    }

    private async Task ServeAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        await using (server.ConfigureAwait(false))
        {
            var caller = verifier.Identify(server);
            ref var active = ref caller.Trusted ? ref _trusted : ref _untrusted;
            var limit = caller.Trusted ? MaxTrustedConnections : MaxUntrustedConnections;
            if (Interlocked.Increment(ref active) > limit)
            {
                Interlocked.Decrement(ref active);
                LogRefusal(caller);
                return;
            }

            try
            {
                await ServeOneAsync(server, caller, ct).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Decrement(ref caller.Trusted ? ref _trusted : ref _untrusted);
            }
        }
    }

    private async Task ServeOneAsync(NamedPipeServerStream server, PipeCaller caller, CancellationToken ct)
    {
        var requestId = 0;
        try
        {
            using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readTimeout.CancelAfter(RequestReadTimeout);
            var maxBytes = caller.Trusted ? PipeProtocol.MaxMessageBytes : PipeProtocol.MaxUntrustedMessageBytes;
            var body = await PipeProtocol.ReadMessageAsync(server, readTimeout.Token, maxBytes).ConfigureAwait(false);
            if (body is null)
                return;

            PipeResponse response;
            var request = TryParse(body);
            if (request is null)
            {
                response = PipeResponse.Failure(0, PipeErrors.InvalidArgs);
            }
            else
            {
                requestId = request.Id;
                if (!caller.Trusted && request.Op != PipeOps.Hello)
                    log.LogWarning("Refused {Op} from untrusted PID {Pid} ({Image})", request.Op, caller.ProcessId, caller.ImagePath ?? "unknown");
                response = await broker.HandleAsync(caller, request, ct).ConfigureAwait(false);
            }
            await PipeProtocol.WriteMessageAsync(server, JsonSerializer.SerializeToUtf8Bytes(response, PipeProtocol.Json), ct)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Shutting down, or the caller never sent a request in time.
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException)
        {
            log.LogDebug(ex, "Pipe client {Pid} went away or sent a bad message during request {Id}", caller.ProcessId, requestId);
        }
        catch (Exception ex)
        {
            log.LogError(ex, "Request {Id} from PID {Pid} failed", requestId, caller.ProcessId);
        }
    }

    /// <summary>Logs refused connections at most once a minute, so a flood can't flood the log too.</summary>
    private void LogRefusal(PipeCaller caller)
    {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastRefusalLog);
        if (now - last < 60_000 || Interlocked.CompareExchange(ref _lastRefusalLog, now, last) != last)
            return;
        log.LogWarning("Too many connections from {Kind} programs; refusing PID {Pid} ({Image})",
            caller.Trusted ? "trusted" : "unknown", caller.ProcessId, caller.ImagePath ?? "unknown");
    }

    private static PipeRequest? TryParse(byte[] body)
    {
        try
        {
            var request = JsonSerializer.Deserialize<PipeRequest>(body, PipeProtocol.Json);
            return request is { Op.Length: > 0 } ? request : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private NamedPipeServerStream CreateInstance(bool firstInstance)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(WellKnown.Network, PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(WellKnown.LocalSystem, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(WellKnown.Administrators, PipeAccessRights.FullControl, AccessControlType.Allow));
        // Anyone signed in to this PC may connect; trust comes from the verified program path, not from
        // connecting. Nobody but SYSTEM and administrators can create instances of the pipe.
        security.AddAccessRule(new PipeAccessRule(
            WellKnown.AuthenticatedUsers, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        if (!layout.IsService)
        {
            // Run from a console, the developer running it needs to create more instances of their own pipe.
            security.AddAccessRule(new PipeAccessRule(
                System.Security.Principal.WindowsIdentity.GetCurrent().User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        var options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(
            _pipeName, PipeDirection.InOut, MaxInstances, PipeTransmissionMode.Byte, options, BufferBytes, BufferBytes, security);
    }
}
