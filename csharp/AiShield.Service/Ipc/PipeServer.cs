using System.IO.Pipes;
using System.Security.AccessControl;
using System.Text.Json;
using AiShield.Core.Broker;
using AiShield.Core.Ipc;
using AiShield.Core.Security;
using AiShield.Core.Windows;

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

internal sealed class PipeServer(ShieldBroker broker, ClientVerifier verifier, ServiceLayout layout, ILogger<PipeServer> log) : BackgroundService
{
    private const int Listeners = 4;
    private static readonly TimeSpan RequestReadTimeout = TimeSpan.FromSeconds(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        NamedPipeServerStream first;
        try
        {
            // If anything else already owns the name, refuse to share it. Clients also check who owns it.
            first = CreateInstance(firstInstance: true, layout.IsService);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.LogCritical(ex, "Couldn't create the {Pipe} pipe. Another program may be holding its name", PipeProtocol.PipeName);
            throw;
        }

        log.LogInformation("Listening on pipe {Pipe}", PipeProtocol.PipeName);
        var loops = Enumerable.Range(0, Listeners)
            .Select(i => ListenAsync(i == 0 ? first : null, stoppingToken))
            .ToArray();
        await Task.WhenAll(loops).ConfigureAwait(false);
    }

    private async Task ListenAsync(NamedPipeServerStream? initial, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var server = initial ?? CreateInstance(firstInstance: false, layout.IsService);
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
                log.LogWarning(ex, "A pipe connection failed before it started");
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
            var requestId = 0;
            try
            {
                using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                readTimeout.CancelAfter(RequestReadTimeout);
                var body = await PipeProtocol.ReadMessageAsync(server, readTimeout.Token).ConfigureAwait(false);
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
                // Shutting down, or the caller never sent a request.
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException)
            {
                log.LogDebug(ex, "Pipe client {Pid} went away during request {Id}", caller.ProcessId, requestId);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Request {Id} from PID {Pid} failed", requestId, caller.ProcessId);
            }
        }
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

    private static NamedPipeServerStream CreateInstance(bool firstInstance, bool isService)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(WellKnown.Network, PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(WellKnown.LocalSystem, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(WellKnown.Administrators, PipeAccessRights.FullControl, AccessControlType.Allow));
        // Anyone signed in to this PC may connect; trust comes from the verified program path, not from
        // connecting. Nobody but SYSTEM and administrators can create instances of the pipe.
        security.AddAccessRule(new PipeAccessRule(
            WellKnown.AuthenticatedUsers, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        if (!isService)
        {
            // Run from a console, the developer running it needs to create more instances of their own pipe.
            security.AddAccessRule(new PipeAccessRule(
                System.Security.Principal.WindowsIdentity.GetCurrent().User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        var options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(
            PipeProtocol.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, options, 64 * 1024, 64 * 1024, security);
    }
}
