using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using AiShield.Core.Windows;

namespace AiShield.Core.Ipc;

/// <summary>
/// Talks to the AI Firewall service. Each request gets its own connection, so a request waiting on the
/// user's confirmation never holds up the others.
/// </summary>
public sealed class ShieldPipeClient
{
    private int _nextId;

    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Only talk to the pipe if the AI Firewall service owns it. Anything else holding that name is an impostor.
    /// </summary>
    public bool RequireServiceServer { get; init; } = true;

    /// <summary>Returns null if the service isn't reachable, or something other than the service owns the pipe.</summary>
    public async Task<PipeResponse?> SendAsync(string op, object? args = null, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        // Identification lets the service check who we are without being able to act as us.
        using var pipe = new NamedPipeClientStream(
            ".", PipeProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(ConnectTimeout);
        try
        {
            await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or TimeoutException or UnauthorizedAccessException)
        {
            ct.ThrowIfCancellationRequested();
            return null;
        }

        if (RequireServiceServer && !IsServedByService(pipe))
            return null;

        deadline.CancelAfter(timeout ?? TimeSpan.FromSeconds(15));
        var request = new PipeRequest(
            Interlocked.Increment(ref _nextId), op,
            args is null ? null : JsonSerializer.SerializeToElement(args, PipeProtocol.Json));
        try
        {
            await PipeProtocol.WriteMessageAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(request, PipeProtocol.Json), deadline.Token)
                .ConfigureAwait(false);
            var body = await PipeProtocol.ReadMessageAsync(pipe, deadline.Token).ConfigureAwait(false);
            return body is null ? null : JsonSerializer.Deserialize<PipeResponse>(body, PipeProtocol.Json);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidDataException or JsonException)
        {
            ct.ThrowIfCancellationRequested();
            return null;
        }
    }

    public async Task<T?> GetAsync<T>(string op, object? args = null, CancellationToken ct = default)
    {
        var response = await SendAsync(op, args, ct: ct).ConfigureAwait(false);
        if (response is not { Ok: true, Data: { } data })
            return default;
        try
        {
            return data.Deserialize<T>(PipeProtocol.Json);
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private static bool IsServedByService(NamedPipeClientStream pipe)
    {
        var serverPid = NativeProcess.GetPipeServerProcessId(pipe.SafePipeHandle);
        var servicePid = ServiceQuery.GetProcessId(PipeProtocol.ServiceName);
        return serverPid is > 0 && serverPid == servicePid;
    }
}
