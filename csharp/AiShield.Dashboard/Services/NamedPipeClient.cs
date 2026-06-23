using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace AiShield.Dashboard.Services;

/// <summary>
/// Lightweight named-pipe client for local AI Firewall IPC (fallback when HTTP is blocked).
/// </summary>
public sealed class NamedPipeClient : IDisposable
{
    private const string PipeName = "AiShield";

    public async Task<JsonDocument?> SendAsync(object request, int timeoutMs = 3000, CancellationToken ct = default)
    {
        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        await pipe.ConnectAsync(cts.Token);
        var payload = JsonSerializer.SerializeToUtf8Bytes(request);
        await pipe.WriteAsync(payload, cts.Token);
        await pipe.FlushAsync(cts.Token);

        var buf = new byte[65536];
        var read = await pipe.ReadAsync(buf.AsMemory(0, buf.Length), cts.Token);
        if (read <= 0) return null;
        return JsonDocument.Parse(Encoding.UTF8.GetString(buf, 0, read));
    }

    public async Task<bool> IsAvailableAsync()
    {
        try
        {
            var doc = await SendAsync(new { cmd = "status" }, timeoutMs: 1500);
            return doc?.RootElement.GetProperty("ok").GetBoolean() == true;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose() { }
}
