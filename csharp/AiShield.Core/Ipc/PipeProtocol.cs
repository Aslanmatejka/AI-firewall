using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AiShield.Core.Ipc;

/// <summary>
/// One request per connection: a 4-byte little-endian length, then UTF-8 JSON. The same in both directions.
/// </summary>
public static class PipeProtocol
{
    public const string PipeName = "AiShield.v1";
    public const string ServiceName = "AiShield";
    public const int MaxMessageBytes = 1024 * 1024;

    public static JsonSerializerOptions Json { get; } = new(JsonSerializerDefaults.General)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public static async Task WriteMessageAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        if (payload.Length > MaxMessageBytes)
            throw new InvalidDataException($"Message of {payload.Length} bytes is over the {MaxMessageBytes}-byte limit");

        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Returns null if the other side closed the connection before sending anything.</summary>
    public static async Task<byte[]?> ReadMessageAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        if (!await FillAsync(stream, header, ct).ConfigureAwait(false))
            return null;

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is < 0 or > MaxMessageBytes)
            throw new InvalidDataException($"Message length {length} is out of range");

        var body = new byte[length];
        if (!await FillAsync(stream, body, ct).ConfigureAwait(false))
            throw new EndOfStreamException("Connection closed in the middle of a message");
        return body;
    }

    private static async Task<bool> FillAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var filled = 0;
        while (filled < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(filled), ct).ConfigureAwait(false);
            if (read == 0)
            {
                if (filled == 0)
                    return false;
                throw new EndOfStreamException("Connection closed in the middle of a message");
            }
            filled += read;
        }
        return true;
    }
}

public static class PipeOps
{
    public const string Hello = "hello";
    public const string Status = "status";
    public const string Config = "config";
    public const string Events = "events";
    public const string Audit = "audit";
    public const string AppPolicies = "app-policies";
    public const string Deny = "deny";
    public const string Review = "review";
    public const string SetGlobalPolicy = "set-global-policy";
    public const string SetAppPolicy = "set-app-policy";
    public const string RemoveAppPolicy = "remove-app-policy";
    public const string LockdownOn = "lockdown-on";
    public const string LockdownOff = "lockdown-off";
    public const string RestoreDefaults = "restore-defaults";
    public const string RevokeGrants = "revoke-grants";
    public const string Terminate = "terminate";
    public const string HelperExit = "helper-exit";
#if AISHIELD_TEST_HOOKS
    public const string TestSubmitRequest = "test-submit-request";
#endif
}

public static class PipeErrors
{
    public const string UntrustedClient = "untrusted-client";
    public const string UnknownOp = "unknown-op";
    public const string InvalidArgs = "invalid-args";
    public const string NotFound = "not-found";
    public const string NotApproved = "not-approved";
    public const string Failed = "failed";
}

public sealed record PipeRequest(int Id, string Op, JsonElement? Args = null);

public sealed record PipeResponse(int Id, bool Ok, string? Error = null, JsonElement? Data = null, string? Consent = null)
{
    public static PipeResponse Success(int id, object? data = null, ConsentOutcome? consent = null)
        => new(id, true, null, data is null ? null : JsonSerializer.SerializeToElement(data, PipeProtocol.Json), consent?.ToWire());

    public static PipeResponse Failure(int id, string error, ConsentOutcome? consent = null)
        => new(id, false, error, null, consent?.ToWire());
}

public enum ConsentOutcome
{
    NotNeeded,
    Approved,
    Denied,
    Dismissed,
    Unavailable,
    Busy,
}

public static class ConsentOutcomes
{
    public static string ToWire(this ConsentOutcome outcome) => outcome switch
    {
        ConsentOutcome.NotNeeded => "not-needed",
        ConsentOutcome.Approved => "approved",
        ConsentOutcome.Denied => "denied",
        ConsentOutcome.Dismissed => "dismissed",
        ConsentOutcome.Busy => "busy",
        _ => "unavailable",
    };
}

/// <summary>What the secure prompt shows. Every field is cleaned before display.</summary>
public sealed record ConsentText(string Title, string Summary, IReadOnlyList<string> Details, string RequestedBy);

/// <summary>Exit codes of AiShield.Consent.exe. Zero and one are avoided because crashes produce them.</summary>
public static class ConsentExitCodes
{
    public const int Approved = 10;
    public const int Denied = 11;
    public const int Dismissed = 12;
    public const int DesktopUnavailable = 13;
    public const int Error = 14;

    public static ConsentOutcome ToOutcome(int? exitCode) => exitCode switch
    {
        Approved => ConsentOutcome.Approved,
        Denied => ConsentOutcome.Denied,
        Dismissed => ConsentOutcome.Dismissed,
        _ => ConsentOutcome.Unavailable,
    };
}

/// <summary>Exit codes of AiShield.Dashboard.exe that the service treats specially.</summary>
public static class HelperExitCodes
{
    public const int AnotherInstanceRunning = 3;
}
