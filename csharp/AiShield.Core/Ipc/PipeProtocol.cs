using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AiShield.Core.Ipc;

/// <summary>
/// One request per connection: a 4-byte little-endian length, then UTF-8 JSON. The same in both directions.
/// </summary>
public static class PipeProtocol
{
    public const string ServiceName = "AiShield";
    public const int MaxMessageBytes = 1024 * 1024;

    /// <summary>Unknown programs may only say hello, which needs a few bytes, not a megabyte.</summary>
    public const int MaxUntrustedMessageBytes = 4 * 1024;

    // The service picks a new random pipe name each time it starts and publishes it here, where only
    // SYSTEM and administrators can write. Nobody can grab a name before the service knows it.
    public const string RegistryKey = @"SOFTWARE\AiShield";
    public const string RegistryValue = "PipeName";
    private const string PipeNamePrefix = "AiShield.v1.";

    public static string NewPipeName()
        => PipeNamePrefix + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

    public static bool IsValidPipeName(string? name)
        => name is { Length: 28 }
            && name.StartsWith(PipeNamePrefix, StringComparison.Ordinal)
            && name[PipeNamePrefix.Length..].All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>The running service's pipe name, or null if no service has published one.</summary>
    public static string? DiscoverPipeName()
    {
        using var hive = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
        using var key = hive.OpenSubKey(RegistryKey);
        var name = key?.GetValue(RegistryValue) as string;
        return IsValidPipeName(name) ? name : null;
    }

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

    /// <summary>
    /// Returns null if the other side closed the connection before sending anything. The declared length
    /// is checked against <paramref name="maxBytes"/> before any memory is set aside for the message.
    /// </summary>
    public static async Task<byte[]?> ReadMessageAsync(Stream stream, CancellationToken ct, int maxBytes = MaxMessageBytes)
    {
        var header = new byte[4];
        if (!await FillAsync(stream, header, ct).ConfigureAwait(false))
            return null;

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length < 0 || length > Math.Min(maxBytes, MaxMessageBytes))
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
