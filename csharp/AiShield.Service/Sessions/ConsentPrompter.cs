using System.ComponentModel;
using System.Text.Json;
using AiShield.Core.Broker;
using AiShield.Core.Ipc;
using AiShield.Service.Native;

namespace AiShield.Service.Sessions;

/// <summary>
/// Shows AiShield.Consent.exe as SYSTEM on a private desktop in the user's session, like a UAC prompt.
/// Only one prompt at a time, and a short pause after a refusal so a misbehaving app can't flood the user.
/// </summary>
internal sealed class ConsentPrompter(ServiceLayout layout, ILogger<ConsentPrompter> log) : IConsentPrompter, IDisposable
{
    private static readonly TimeSpan PromptLimit = TimeSpan.FromSeconds(150);
    private static readonly TimeSpan QuietAfterRefusal = TimeSpan.FromSeconds(3);

    private readonly SemaphoreSlim _one = new(1, 1);
    private DateTimeOffset _quietUntil = DateTimeOffset.MinValue;

    public async Task<ConsentOutcome> AskAsync(int sessionId, ConsentText text, CancellationToken ct)
    {
        if (!layout.IsService || !layout.InstallProtected || !File.Exists(layout.ConsentExe))
        {
            log.LogWarning("The secure prompt isn't available: {Reason}",
                layout.InstallProtected ? "AiShield.Consent.exe is missing" : layout.InstallProblem);
            return ConsentOutcome.Unavailable;
        }
        if (!await _one.WaitAsync(TimeSpan.Zero, ct).ConfigureAwait(false))
            return ConsentOutcome.Busy;

        try
        {
            if (DateTimeOffset.UtcNow < _quietUntil)
                return ConsentOutcome.Busy;

            var request = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(text, PipeProtocol.Json))
                .Replace('+', '-').Replace('/', '_').TrimEnd('=');
            using var prompt = SessionNative.StartAsSystemInSession(sessionId, layout.ConsentExe, $"--request {request}");
            var exitCode = await prompt.WaitForExitAsync(PromptLimit, ct).ConfigureAwait(false);
            if (exitCode is null)
            {
                log.LogWarning("The secure prompt in session {Session} didn't close in time", sessionId);
                prompt.Kill(ConsentExitCodes.Dismissed);
            }

            var outcome = ConsentExitCodes.ToOutcome(exitCode);
            log.LogInformation("Secure prompt in session {Session}: {Outcome} (exit code {Code})", sessionId, outcome, exitCode);
            if (outcome != ConsentOutcome.Approved)
                _quietUntil = DateTimeOffset.UtcNow + QuietAfterRefusal;
            return outcome;
        }
        catch (Win32Exception ex)
        {
            log.LogError(ex, "Couldn't show the secure prompt in session {Session}", sessionId);
            return ConsentOutcome.Unavailable;
        }
        finally
        {
            _one.Release();
        }
    }

    public void Dispose() => _one.Dispose();
}
