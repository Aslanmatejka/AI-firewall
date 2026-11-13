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

    private readonly SemaphoreSlim _one = new(1, 1);
    // Each refusal doubles the wait before the next prompt, from 3 seconds up to a minute.
    private readonly RefusalBackoff _backoff = new(TimeSpan.FromSeconds(3), TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(10));

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
            if (DateTimeOffset.UtcNow < _backoff.QuietUntil(DateTimeOffset.UtcNow))
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
                _backoff.Refused(DateTimeOffset.UtcNow);
            else
                _backoff.Approved();
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
