namespace AiShield.Service;

/// <summary>
/// A background task the service can't work without. If it fails, the process exits with an error
/// instead of stopping cleanly, because Windows only restarts a service that fails.
/// </summary>
internal abstract class CriticalService(ILogger log) : BackgroundService
{
    protected abstract Task RunAsync(CancellationToken stoppingToken);

    protected sealed override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            log.LogCritical(ex, "{Task} failed. Exiting so Windows restarts the service", GetType().Name);
            Environment.Exit(1);
        }
    }
}
