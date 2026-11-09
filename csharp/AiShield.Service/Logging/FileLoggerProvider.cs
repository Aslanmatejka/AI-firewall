using System.Globalization;

namespace AiShield.Service.Logging;

/// <summary>A small rolling log file in the service's protected data folder.</summary>
internal sealed class FileLoggerProvider(string path, long maxBytes = 5 * 1024 * 1024, int keep = 3) : ILoggerProvider
{
    private readonly Lock _gate = new();

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName[(categoryName.LastIndexOf('.') + 1)..]);

    public void Dispose()
    {
    }

    internal void Write(LogLevel level, string category, string message, Exception? exception)
    {
        var line = string.Create(CultureInfo.InvariantCulture,
            $"{DateTimeOffset.Now:O} {Abbreviation(level)} {category}: {message}{(exception is null ? "" : Environment.NewLine + exception)}{Environment.NewLine}");
        lock (_gate)
        {
            try
            {
                Roll();
                File.AppendAllText(path, line);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Logging must never take the service down.
            }
        }
    }

    private void Roll()
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length < maxBytes)
            return;
        for (var i = keep - 1; i >= 1; i--)
        {
            var from = $"{path}.{i}";
            if (File.Exists(from))
                File.Move(from, $"{path}.{i + 1}", overwrite: true);
        }
        File.Move(path, $"{path}.1", overwrite: true);
    }

    private static string Abbreviation(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRC",
        LogLevel.Debug => "DBG",
        LogLevel.Information => "INF",
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        _ => "CRT",
    };

    private sealed class FileLogger(FileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
                provider.Write(logLevel, category, formatter(state, exception), exception);
        }
    }
}
