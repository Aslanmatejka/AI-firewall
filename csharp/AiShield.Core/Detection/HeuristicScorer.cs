using System.Text.RegularExpressions;

namespace AiShield.Core.Detection;

public sealed record ProcessSignals(
    string ImagePath,
    string? CommandLine,
    double GpuMb,
    double WorkingSetMb,
    bool ConnectedToAiDomain,
    IReadOnlyList<string> LoadedModules);

public sealed record HeuristicScore(int Score, IReadOnlyList<string> Reasons);

/// <summary>
/// Scores how AI-like an unrecognized process looks, from 0 to 100. Results are suggestions for the
/// user and never trigger enforcement on their own.
/// </summary>
public sealed partial class HeuristicScorer(double gpuThresholdMb = 512, int threshold = 65)
{
    public int Threshold => threshold;

    public bool IsSuspicious(HeuristicScore score) => score.Score >= threshold;

    public HeuristicScore Score(ProcessSignals signals)
    {
        var reasons = new List<string>();
        var score = 0;

        if (signals.GpuMb >= gpuThresholdMb)
        {
            score += 35;
            reasons.Add($"GPU memory {signals.GpuMb:0} MB");
        }
        else if (signals.GpuMb >= gpuThresholdMb * 0.5)
        {
            score += 15;
            reasons.Add($"Elevated GPU memory {signals.GpuMb:0} MB");
        }

        if (signals.ConnectedToAiDomain)
        {
            score += 20;
            reasons.Add("Connected to a known AI service");
        }

        if (signals.WorkingSetMb >= 2048)
        {
            score += 15;
            reasons.Add($"High memory use {signals.WorkingSetMb:0} MB");
        }
        else if (signals.WorkingSetMb >= 1024)
        {
            score += 8;
        }

        var commandLine = signals.CommandLine ?? "";
        if (AiPathHint().IsMatch(signals.ImagePath) || AiPathHint().IsMatch(commandLine))
        {
            score += 25;
            reasons.Add("AI-related path or command line");
        }

        if (InferenceCommandLine().IsMatch(commandLine))
        {
            score += 20;
            reasons.Add("Inference-style command line");
        }

        if (signals.LoadedModules.Any(module => AiRuntimeModule().IsMatch(module)))
        {
            score += 15;
            reasons.Add("Loaded AI runtime libraries");
        }

        var name = Path.GetFileName(signals.ImagePath);
        if (score < 40 && (name.Equals("python.exe", StringComparison.OrdinalIgnoreCase)
            || name.Equals("pythonw.exe", StringComparison.OrdinalIgnoreCase)))
        {
            score += 5;
            reasons.Add("Python interpreter (weak signal)");
        }

        return new HeuristicScore(Math.Min(score, 100), reasons);
    }

    [GeneratedRegex(@"(ollama|lmstudio|openai|anthropic|huggingface|\.cache\\huggingface|models|gguf|transformers|torch|cuda|onnx|llama|gpt|claude|copilot|cursor)", RegexOptions.IgnoreCase)]
    private static partial Regex AiPathHint();

    [GeneratedRegex(@"(--model|--gguf|inference|generate|chat\.|api\.openai|localhost:11434)", RegexOptions.IgnoreCase)]
    private static partial Regex InferenceCommandLine();

    [GeneratedRegex(@"(cublas|cudnn|onnxruntime|torch|llama|ggml|openblas|mkl|directml)", RegexOptions.IgnoreCase)]
    private static partial Regex AiRuntimeModule();
}
