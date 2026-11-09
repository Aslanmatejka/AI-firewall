using AiShield.Core.Config;
using AiShield.Core.Detection;

namespace AiShield.Core.Tests;

public sealed class DetectionTests
{
    private readonly AiDetector _detector = new(TestDefaults.Create().Signatures);

    [Theory]
    [InlineData(@"C:\Users\me\.claude\notepad.exe")]
    [InlineData(@"C:\Tools\continue\backup.exe")]
    [InlineData(@"C:\Users\me\AppData\Local\Programs\cursor\resources\app\node_modules\helpers\rg.exe")]
    [InlineData(@"C:\Users\me\.cursor\extensions\ms-python\pet.exe")]
    [InlineData(@"C:\Windows\System32\conhost.exe")]
    public void FolderNamesDontMakeAProgramAnAi(string path) => Assert.Null(_detector.Match(path, null));

    [Theory]
    [InlineData(@"C:\Apps\claude.exe", "Claude")]
    [InlineData(@"C:\Apps\Cursor.exe", "Cursor")]
    [InlineData(@"C:\Program Files\Ollama\ollama app.exe", "Ollama")]
    [InlineData(@"\Device\HarddiskVolume3\Program Files\Ollama\ollama.exe", "Ollama")]
    public void ProgramsAreRecognizedByName(string path, string app) => Assert.Equal(app, _detector.Match(path, null)?.AppName);

    [Fact]
    public void ExactPatternsDontMatchLongerNames()
    {
        Assert.Null(_detector.Match(@"C:\Games\notcursor.exe", null));
        Assert.Null(_detector.Match(@"C:\Games\raider.exe", null));
        Assert.Equal("Aider", _detector.Match(@"C:\Py\Scripts\aider.exe", null)?.AppName);
    }

    [Fact]
    public void CommandLineAgentsAreRecognizedThroughTheirInterpreter()
    {
        var match = _detector.Match(
            @"C:\Program Files\nodejs\node.exe",
            @"""C:\Program Files\nodejs\node.exe"" C:\Users\me\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js");
        Assert.Equal("Claude Code", match?.AppName);
        Assert.Equal("command line", match?.DetectedBy);

        Assert.Equal("Aider", _detector.Match(@"C:\Python312\python.exe", "python.exe -m aider --model x")?.AppName);
    }

    [Fact]
    public void AnInterpreterOnItsOwnIsNotAnAi()
    {
        Assert.Null(_detector.Match(@"C:\Program Files\nodejs\node.exe", @"node C:\work\server.js"));
        Assert.Null(_detector.Match(@"C:\Python312\python.exe", null));
    }

    [Fact]
    public void CommandLinesOnlyCountForInterpreters()
    {
        // Someone opening a note about Claude Code in Notepad isn't running it.
        Assert.Null(_detector.Match(@"C:\Windows\notepad.exe", @"notepad C:\notes\@anthropic-ai\claude-code.txt"));
    }

    [Fact]
    public void ShippedSignaturesRecognizeCommonApps()
    {
        var shipped = new AiDetector(ShieldDefaults.Load(Path.Combine(AppContext.BaseDirectory, "default.json")).Signatures);
        Assert.Equal("Ollama", shipped.Match(@"C:\Users\me\AppData\Local\Programs\Ollama\ollama.exe", null)?.AppName);
        Assert.Equal("Cursor", shipped.Match(@"C:\Users\me\AppData\Local\Programs\cursor\Cursor.exe", null)?.AppName);
        Assert.Equal("Claude Code", shipped.Match(@"C:\nodejs\node.exe", @"node C:\npm\node_modules\@anthropic-ai\claude-code\cli.js")?.AppName);
        Assert.Null(shipped.Match(@"C:\Windows\System32\svchost.exe", null));
    }

    // Ported from python/tests/test_ml_heuristics.py.
    [Fact]
    public void HighGpuAndAiTrafficScoreHigh()
    {
        var scorer = new HeuristicScorer(512, 65);
        var score = scorer.Score(new ProcessSignals(@"C:\x\tool.exe", null, 600, 0, true, []));
        Assert.True(score.Score >= 55);
        Assert.NotEmpty(score.Reasons);
    }

    [Fact]
    public void LowSignalsStayBelowTheThreshold()
    {
        var scorer = new HeuristicScorer(512, 65);
        Assert.False(scorer.IsSuspicious(scorer.Score(new ProcessSignals(@"C:\x\tool.exe", null, 0, 0, false, []))));
    }

    [Fact]
    public void AiTrafficCountsOnce()
    {
        // The Python scorer added this signal twice.
        var scorer = new HeuristicScorer();
        Assert.Equal(20, scorer.Score(new ProcessSignals(@"C:\x\tool.exe", null, 0, 0, true, [])).Score);
    }

    [Fact]
    public void InferenceServersLookSuspicious()
    {
        var scorer = new HeuristicScorer();
        var score = scorer.Score(new ProcessSignals(
            @"C:\llama\server.exe", "server.exe --model C:\\models\\x.gguf", 4096, 3000, false, [@"C:\llama\ggml.dll"]));
        Assert.True(scorer.IsSuspicious(score));
    }
}

public sealed class ProcessTrackerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);
    private readonly ProcessTracker _tracker = new(new AiDetector(TestDefaults.Create().Signatures));

    private static ProcessStart Start(int pid, int parent, string path, string? cmd = null) => new(pid, parent, path, cmd, 1, T0);

    [Fact]
    public void ChildrenOfAnAiAppCountAsThatApp()
    {
        var started = new List<TrackedAiProcess>();
        _tracker.AiAppStarted += started.Add;
        _tracker.OnStart(Start(1, 0, @"C:\Windows\explorer.exe"));
        _tracker.OnStart(Start(10, 1, @"C:\Apps\Cursor.exe"));
        _tracker.OnStart(Start(11, 10, @"C:\Apps\Cursor.exe"));
        _tracker.OnStart(Start(12, 11, @"C:\Windows\System32\cmd.exe"));
        _tracker.OnStart(Start(13, 12, @"C:\Git\git.exe"));

        Assert.Equal("Cursor", Assert.Single(started).AppName);
        Assert.Equal(10, Assert.Single(_tracker.AiApps()).Pid);
        Assert.Equal(10, _tracker.Find(13)?.RootPid);
        Assert.Null(_tracker.Find(1));
    }

    [Fact]
    public void ADifferentAiStartedByAnotherIsItsOwnApp()
    {
        _tracker.OnStart(Start(10, 0, @"C:\Apps\Cursor.exe"));
        _tracker.OnStart(Start(20, 10, @"C:\nodejs\node.exe", @"node C:\npm\@anthropic-ai\claude-code\cli.js"));
        Assert.Equal(["Claude Code", "Cursor"], _tracker.AiApps().Select(a => a.AppName));
    }

    [Fact]
    public void StoppedProcessesAreForgotten()
    {
        _tracker.OnStart(Start(10, 0, @"C:\Apps\Cursor.exe"));
        _tracker.OnStop(10);
        Assert.Empty(_tracker.AiApps());
        Assert.False(_tracker.Knows(10));
    }

    [Fact]
    public void AReusedPidIsANewProcess()
    {
        _tracker.OnStart(Start(10, 0, @"C:\Apps\Cursor.exe"));
        _tracker.OnStart(Start(10, 0, @"C:\Windows\notepad.exe"));
        Assert.Empty(_tracker.AiApps());
    }

    [Fact]
    public void SeedingInAnyOrderStillLinksChildrenToParents()
    {
        _tracker.Seed(
        [
            Start(13, 12, @"C:\Git\git.exe"),
            Start(12, 10, @"C:\Windows\System32\cmd.exe"),
            Start(10, 4, @"C:\Apps\Cursor.exe"),
            Start(4, 13, @"C:\Windows\explorer.exe"),
        ]);
        Assert.Equal(10, _tracker.Find(13)?.RootPid);
        Assert.Single(_tracker.AiApps());
    }
}
