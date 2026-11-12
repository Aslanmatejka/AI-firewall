using AiShield.Core.Maintenance;

namespace AiShield.Core.Tests;

public sealed class HostsFileTests
{
    private static readonly string[] Domains = ["openai.com", "claude.ai"];

    [Fact]
    public void RemovesTheEngineBlockAndKeepsEverythingElse()
    {
        const string hosts = "# Copyright (c) Microsoft\r\n127.0.0.1 localhost\r\n\r\n# AiShield blocked domains\r\n"
            + "127.0.0.1 openai.com\r\n127.0.0.1 www.openai.com\r\n127.0.0.1 claude.ai\r\n127.0.0.1 www.claude.ai\r\n";
        var cleaned = HostsFile.RemoveLegacyEntries(hosts, Domains, out var removed);
        Assert.Equal(5, removed);
        Assert.Equal("# Copyright (c) Microsoft\r\n127.0.0.1 localhost\r\n\r\n", cleaned);
    }

    [Fact]
    public void RemovesTheScriptBlockWithItsMarkers()
    {
        const string hosts = "127.0.0.1 localhost\n# AI-FIREWALL-START\n0.0.0.0 openai.com\n0.0.0.0 www.openai.com\n# AI-FIREWALL-END\n10.0.0.5 nas\n";
        var cleaned = HostsFile.RemoveLegacyEntries(hosts, Domains, out var removed);
        Assert.Equal(4, removed);
        Assert.Equal("127.0.0.1 localhost\n10.0.0.5 nas\n", cleaned);
    }

    [Fact]
    public void KeepsTheUsersOwnLinesEvenInsideABlock()
    {
        // Without its end marker the block stops at the first line that isn't one of ours.
        const string hosts = "# AI-FIREWALL-START\n0.0.0.0 openai.com\n192.168.1.20 printer\n0.0.0.0 claude.ai\n";
        var cleaned = HostsFile.RemoveLegacyEntries(hosts, Domains, out var removed);
        Assert.Equal(2, removed);
        Assert.Equal("192.168.1.20 printer\n0.0.0.0 claude.ai\n", cleaned);
    }

    [Fact]
    public void LeavesUnrelatedDomainsAndFilesWithoutMarkersAlone()
    {
        const string hosts = "# AiShield blocked domains\n127.0.0.1 example.com\n";
        Assert.Equal("127.0.0.1 example.com\n", HostsFile.RemoveLegacyEntries(hosts, Domains, out _));

        const string clean = "127.0.0.1 localhost\r\n0.0.0.0 openai.com\r\n";
        Assert.Same(clean, HostsFile.RemoveLegacyEntries(clean, Domains, out var removed));
        Assert.Equal(0, removed);
    }
}
