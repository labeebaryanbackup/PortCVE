using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using PortCVE.Cli;
using PortCVE.Collection;
using PortCVE.Domain;
using PortCVE.Platforms.Linux;
using PortCVE.Vulnerabilities;

namespace PortCVE.Tests;

internal sealed class LinuxFactAttribute : FactAttribute
{
    public LinuxFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
        {
            Skip = "Requires the native Linux filesystem and socket stack.";
        }
    }
}

public sealed class LinuxRuntimeTests
{
    [LinuxFact]
    public void LocalFiles_AllowRegularFilesAndMissingOutputButRejectSymlinkAncestors()
    {
        using var fixture = new LocalFixture();
        var regular = Path.Combine(fixture.Root, "input.json");
        File.WriteAllText(regular, "{}");
        Assert.True(LocalPathPolicy.ValidateExistingImportFile(regular).IsValid);
        Assert.True(LocalPathPolicy.ValidateOptionalImportOutputFile(
            Path.Combine(fixture.Root, "new", "output.json")).IsValid);

        var link = Path.Combine(fixture.Root, "linked-input.json");
        File.CreateSymbolicLink(link, regular);
        Assert.Equal("import_path_reparse", LocalPathPolicy.ValidateExistingImportFile(link).Code);
        var dangling = Path.Combine(fixture.Root, "dangling");
        Directory.CreateSymbolicLink(dangling, Path.Combine(fixture.Root, "missing"));
        Assert.Equal("import_output_path_reparse", LocalPathPolicy.ValidateOptionalImportOutputFile(
            Path.Combine(dangling, "output.json")).Code);

        var directoryLink = Path.Combine(fixture.Root, "linked-directory");
        Directory.CreateSymbolicLink(directoryLink, fixture.Root);
        Assert.Equal("import_path_reparse", LocalPathPolicy.ValidateExistingImportFile(
            Path.Combine(directoryLink, "input.json")).Code);
        Assert.False(LocalPathPolicy.ValidateOptionalImportOutputFile(
            Path.Combine(regular, "child.json")).IsValid);
    }

    [LinuxFact]
    public void LocalFiles_RejectFifoSocketAndDeviceWithoutOpeningThem()
    {
        using var fixture = new LocalFixture();
        var fifo = Path.Combine(fixture.Root, "pipe");
        Assert.Equal(0, MkFifo(fifo, 384)); // 0600; no writer is started.
        Assert.Equal("import_path_invalid", LocalPathPolicy.ValidateExistingImportFile(fifo).Code);
        var socketPath = Path.Combine(fixture.Root, "socket");
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        socket.Bind(new UnixDomainSocketEndPoint(socketPath));
        Assert.Equal("import_path_invalid", LocalPathPolicy.ValidateExistingImportFile(socketPath).Code);
        Assert.False(LocalPathPolicy.ValidateExistingImportFile("/dev/null").IsValid);
    }

    [Theory]
    [InlineData("/mnt/data", "/mnt/data/file", true)]
    [InlineData("/mnt/data", "/mnt/database/file", false)]
    [InlineData("/", "/home/test/file", true)]
    [InlineData("/mnt/Data", "/mnt/data/file", false)]
    public void MountMatching_UsesWholeComponentsAndCaseSensitivePaths(string mount, string path, bool expected)
    {
        Assert.Equal(expected, LinuxFileSystem.ContainsPath(mount, path));
    }

    [LinuxFact]
    public void TempCleanup_DoesNotDeleteCaseDifferentSibling()
    {
        using var fixture = new LocalFixture();
        var expectedRoot = Path.Combine(fixture.Root, "Temp");
        var siblingRoot = Path.Combine(fixture.Root, "temp");
        var candidate = Path.Combine(siblingRoot, $"scan-{Guid.NewGuid():N}");
        Directory.CreateDirectory(expectedRoot);
        Directory.CreateDirectory(candidate);
        Assert.False(TrivyVulnerabilityScanner.TryDeleteInvocationTempDirectory(expectedRoot, candidate));
        Assert.False(TrivyDatabaseService.TryDeleteInvocationTempDirectory(expectedRoot, candidate));
        Assert.True(Directory.Exists(candidate));
    }

    [LinuxFact]
    public async Task Snapshot_ObservesOwnedLoopbackTcpAndUdpAndReportsMissingAttribution()
    {
        using var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var tcpPort = ((IPEndPoint)tcp.LocalEndpoint).Port;
        var udpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var snapshot = await new SnapshotBuilder().CollectAsync(
            new SnapshotOptions(IncludeFirewall: true, IncludeProfiles: true), CancellationToken.None);
        foreach (var (protocol, port) in new[] { (TransportProtocol.Tcp, tcpPort), (TransportProtocol.Udp, udpPort) })
        {
            var listener = Assert.Single(snapshot.Listeners, item => item.Protocol == protocol
                && item.LocalPort == port && item.LocalAddress == "127.0.0.1");
            Assert.Equal(BindScope.Loopback, listener.BindScope);
            Assert.False(listener.Owner.IsComplete);
            Assert.Equal(-1, listener.Owner.Pid);
            Assert.Equal(FirewallVerdict.Unknown, listener.HostPolicy.Verdict);
        }
        Assert.Contains(snapshot.Collectors, item => item.Name == "sockets" && item.Status == CollectorStatus.Complete);
        Assert.Contains(snapshot.Diagnostics, item => item.Code == "linux_owner_attribution_unavailable");
        Assert.Contains(snapshot.Diagnostics, item => item.Code == "linux_firewall_unavailable");
        Assert.Contains(snapshot.Diagnostics, item => item.Code == "windows_profiles_unavailable");

        using var output = new StringWriter();
        var exitCode = await new CliApplication().RunAsync(CliParser.Parse(["list", "--strict"]),
            output, TextWriter.Null, CancellationToken.None);
        Assert.Equal(3, exitCode);
    }

    [LinuxFact]
    public async Task Snapshot_HonorsCancellationBeforeCollection()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new LinuxSnapshotBuilder()
            .CollectAsync(new SnapshotOptions(), cancellation.Token));
    }

    private sealed class LocalFixture : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), $"portcve-linux-{Guid.NewGuid():N}");
        public LocalFixture() => Directory.CreateDirectory(Root);
        public void Dispose() => Directory.Delete(Root, recursive: true);
    }

    [DllImport("libc", EntryPoint = "mkfifo", SetLastError = true)]
    private static extern int MkFifo([MarshalAs(UnmanagedType.LPUTF8Str)] string path, uint mode);
}
