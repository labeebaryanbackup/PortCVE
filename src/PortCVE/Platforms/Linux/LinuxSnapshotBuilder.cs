using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using PortCVE.Analysis;
using PortCVE.Collection;
using PortCVE.Domain;

namespace PortCVE.Platforms.Linux;

/// <summary>Local Linux socket inventory; does not infer owners or Windows policy.</summary>
internal sealed class LinuxSnapshotBuilder : ISnapshotBuilder
{
    public async Task<SystemSnapshot> CollectAsync(SnapshotOptions options, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        var reports = new List<CollectorReport>();
        var diagnostics = new List<CollectorDiagnostic>();
        var interfaces = await new NetworkInterfaceCollector().CollectAsync(false, cancellationToken);
        reports.Add(interfaces.Report);
        diagnostics.AddRange(interfaces.Report.Diagnostics);
        var listeners = new List<ListenerEvidence>();

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            foreach (var endpoint in properties.GetActiveTcpListeners())
            {
                cancellationToken.ThrowIfCancellationRequested();
                listeners.Add(CreateListener(endpoint, TransportProtocol.Tcp, interfaces.Value, options));
            }
            foreach (var endpoint in properties.GetActiveUdpListeners())
            {
                cancellationToken.ThrowIfCancellationRequested();
                listeners.Add(CreateListener(endpoint, TransportProtocol.Udp, interfaces.Value, options));
            }
            reports.Add(new("sockets", CollectorStatus.Complete, started, stopwatch.ElapsedMilliseconds, []));
        }
        catch (Exception exception) when (exception is NetworkInformationException or IOException or UnauthorizedAccessException)
        {
            var diagnostic = new CollectorDiagnostic("sockets", CollectorStatus.Failed,
                "linux_socket_collection_failed", exception.Message);
            diagnostics.Add(diagnostic);
            reports.Add(new("sockets", CollectorStatus.Failed, started, stopwatch.ElapsedMilliseconds, [diagnostic]));
        }

        AddUnavailable("process_owners", "linux_owner_attribution_unavailable",
            "This Linux inventory does not attribute sockets to PIDs, services, accounts or executable hashes.");
        AddUnavailable("docker", "linux_container_attribution_unavailable",
            "Docker published-port correlation is not implemented by this Linux inventory.");
        if (options.IncludeFirewall)
        {
            AddUnavailable("firewall", "linux_firewall_unavailable",
                "Windows Firewall analysis is unavailable on Linux; nftables/iptables policy was not evaluated.");
        }
        if (options.IncludeProfiles)
        {
            AddUnavailable("network_profiles", "windows_profiles_unavailable",
                "Windows network profile categories do not apply to Linux interfaces.");
        }

        return new(SystemSnapshot.CurrentSchemaVersion,
            Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown",
            started, stopwatch.ElapsedMilliseconds, Environment.OSVersion.VersionString,
            reports, interfaces.Value,
            listeners.OrderBy(static item => item.Protocol).ThenBy(static item => item.LocalPort)
                .ThenBy(static item => item.Family).ThenBy(static item => item.LocalAddress, StringComparer.Ordinal).ToArray(),
            diagnostics);

        void AddUnavailable(string collector, string code, string message)
        {
            var diagnostic = new CollectorDiagnostic(collector, CollectorStatus.Unavailable, code, message);
            diagnostics.Add(diagnostic);
            reports.Add(new(collector, CollectorStatus.Unavailable, started, 0, [diagnostic]));
        }
    }

    private static ListenerEvidence CreateListener(IPEndPoint endpoint, TransportProtocol protocol,
        IReadOnlyList<NetworkInterfaceEvidence> interfaces, SnapshotOptions options)
    {
        var family = endpoint.AddressFamily == AddressFamily.InterNetwork ? IpFamily.Ipv4 : IpFamily.Ipv6;
        var bind = BindScopeClassifier.Classify(endpoint.Address, family, interfaces);
        const string ownerLimitation = "Linux socket owner attribution is unavailable; no PID or service identity was inferred.";
        var owner = new OwnerEvidence(-1, null, "unknown", null, null, null, null, null, null,
            [], false, false, [ownerLimitation]);
        var policy = new HostPolicyEvidence(options.IncludeFirewall ? FirewallVerdict.Unknown : FirewallVerdict.NotEvaluated,
            Confidence.Low, "Linux host firewall policy was not evaluated.", [],
            ["Windows Firewall analysis is unavailable on Linux. External reachability was not tested."]);
        return new(SnapshotBuilder.CreateBindKey(protocol, family, endpoint.Address.ToString(), endpoint.Port),
            protocol, family, endpoint.Address.ToString(), endpoint.Port,
            protocol == TransportProtocol.Tcp ? "LISTEN" : "BOUND", bind.Scope, bind.Summary, owner,
            bind.ActiveOn, policy,
            ["The local Linux network stack reported this bound endpoint through .NET IPGlobalProperties."],
            bind.Limitations.Append(ownerLimitation).ToArray());
    }
}
