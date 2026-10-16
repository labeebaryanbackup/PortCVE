# Linux usage

This local recovery adds Linux x64 to the source build. It has not been pushed or released on GitHub.

## Available now

- `portcve list`, `portcve tcp:PORT`, `portcve snapshot`, `portcve doctor`: native .NET TCP/UDP enumeration and interface/bind classification.
- `portcve import nmap scan.xml`, `portcve import nuclei findings.jsonl`: local evidence normalization. These commands do not run Nmap or Nuclei and do not contact the reported addresses.
- JSON reports, selectors and local parsing/analysis logic.

The import and cache path policy rejects UNC/device syntax, symlinks in path ancestors, nonlocal filesystems, and special files such as FIFOs, Unix sockets and devices. Linux checks use `statx` without following symlinks; Windows retains `GetFileAttributesW`. Trivy discovery accepts the Linux `trivy` executable name. Temporary directory cleanup uses case-sensitive containment on Linux.

## Collection limits

Linux currently supplies socket and interface evidence only. PID `-1` and image name `unknown` mean no owner identity was established. It does not infer processes, accounts, service identities, executable hashes, Docker mappings, Windows profiles, or nftables/iptables verdicts.

`list --strict` and `snapshot --strict` return exit code **3**, even when sockets were enumerated successfully. That correctly reports missing owner evidence. A Linux baseline can be saved with `--allow-incomplete` for inspection; it cannot establish a complete owner-aware policy pass. Do not treat a local bind as proof of external reachability.

The optional Trivy executable and vulnerability database must be installed/populated separately before CVE scans. This recovery did not download a CVE database or validate a real Trivy scan. Remote scanning code remains available behind `--authorized`, but no remote host was scanned during this recovery.

## Build and verify

```bash
dotnet restore PortCVE.sln --locked-mode
dotnet test tests/PortCVE.Tests/PortCVE.Tests.csproj -c Release --no-restore -p:SelfContained=false
dotnet publish src/PortCVE/PortCVE.csproj -c Release -r linux-x64 --self-contained false -o artifacts/linux-x64
./artifacts/linux-x64/portcve doctor
```

The additional Linux tests hold their own loopback TCP/UDP listeners open while collecting real socket evidence, verify strict-mode exit code 3, and exercise native symlink/FIFO/socket rejection. Windows-specific APIs were not executed on this Linux laptop; their existing code paths remain, and the shared tests run here with explicit platform boundaries.
