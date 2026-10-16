using System.Runtime.InteropServices;

namespace PortCVE.Platforms.Linux;

internal static class LinuxFileSystem
{
    // Linux UAPI statx has a fixed 256-byte layout, independent of libc's stat ABI.
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct StatxBuffer
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(28)] public ushort Mode;
    }

    internal static bool TryGetAttributesWithoutFollowing(
        string path, out FileAttributes attributes, out int errorCode)
    {
        const int atFdcwd = -100;
        const int atSymlinkNoFollow = 0x100;
        const int atNoAutomount = 0x800;
        const uint statxType = 1;
        if (Statx(atFdcwd, path, atSymlinkNoFollow | atNoAutomount, statxType, out var status) != 0)
        {
            attributes = default;
            var nativeError = Marshal.GetLastPInvokeError();
            // The shared caller uses 2/3 for missing file/path. Other errors fail closed.
            errorCode = nativeError == 20 ? 3 : nativeError;
            return false;
        }

        if ((status.Mask & statxType) == 0)
        {
            attributes = default;
            errorCode = 95;
            return false;
        }

        attributes = (status.Mode & 0xf000) switch
        {
            0x4000 => FileAttributes.Directory,
            0x8000 => FileAttributes.Normal,
            0xa000 => FileAttributes.ReparsePoint,
            _ => FileAttributes.Device, // FIFO, socket, character and block device.
        };
        errorCode = 0;
        return true;
    }

    internal static DriveType GetContainingDriveType(string fullPath)
    {
        // The root filesystem alone cannot establish locality: a child may be NFS/SMB/FUSE.
        var drive = DriveInfo.GetDrives()
            .Where(item => ContainsPath(item.Name, fullPath))
            .OrderByDescending(static item => item.Name.Length)
            .FirstOrDefault();
        return drive?.DriveType ?? DriveType.Unknown;
    }

    internal static bool ContainsPath(string mountPath, string fullPath)
    {
        var prefix = Path.TrimEndingDirectorySeparator(mountPath);
        return prefix == "/" || fullPath.Equals(prefix, StringComparison.Ordinal)
            || fullPath.StartsWith(prefix + "/", StringComparison.Ordinal);
    }

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        int flags, uint mask, out StatxBuffer buffer);
}
