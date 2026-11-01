using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ServerGuard.Agent;

internal sealed record HealthMetrics(string sampledAt, double? cpuPercent, long? memoryTotalBytes, long? memoryUsedBytes, long? diskTotalBytes, long? diskUsedBytes);
internal sealed record AgentEvent(string sourceEventId, string kind, string severity, string occurredAt, Dictionary<string, string> payload);

[SupportedOSPlatform("windows")]
internal sealed class TelemetryCollector
{
    [StructLayout(LayoutKind.Sequential)]
    private sealed class MemoryStatus
    {
        public uint Length = (uint)Marshal.SizeOf<MemoryStatus>();
        public uint Load = 0;
        public ulong TotalPhysical = 0;
        public ulong AvailablePhysical = 0;
        public ulong TotalPageFile = 0;
        public ulong AvailablePageFile = 0;
        public ulong TotalVirtual = 0;
        public ulong AvailableVirtual = 0;
        public ulong AvailableExtendedVirtual = 0;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out System.Runtime.InteropServices.ComTypes.FILETIME idle, out System.Runtime.InteropServices.ComTypes.FILETIME kernel, out System.Runtime.InteropServices.ComTypes.FILETIME user);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx([In, Out] MemoryStatus status);
    private (ulong Idle, ulong Total)? previous = ReadCpu();
    private static ulong Ticks(System.Runtime.InteropServices.ComTypes.FILETIME value) => ((ulong)(uint)value.dwHighDateTime << 32) | (uint)value.dwLowDateTime;
    private static (ulong Idle, ulong Total)? ReadCpu()
    {
        if (!GetSystemTimes(out var idle, out var kernel, out var user)) return null;
        var kernelTicks = Ticks(kernel);
        var userTicks = Ticks(user);
        if (ulong.MaxValue - userTicks < kernelTicks) return null;
        return (Ticks(idle), kernelTicks + userTicks);
    }
    public HealthMetrics Collect()
    {
        var current = ReadCpu();
        double? cpu = null;
        if (current is { } latest && previous is { } before && latest.Total > before.Total && latest.Idle >= before.Idle)
        {
            var total = latest.Total - before.Total;
            var idle = latest.Idle - before.Idle;
            if (idle <= total) cpu = (double)(total - idle) / total * 100;
        }
        previous = current;
        long? memoryTotal = null;
        long? memoryUsed = null;
        var memory = new MemoryStatus();
        if (GlobalMemoryStatusEx(memory) && memory.TotalPhysical is > 0 and <= 9007199254740991 && memory.AvailablePhysical <= memory.TotalPhysical)
        {
            memoryTotal = (long)memory.TotalPhysical;
            memoryUsed = (long)(memory.TotalPhysical - memory.AvailablePhysical);
        }
        long? diskTotal = null;
        long? diskUsed = null;
        try
        {
            var drive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)!);
            var total = drive.TotalSize;
            var available = drive.AvailableFreeSpace;
            if (total is > 0 and <= 9007199254740991 && available >= 0 && available <= total) { diskTotal = total; diskUsed = total - available; }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
        return new HealthMetrics(DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture), cpu, memoryTotal, memoryUsed, diskTotal, diskUsed);
    }
}
