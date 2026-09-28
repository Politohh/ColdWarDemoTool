using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ColdWarDemo.Core;

public sealed record GameProcess(int Pid, string Name)
{
    public override string ToString() => $"Cold War · PID {Pid}";
    public static IReadOnlyList<GameProcess> Find()
    {
        if (!OperatingSystem.IsWindows()) return [];
        var result = new List<GameProcess>();
        foreach (Process process in Process.GetProcessesByName("BlackOpsColdWar"))
        {
            using (process) result.Add(new(process.Id, process.ProcessName));
        }
        return result.OrderBy(x => x.Pid).ToArray();
    }
}

public sealed record MemoryRegion(ulong Address, ulong Size, ulong Allocation, uint Protect, uint Type);
public sealed record MemoryRun(ulong Address, int Size);

[SupportedOSPlatform("windows")]
public sealed class ProcessMemory : IDisposable
{
    public const uint RequestedAccess = 0x410; // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    private readonly SafeProcessHandle handle;
    public int Pid { get; }
    public uint GrantedAccess { get; }
    public string ExecutablePath { get; }
    public DateTimeOffset CreatedUtc { get; }

    public ProcessMemory(int pid)
    {
        if (!Environment.Is64BitProcess) throw new InvalidOperationException("Use the 64-bit application.");
        Pid = pid;
        handle = Native.OpenProcess(RequestedAccess, false, pid);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Cold War could not be opened for reading. Check that it is running at the same Windows privilege level.");
        }
        try
        {
            byte[] info = new byte[56]; // PUBLIC_OBJECT_BASIC_INFORMATION
            int status = Native.NtQueryObject(handle, 0, info, (uint)info.Length, out _);
            if (status != 0) throw new InvalidOperationException($"Could not verify process access (NTSTATUS 0x{status:X8}).");
            GrantedAccess = DemoFormat.Word(info, 4);
            const uint mutationRights = 0x2 | 0x8 | 0x20; // CREATE_THREAD | VM_OPERATION | VM_WRITE
            if ((GrantedAccess & mutationRights) != 0 || (GrantedAccess & 0x10) == 0)
                throw new InvalidOperationException("Unexpected process access rights. The read was stopped.");
            var path = new StringBuilder(32768);
            uint pathLength = (uint)path.Capacity;
            if (!Native.QueryFullProcessImageName(handle, 0, path, ref pathLength)) throw Error();
            ExecutablePath = path.ToString();
            if (!Path.GetFileName(ExecutablePath).Equals("BlackOpsColdWar.exe", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The selected process is not Cold War.");
            if (!Native.GetProcessTimes(handle, out long created, out _, out _, out _)) throw Error();
            CreatedUtc = DateTimeOffset.FromFileTime(created).ToUniversalTime();
        }
        catch { handle.Dispose(); throw; }
    }

    public void EnsureRunning()
    {
        if (!Native.GetExitCodeProcess(handle, out uint exitCode) || exitCode != 259)
            throw new InvalidOperationException("Cold War closed during the search. Load the replay and try again.");
    }

    public byte[] Read(ulong address, int length)
    {
        byte[] data = new byte[length];
        ReadInto(address, data, length);
        return data;
    }

    public void ReadInto(ulong address, byte[] buffer, int length)
    {
        if (length < 1 || length > buffer.Length || length > 16 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(length));
        bool ok = Native.ReadProcessMemory(handle, ToPointer(address), buffer, (nuint)length, out nuint read);
        if (!ok || read != (nuint)length)
            throw new IOException($"Memory at 0x{address:X} became unavailable (read {read}/{length} bytes).");
    }

    public IReadOnlyList<MemoryRegion> Regions(CancellationToken cancellation)
    {
        var result = new List<MemoryRegion>();
        ulong address = 0;
        nuint structureSize = (nuint)Marshal.SizeOf<Native.MemoryBasicInformation>();
        if (structureSize != 48) throw new InvalidOperationException("Unexpected Windows memory-query structure size.");
        while (address < 0x7FFFFFFFFFFF)
        {
            cancellation.ThrowIfCancellationRequested();
            if (Native.VirtualQueryEx(handle, ToPointer(address), out var info, structureSize) == 0) break;
            ulong start = (ulong)(nuint)info.BaseAddress, size = (ulong)info.RegionSize;
            if (size == 0 || start + size <= address) break;
            uint protection = info.Protect & 0xFF;
            bool readable = protection is 0x2 or 0x4 or 0x8 or 0x20 or 0x40 or 0x80;
            if (info.State == 0x1000 && readable && (info.Protect & 0x100) == 0)
                result.Add(new(start, size, (ulong)(nuint)info.AllocationBase, info.Protect, info.Type));
            address = checked(start + size);
        }
        EnsureRunning();
        return result;
    }

    public IEnumerable<MemoryRun> ResidentRuns(MemoryRegion region, CancellationToken cancellation)
    {
        const int pageSize = 4096;
        ulong pages = region.Size / pageSize;
        ulong runStart = 0;
        int runSize = 0;
        for (ulong first = 0; first < pages; first += 16384)
        {
            cancellation.ThrowIfCancellationRequested();
            int count = (int)Math.Min(16384UL, pages - first);
            var entries = new Native.WorkingSetExInformation[count];
            for (int i = 0; i < count; i++) entries[i].VirtualAddress = ToPointer(region.Address + (first + (uint)i) * pageSize);
            uint bytes = checked((uint)(count * Marshal.SizeOf<Native.WorkingSetExInformation>()));
            if (!Native.QueryWorkingSetEx(handle, entries, bytes)) throw Error();
            foreach (var entry in entries)
            {
                if ((entry.VirtualAttributes & 1) != 0)
                {
                    if (runSize == 0) runStart = (ulong)(nuint)entry.VirtualAddress;
                    runSize += pageSize;
                    if (runSize >= 4 * 1024 * 1024)
                    {
                        yield return new(runStart, runSize);
                        runSize = 0;
                    }
                }
                else if (runSize > 0)
                {
                    yield return new(runStart, runSize);
                    runSize = 0;
                }
            }
        }
        if (runSize > 0) yield return new(runStart, runSize);
    }

    private static nint ToPointer(ulong address) => unchecked((nint)(long)address);
    private static Win32Exception Error() => new(Marshal.GetLastWin32Error());
    public void Dispose() => handle.Dispose();

    // This API surface deliberately contains no remote write, allocation, thread, hook, or debugger functions.
    private static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct MemoryBasicInformation
        {
            public nint BaseAddress, AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public nuint RegionSize;
            public uint State, Protect, Type;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct WorkingSetExInformation { public nint VirtualAddress; public nuint VirtualAttributes; }
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
        [DllImport("ntdll.dll")]
        internal static extern int NtQueryObject(SafeProcessHandle handle, int infoClass, [Out] byte[] info, uint length, out uint returned);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryFullProcessImageNameW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryFullProcessImageName(SafeProcessHandle handle, uint flags, StringBuilder path, ref uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetProcessTimes(SafeProcessHandle handle, out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(SafeProcessHandle handle, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ReadProcessMemory(SafeProcessHandle handle, nint address, [Out] byte[] data, nuint size, out nuint read);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern nuint VirtualQueryEx(SafeProcessHandle handle, nint address, out MemoryBasicInformation info, nuint length);
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "K32QueryWorkingSetEx")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryWorkingSetEx(SafeProcessHandle handle, [In, Out] WorkingSetExInformation[] entries, uint length);
    }
}
