using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace ColdWarDemo.Core;

public sealed record CaptureSource(int Pid, string ExecutablePath, DateTimeOffset ProcessCreatedUtc,
    ulong Address, uint RequestedAccess, uint GrantedAccess, DateTimeOffset CapturedUtc);
public sealed record CapturedDemo(byte[] Data, DemoMetadata Metadata, CaptureSource? Source, string? OriginalPath)
{
    public string SourceLabel => Source is not null ? $"Captured from Cold War · PID {Source.Pid}" : "Opened from disk";
    public string Title => Metadata.DisplayMap;
    public string Subtitle => $"{Metadata.DisplayMode} · {Metadata.DisplayDuration}";
    public string RecordedLabel => Metadata.DisplayDate;
}
public sealed record ScanProgress(long BytesRead, int RegionsVisited, int TotalRegions, int Found, string Stage)
{
    public string Description => $"{Stage} · {BytesRead / (1024.0 * 1024 * 1024):0.0} GB checked · {Found} found";
}
public sealed record ScanResult(IReadOnlyList<CapturedDemo> Demos, long BytesRead, int ReadFailures,
    TimeSpan Elapsed, bool Complete);

[SupportedOSPlatform("windows")]
public static class ReplayScanner
{
    public static ScanResult Scan(int pid, IProgress<ScanProgress>? progress, CancellationToken cancellation,
        TimeSpan? timeLimit = null, Action<CapturedDemo>? found = null)
    {
        using var memory = new ProcessMemory(pid);
        var timer = Stopwatch.StartNew();
        TimeSpan limit = timeLimit ?? TimeSpan.FromMinutes(3);
        IReadOnlyList<MemoryRegion> regions = memory.Regions(cancellation);
        var readableEnds = new Dictionary<ulong, ulong>();
        // A buffer can cross protection boundaries, but cannot cross an unreadable gap.
        for (int i = regions.Count - 1; i >= 0; i--)
        {
            MemoryRegion region = regions[i];
            ulong end = checked(region.Address + region.Size);
            if (i + 1 < regions.Count && regions[i + 1].Address == end && regions[i + 1].Allocation == region.Allocation)
                end = readableEnds[regions[i + 1].Address];
            readableEnds[region.Address] = end;
        }
        var targets = regions.Where(r => r.Type is 0x20000 or 0x40000 && r.Size >= 4096).ToArray();
        var demos = new List<CapturedDemo>();
        var hashes = new HashSet<string>(StringComparer.Ordinal);
        var candidates = new HashSet<ulong>();
        long bytesRead = 0;
        int readFailures = 0, visited = 0;
        byte[] buffer = new byte[4 * 1024 * 1024 + 15];
        byte[] tail = new byte[15];
        ulong previousEnd = 0;
        TimeSpan lastProgress = TimeSpan.Zero;
        bool complete = true;
        foreach (MemoryRegion region in targets)
        {
            cancellation.ThrowIfCancellationRequested();
            if (timer.Elapsed > limit) { complete = false; break; }
            visited++;
            foreach (MemoryRun run in memory.ResidentRuns(region, cancellation))
            {
                cancellation.ThrowIfCancellationRequested();
                if (timer.Elapsed > limit) { complete = false; break; }
                int carry = previousEnd == run.Address ? 15 : 0;
                // Reads use a separate array so a preceding tail is never overwritten by the native call.
                byte[] raw;
                try { raw = memory.Read(run.Address, run.Size); }
                catch (IOException) { readFailures++; previousEnd = 0; continue; }
                bytesRead += run.Size;
                if (carry > 0) tail.CopyTo(buffer, 0);
                raw.CopyTo(buffer, carry);
                int available = run.Size + carry;
                ReadOnlySpan<byte> data = buffer.AsSpan(0, available);
                int position = 0;
                while (position < available)
                {
                    int match = data[position..].IndexOf(DemoFormat.MagicBytes);
                    if (match < 0) break;
                    position += match;
                    ulong address = checked(run.Address - (uint)carry + (uint)position);
                    position += 4;
                    // A header at a chunk edge must be reconsidered with the next chunk's carry.
                    if (position + 12 > available || !candidates.Add(address)) continue;
                    uint firstLength = DemoFormat.Word(data, position + 4), expanded = DemoFormat.Word(data, position + 8);
                    if (firstLength is < 32 or > 0x192000 || expanded is < 1024 or > 0x192000) continue;
                    try
                    {
                        InitialBlocks blocks = DemoFormat.ReadInitial(memory.Read, address);
                        CapturedDemo? demo = Extract(memory, address, readableEnds[region.Address], blocks, cancellation, timer, limit);
                        if (demo is not null && hashes.Add(demo.Metadata.Sha256))
                        {
                            demos.Add(demo);
                            found?.Invoke(demo);
                            progress?.Report(new(bytesRead, visited, targets.Length, demos.Count, "Replay found"));
                            if (demos.Count >= 8) { complete = false; break; }
                        }
                    }
                    catch (Exception e) when (e is InvalidDataException or IOException or OverflowException or ArgumentException)
                    {
                        // A magic value in unrelated game data is not a replay. Reject without modifying the process.
                    }
                }
                previousEnd = checked(run.Address + (uint)run.Size);
                raw.AsSpan(raw.Length - 15, 15).CopyTo(tail);
                if (timer.Elapsed - lastProgress >= TimeSpan.FromMilliseconds(350))
                {
                    memory.EnsureRunning();
                    progress?.Report(new(bytesRead, visited, targets.Length, demos.Count, "Searching loaded demos"));
                    lastProgress = timer.Elapsed;
                }
                if (demos.Count >= 8) break;
            }
            if (!complete) break;
        }
        progress?.Report(new(bytesRead, visited, targets.Length, demos.Count, "Search finished"));
        return new(demos, bytesRead, readFailures, timer.Elapsed, complete);
    }

    private static CapturedDemo? Extract(ProcessMemory memory, ulong address, ulong allocationEnd,
        InitialBlocks blocks, CancellationToken cancellation, Stopwatch timer, TimeSpan limit)
    {
        if (allocationEnd <= address) return null;
        int maximum = (int)Math.Min(allocationEnd - address, (ulong)DemoFormat.MaxBytes);
        using var stream = new MemoryStream();
        int searchedThrough = blocks.InitialEnd;
        while (stream.Length < maximum)
        {
            cancellation.ThrowIfCancellationRequested();
            if (timer.Elapsed > limit) return null;
            int count = Math.Min(4 * 1024 * 1024, maximum - (int)stream.Length);
            byte[] chunk = memory.Read(checked(address + (ulong)stream.Length), count);
            stream.Write(chunk);
            ReadOnlySpan<byte> data = stream.GetBuffer().AsSpan(0, (int)stream.Length);
            int position = Math.Max(blocks.InitialEnd, searchedThrough - 3);
            while (position < data.Length)
            {
                int match = data[position..].IndexOf(DemoFormat.MagicBytes);
                if (match < 0) break;
                position += match;
                int end = position + 4;
                position += 4;
                DemoEnvelope? envelope = DemoFormat.FindFooter(data, end, blocks.InitialEnd);
                if (envelope is null) continue;
                byte[] candidate = data[..end].ToArray();
                DemoMetadata metadata;
                try { metadata = DemoFormat.Parse(candidate); }
                catch (InvalidDataException) { continue; }
                using var secondHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                for (int offset = 0; offset < end; offset += 4 * 1024 * 1024)
                {
                    cancellation.ThrowIfCancellationRequested();
                    secondHash.AppendData(memory.Read(checked(address + (uint)offset), Math.Min(4 * 1024 * 1024, end - offset)));
                }
                if (Convert.ToHexStringLower(secondHash.GetHashAndReset()) != metadata.Sha256) return null;
                var source = new CaptureSource(memory.Pid, memory.ExecutablePath, memory.CreatedUtc, address,
                    ProcessMemory.RequestedAccess, memory.GrantedAccess, DateTimeOffset.UtcNow);
                return new(candidate, metadata, source, null);
            }
            searchedThrough = data.Length;
        }
        return null;
    }
}

public sealed record SaveResult(string Path, string? MetadataWarning);

public static class DemoStorage
{
    public static CapturedDemo Open(string path)
    {
        byte[] data = DemoFormat.ReadFile(path);
        return new(data, DemoFormat.Parse(data), null, Path.GetFullPath(path));
    }

    public static SaveResult Save(CapturedDemo demo, string folder, bool includeMetadata)
    {
        folder = Path.GetFullPath(folder);
        Directory.CreateDirectory(folder);
        string suggested = Path.GetFileName(demo.Metadata.SuggestedName);
        string? path = null;
        string temporary = Path.Combine(folder, $".cw-demo-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.Write(demo.Data);
                file.Flush(flushToDisk: true);
            }
            using (var verify = File.OpenRead(temporary))
                if (Convert.ToHexStringLower(SHA256.HashData(verify)) != demo.Metadata.Sha256)
                    throw new IOException("The saved file did not match the captured demo.");
            for (int index = 0; index < 10000; index++)
            {
                string name = index == 0 ? suggested : $"{Path.GetFileNameWithoutExtension(suggested)}-{index}.demo";
                string destination = Path.Combine(folder, name);
                if (includeMetadata && File.Exists(destination + ".json")) continue;
                try { File.Move(temporary, destination, overwrite: false); path = destination; break; }
                catch (IOException) when (File.Exists(destination)) { }
            }
            if (path is null) throw new IOException("Could not choose an unused output filename.");
            string? metadataWarning = null;
            if (includeMetadata)
            {
                var details = new
                {
                    tool = "Cold War Demo Tool", version = "0.1.1", file = Path.GetFileName(path),
                    metadata = demo.Metadata, source = demo.Source,
                    validation = new { structure = true, lz4Blocks = true,
                        stableAcrossTwoReads = demo.Source is not null,
                        nativeChecksumVerified = false, fullFrameStreamParsed = false,
                        gamePlaybackSafetyVerified = false },
                    captureMethod = "External memory reads only; no hooks, injection, remote writes, or debugger attach."
                };
                string detailsPath = path + ".json";
                string detailsTemporary = temporary + ".json";
                try
                {
                    File.WriteAllText(detailsTemporary, JsonSerializer.Serialize(details, new JsonSerializerOptions { WriteIndented = true }));
                    File.Move(detailsTemporary, detailsPath, overwrite: false);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    metadataWarning = "The demo was saved, but its metadata could not be saved: " + e.Message;
                }
                finally { if (File.Exists(detailsTemporary)) File.Delete(detailsTemporary); }
            }
            return new(path, metadataWarning);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
