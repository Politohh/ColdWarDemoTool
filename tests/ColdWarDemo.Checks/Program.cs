using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using ColdWarDemo.Core;

int passed = 0;
var checks = new List<object>();
string? Arg(string flag)
{
    int index = Array.IndexOf(args, flag);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}
void Check(string name, bool condition)
{
    if (!condition) throw new InvalidOperationException("FAILED: " + name);
    checks.Add(new { name, passed = true });
    passed++;
    Console.WriteLine("PASS " + name);
}
void MustReject(string name, ReadOnlySpan<byte> data)
{
    try { _ = DemoFormat.Parse(data); }
    catch (Exception e) when (e is InvalidDataException or OverflowException or ArgumentException)
    {
        Check(name, true);
        return;
    }
    Check(name, false);
}
string folder = Path.GetFullPath(Arg("--work") ?? Path.Combine(Path.GetTempPath(), "ColdWarDemoTool-checks", Guid.NewGuid().ToString("N")));
Directory.CreateDirectory(folder);
string slumsPath = Arg("--slums") ?? throw new ArgumentException("Provide --slums with the recovered retail Slums demo.");
CapturedDemo slums = DemoStorage.Open(slumsPath);
Check("Retail Slums identity", slums.Metadata.Map == "mp_slums_rm" && slums.Metadata.Mode == "dom");
Check("Retail embedded recording time", slums.Metadata.RecordedAt == new DateTimeOffset(2026, 9, 4, 16, 28, 40, TimeSpan.Zero));
Check("Retail complete duration", slums.Metadata.LastTimeMs - slums.Metadata.FirstTimeMs == 625184);
Check("Retail recovered byte identity", slums.Metadata.Sha256 == "a05061fc933945d4058922b351ac37fba9e53a0d90fde8ce76bf68bb39dc34f5");
Check("Retail format version retained", slums.Metadata.DataVersion == 449);
Check("Retail three expanded blocks", slums.Metadata.InitialStateBytes == 1018027 && slums.Metadata.InitialAuxiliaryBytes == 3261 && slums.Metadata.FooterStateBytes == 6573);
int initialEnd = 8;
for (int i = 0; i < 2; i++) initialEnd = checked(initialEnd + 8 + (int)DemoFormat.Word(slums.Data, initialEnd));
foreach (int cut in new[] { 0, 15, 59, 100, initialEnd - 1, initialEnd, slums.Data.Length - 9, slums.Data.Length - 1 })
    MustReject("Reject truncated demo at " + cut, slums.Data.AsSpan(0, cut));
foreach (int position in new[] { 0, 8, 12, slums.Data.Length - 8, slums.Data.Length - 4 })
{
    byte[] corrupted = (byte[])slums.Data.Clone();
    BinaryPrimitives.WriteUInt32LittleEndian(corrupted.AsSpan(position, 4), uint.MaxValue);
    MustReject("Reject corrupt size or magic at " + position, corrupted);
}
byte[] missingFooter = (byte[])slums.Data.Clone();
int footer = slums.Data.Length - 8 - (int)DemoFormat.Word(slums.Data, slums.Data.Length - 8);
BinaryPrimitives.WriteUInt32LittleEndian(missingFooter.AsSpan(footer + 20, 4), 1);
MustReject("Reject inconsistent footer", missingFooter);
byte[] overlappingFooter = (byte[])slums.Data.Clone();
BinaryPrimitives.WriteUInt32LittleEndian(overlappingFooter.AsSpan(slums.Data.Length - 8, 4), (uint)slums.Data.Length);
MustReject("Reject overlapping footer", overlappingFooter);
string firstSave = DemoStorage.Save(slums, folder, includeMetadata: true).Path;
string secondSave = DemoStorage.Save(slums, folder, includeMetadata: true).Path;
Check("Save preserves bytes", Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(firstSave))) == slums.Metadata.Sha256);
Check("Repeated save never overwrites", firstSave != secondSave && File.Exists(firstSave) && File.Exists(secondSave));
Check("Save creates parseable details", JsonDocument.Parse(File.ReadAllText(firstSave + ".json")).RootElement.GetProperty("validation").GetProperty("lz4Blocks").GetBoolean());
Check("Saved copy reopens", DemoStorage.Open(secondSave).Metadata == slums.Metadata);
string orphanFolder = Path.Combine(folder, "existing-metadata");
Directory.CreateDirectory(orphanFolder);
string orphanMetadata = Path.Combine(orphanFolder, slums.Metadata.SuggestedName + ".json");
File.WriteAllText(orphanMetadata, "existing metadata");
SaveResult orphanSave = DemoStorage.Save(slums, orphanFolder, true);
Check("Existing metadata is never overwritten", File.ReadAllText(orphanMetadata) == "existing metadata" && orphanSave.Path + ".json" != orphanMetadata && orphanSave.MetadataWarning is null);
if (Arg("--local") is { } localPath)
{
    CapturedDemo local = DemoStorage.Open(localPath);
    Check("Older local format parses", local.Metadata.DataVersion == 321 && local.Metadata.Map == "mp_miami" && local.Metadata.Mode == "dm");
    Check("Older local blocks and timeline", local.Metadata.FrameBytes > 0 && local.Metadata.LastTimeMs > local.Metadata.FirstTimeMs);
}
if (Arg("--live") is { } pidText)
{
    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
    int pid = int.Parse(pidText);
    using (var read = new ProcessMemory(pid))
    {
        Check("Live handle has VM_READ", (read.GrantedAccess & 0x10) != 0);
        Check("Live handle excludes mutation rights", (read.GrantedAccess & 0x2A) == 0);
        Check("Live exact Cold War executable", Path.GetFileName(read.ExecutablePath).Equals("BlackOpsColdWar.exe", StringComparison.OrdinalIgnoreCase));
    }
    ScanResult live = ReplayScanner.Scan(pid, new Progress<ScanProgress>(p => Console.WriteLine(p.Description)), CancellationToken.None,
        TimeSpan.FromMinutes(2), found: d => Console.WriteLine($"FOUND {d.Metadata.Map} {d.Metadata.Mode} {d.Metadata.DisplayDate} {d.Metadata.DisplayDuration}"));
    Console.WriteLine(JsonSerializer.Serialize(new { live.BytesRead, live.ReadFailures, live.Elapsed, live.Complete, demos = live.Demos.Select(d => d.Metadata) }, new JsonSerializerOptions { WriteIndented = true }));
    File.WriteAllText(Path.Combine(folder, "live-scan.json"), JsonSerializer.Serialize(live with { Demos = live.Demos.Select(d => d with { Data = [] }).ToArray() }, new JsonSerializerOptions { WriteIndented = true }));
    foreach (CapturedDemo demo in live.Demos)
    {
        string saved = DemoStorage.Save(demo, folder, true).Path;
        Check("Live capture byte stable " + demo.Metadata.Map, DemoStorage.Open(saved).Metadata.Sha256 == demo.Metadata.Sha256);
    }
    Check("Loaded replay recovered", live.Demos.Count > 0);
}
File.WriteAllText(Path.Combine(folder, "checks.json"), JsonSerializer.Serialize(new { passed, checks }, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"All {passed} checks passed.");
