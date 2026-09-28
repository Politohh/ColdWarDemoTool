using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ColdWarDemo.Core;

public sealed record DemoMetadata(string Map, string Mode, DateTimeOffset? RecordedAt,
    int FirstTimeMs, int LastTimeMs, int FileBytes, ushort DataVersion,
    int InitialStateBytes, int InitialAuxiliaryBytes, int FooterStateBytes,
    int FrameBytes, string Sha256)
{
    public TimeSpan Duration => TimeSpan.FromMilliseconds((long)LastTimeMs - FirstTimeMs);
    public string DisplayDuration => Duration.TotalHours >= 1
        ? Duration.ToString(@"h\:mm\:ss") : Duration.ToString(@"m\:ss");
    public string DisplayDate => RecordedAt?.ToLocalTime().ToString("dd MMM yyyy · HH:mm") ?? "Date unavailable";
    public string DisplaySize => $"{FileBytes / 1_000_000.0:0.00} MB";
    public string DisplayMap => Map switch
    {
        "mp_slums_rm" => "Slums", "mp_miami" => "Miami", "mp_miami_strike" => "Miami Strike",
        "mp_moscow" => "Moscow", "mp_nuketown" or "mp_nuketown_1984" => "Nuketown ’84",
        "mp_sm_gas_station" => "Diesel", "mp_mall" => "The Pines", "mp_kgb" => "KGB",
        "mp_village_rm" => "Standoff",
        _ => Map == "" ? "Unknown map" : Map
    };
    public string DisplayMode => Mode switch
    {
        "dom" => "Domination", "dm" => "Free-for-All", "war" or "tdm" => "Team Deathmatch",
        "koth" => "Hardpoint", "sd" => "Search & Destroy", "dem" => "Demolition",
        "conf" => "Kill Confirmed", "ctf" => "Capture the Flag", _ => Mode == "" ? "Unknown mode" : Mode
    };
    public string SuggestedName => $"{Sanitize(Map == "" ? "replay" : Map)}-{Sanitize(Mode == "" ? "demo" : Mode)}-" +
        (RecordedAt?.ToLocalTime().ToString("yyyy-MM-dd-HHmmss") ?? DateTime.Now.ToString("yyyy-MM-dd-HHmmss")) + ".demo";
    private static string Sanitize(string value) => Regex.Replace(value, @"[^a-zA-Z0-9_-]", "_");
}

public sealed record DemoEnvelope(int Length, int FooterOffset, int FooterBytes, int InitialEnd,
    int FirstTimeMs, int LastTimeMs);
public sealed record InitialBlocks(int FirstCompressed, int FirstExpanded, int SecondCompressed,
    int SecondExpanded, int InitialEnd, byte[] StatePrefix);

public static class DemoFormat
{
    public const int MaxBytes = 512 * 1024 * 1024;
    public const uint Magic = 12345;
    public static ReadOnlySpan<byte> MagicBytes => [0x39, 0x30, 0, 0];
    private const int StateLimit = 0x192000;
    private const int AuxiliaryLimit = 0xA0000;

    public static uint Word(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));

    public static InitialBlocks ReadInitial(Func<ulong, int, byte[]> read, ulong address)
    {
        byte[] prefix = read(address, 16);
        if (Word(prefix, 0) != Magic) throw Invalid("No native demo header.");
        int first = Bounded(Word(prefix, 8), 1, StateLimit);
        int expanded = Bounded(Word(prefix, 12), 2, StateLimit);
        byte[] firstState = DecodeLz4(read(checked(address + 16), first), expanded);
        ulong secondHeader = checked(address + 16UL + (uint)first);
        byte[] second = read(secondHeader, 8);
        int length2 = Bounded(Word(second, 0), 1, AuxiliaryLimit);
        int expanded2 = Bounded(Word(second, 4), 2, AuxiliaryLimit);
        _ = DecodeLz4(read(checked(secondHeader + 8), length2), expanded2);
        return new(first, expanded, length2, expanded2, checked(24 + first + length2),
            firstState[..Math.Min(firstState.Length, 512)]);
    }

    public static DemoEnvelope? FindFooter(ReadOnlySpan<byte> data, int end, int initialEnd)
    {
        if (end < Math.Max(60, initialEnd + 36) || end > data.Length ||
            Word(data, end - 4) != Magic) return null;
        uint footerSize = Word(data, end - 8);
        if (footerSize < 28 || footerSize > AuxiliaryLimit + 28 || footerSize > end - 8) return null;
        int footer = end - 8 - (int)footerSize;
        if (footer < initialEnd || footer + 28 > end - 8) return null;
        uint compressed = Word(data, footer + 20), expanded = Word(data, footer + 24);
        uint first = Word(data, footer), last = Word(data, footer + 4);
        if (compressed != footerSize - 28 || expanded > 0x20000 || expanded < 1 ||
            first > last || last > int.MaxValue) return null;
        return new(end, footer, (int)footerSize, initialEnd, (int)first, (int)last);
    }

    public static DemoMetadata Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 60 || data.Length > MaxBytes || Word(data, 0) != Magic)
            throw Invalid("This is not a complete supported native Cold War demo.");
        int cursor = 8;
        byte[][] blocks = new byte[2][];
        for (int i = 0; i < 2; i++)
        {
            Ensure(data, cursor, 8);
            int compressed = Bounded(Word(data, cursor), 1, i == 0 ? StateLimit : AuxiliaryLimit);
            int expanded = Bounded(Word(data, cursor + 4), 2, i == 0 ? StateLimit : AuxiliaryLimit);
            cursor = checked(cursor + 8);
            Ensure(data, cursor, compressed);
            blocks[i] = DecodeLz4(data.Slice(cursor, compressed), expanded);
            cursor = checked(cursor + compressed);
        }
        DemoEnvelope envelope = FindFooter(data, data.Length, cursor) ??
            throw Invalid("The demo is incomplete or its footer is invalid.");
        int footerLength = checked((int)Word(data, envelope.FooterOffset + 20));
        int footerExpanded = checked((int)Word(data, envelope.FooterOffset + 24));
        _ = DecodeLz4(data.Slice(envelope.FooterOffset + 28, footerLength), footerExpanded);
        ReadOnlySpan<byte> state = blocks[0];
        string prefix = Encoding.Latin1.GetString(state[..Math.Min(state.Length, 512)]);
        Match mapMatch = Regex.Match(prefix, @"\b(?:mp|zm|cp)_[a-zA-Z0-9_]+\x00");
        string map = mapMatch.Success ? mapMatch.Value.TrimEnd('\0') : "";
        string mode = "";
        if (mapMatch.Success)
        {
            int end = mapMatch.Index;
            while (end > 0 && prefix[end - 1] == '\0') end--;
            int start = end;
            while (start > 0 && (char.IsAsciiLetter(prefix[start - 1]) || prefix[start - 1] == '_')) start--;
            if (end - start is > 0 and < 32) mode = prefix[start..end];
        }
        DateTimeOffset? recorded = null;
        Match build = Regex.Match(prefix, @"[A-Z]{2}-[A-Z0-9 -]{3,80} CL\([0-9]+\)");
        if (build.Success && build.Index >= 4)
        {
            uint timestamp = Word(state, build.Index - 4);
            if (timestamp is >= 946684800 and <= 4102444800) recorded = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        }
        return new(map, mode, recorded, envelope.FirstTimeMs, envelope.LastTimeMs, data.Length,
            BinaryPrimitives.ReadUInt16LittleEndian(state), blocks[0].Length, blocks[1].Length,
            footerExpanded, envelope.FooterOffset - cursor, Convert.ToHexStringLower(SHA256.HashData(data)));
    }

    public static byte[] ReadFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 60 or > MaxBytes) throw Invalid("The file is incomplete or exceeds the 512 MB demo limit.");
        byte[] data = new byte[(int)stream.Length];
        stream.ReadExactly(data);
        return data;
    }

    public static byte[] DecodeLz4(ReadOnlySpan<byte> source, int expected)
    {
        if (expected < 1 || expected > StateLimit) throw Invalid("Invalid expanded block size.");
        byte[] result = new byte[expected];
        int input = 0, output = 0;
        while (input < source.Length)
        {
            byte token = source[input++];
            int literals = Extended(source, ref input, token >> 4);
            if (literals > source.Length - input || literals > expected - output) throw Invalid("Invalid LZ4 literals.");
            source.Slice(input, literals).CopyTo(result.AsSpan(output));
            input += literals;
            output += literals;
            if (input == source.Length) break;
            if (source.Length - input < 2) throw Invalid("Truncated LZ4 offset.");
            int offset = BinaryPrimitives.ReadUInt16LittleEndian(source.Slice(input, 2));
            input += 2;
            if (offset < 1 || offset > output) throw Invalid("Invalid LZ4 offset.");
            int match = checked(Extended(source, ref input, token & 15) + 4);
            if (match > expected - output) throw Invalid("Invalid LZ4 match length.");
            // Byte-wise copy is intentional: an LZ4 match may overlap its own output.
            for (int j = 0; j < match; j++) result[output + j] = result[output + j - offset];
            output += match;
        }
        if (output != expected) throw Invalid("The compressed block does not expand to its declared size.");
        return result;
    }

    private static int Extended(ReadOnlySpan<byte> source, ref int cursor, int length)
    {
        if (length != 15) return length;
        byte extra;
        do
        {
            if (cursor >= source.Length) throw Invalid("Truncated LZ4 length.");
            extra = source[cursor++];
            length = checked(length + extra);
        } while (extra == 255);
        return length;
    }
    private static void Ensure(ReadOnlySpan<byte> data, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset > data.Length - length) throw Invalid("Truncated demo block.");
    }
    private static int Bounded(uint value, int minimum, int maximum) =>
        value >= minimum && value <= maximum ? (int)value : throw Invalid("Invalid native demo block size.");
    private static InvalidDataException Invalid(string message) => new(message);
}
