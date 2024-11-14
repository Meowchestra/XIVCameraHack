using System.Globalization;
using System.Text;

namespace CameraHackTool.Util;

public class MemoryManager
{

    private static MemoryManager? _instance;
    /// <summary>
    /// Singleton instance of the MemoryManager
    /// </summary>
    public static MemoryManager Instance
    {
        get { return
            // create an instance of the MemoryManager if the value is null
            _instance ??= new MemoryManager(); }
    }

    /// <summary>
    /// The mem instance
    /// </summary>
    public Mem MemLib { get; }

    public long TimeStopAsm;
    public string? BaseAddress { get; set; }
    public string? CameraAddress { get; set; }
    public string? GposeAddress { get; set; }
    public string? GposeEntityOffset { get; set; }
    public string? GposeCheckAddress { get; set; }
    public string? GposeCheck2Address { get; set; }
    public string? TargetAddress { get; set; }
    public string? WeatherAddress { get; set; }
    public string? TimeAddress { get; set; }
    public string? TerritoryAddress { get; set; }
    public string? MusicOffset { get; set; }
    public string? GposeFilters { get; set; }
    public string? SkeletonAddress { get; set; }
    public string? SkeletonAddress2 { get; set; }
    public string? SkeletonAddress3 { get; set; }
    public string? SkeletonAddress4 { get; set; }
    public string? SkeletonAddress5 { get; set; }
    public string? SkeletonAddress6 { get; set; }

    public string? SkeletonAddress7 { get; set; }

    public string? PhysicsAddress { get; set; }
    public string? PhysicsAddress2 { get; set; }
    public string? PhysicsAddress3 { get; set; }
    public string? CharacterRenderAddress { get; set; }
    public string? CharacterRenderAddress2 { get; set; }
    /// <summary>
    /// Constructor for the singleton memory manager
    /// </summary>
    public MemoryManager()
    {
        // create a new instance of Mem
        MemLib = new Mem();
    }

    /// <summary>
    /// Open the process in MemLib
    /// </summary>
    /// <param name="pid"></param>
    public void OpenProcess(int pid)
    {
        // open the process
        if (!MemLib.OpenProcess(pid.ToString()))
            throw new Exception("Couldn't open process!");
    }

    /// <summary>
    /// Get a string for use in memlib
    /// </summary>
    /// <returns></returns>
    public bool IsReady()
    {
        return MemLib.TheProc is { HasExited: false };
    }
    public string? GetBaseAddress(long offset)
    {
        return (MemLib.TheProc?.MainModule?.BaseAddress.ToInt64() + offset)?.ToString("X");
    }

    /// <summary>
    /// Returns if there is a process opened
    /// </summary>
    /// <returns></returns>

    /// <summary>
    /// Adds two hex strings together
    /// </summary>
    /// <param name="a"></param>
    /// <param name="b"></param>
    /// <returns></returns>
    public static string? Add(string? a, string b)
    {
        return a != null ? (long.Parse(a, NumberStyles.HexNumber) + long.Parse(b, NumberStyles.HexNumber)).ToString("X") : null;
    }

    public static string GetAddressString(string baseAddr, params string[] addr)
    {
        var ret = baseAddr + ",";

        ret = addr.Aggregate(ret, (current, a) => current + a + ",");

        return ret.TrimEnd(',');
    }

    public static string GetAddressString(params string?[] addr)
    {
        var ret = addr.Aggregate("", (current, a) => current + a + ",");

        return ret.TrimEnd(',');
    }
    public static string ByteArrayToString(byte[]? ba)
    {
        if (ba != null)
        {
            var hex = new StringBuilder(ba.Length * 2);
            foreach (var b in ba)
                hex.Append($"{b:x2} ");
            var str = hex.ToString();
            return str.Remove(str.Length - 1);
        }

        return "0";
    }
    public static string ByteArrayToStringU(byte[]? ba)
    {
        if (ba != null)
        {
            var hex = new StringBuilder(ba.Length * 2);
            foreach (var b in ba)
                hex.Append($"{b:x2} ");
            var str = hex.ToString();
            var stre = str.ToUpper();
            return stre.Remove(stre.Length - 1);
        }

        return "0";
    }
    public static byte[] StringToByteArray(string hex)
    {
        var numberChars = hex.Length;
        var bytes = new byte[numberChars / 2];
        for (var i = 0; i < numberChars; i += 2)
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        return bytes;
    }
}