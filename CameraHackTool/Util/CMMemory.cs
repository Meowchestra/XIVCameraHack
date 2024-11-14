using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows;

namespace CameraHackTool.Util;

internal struct MemoryRegionResult
{
    public UIntPtr CurrentBaseAddress { get; init; }
    public long RegionSize { get; init; }
    public UIntPtr RegionBase { get; init; }

}
public class Mem
{
    #region DllImports
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        int dwProcessId
    );

#if WINXP
#else
    [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
    private static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
        out MemoryBasicInformation32 lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
    private static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
        out MemoryBasicInformation64 lpBuffer, UIntPtr dwLength);
    
    [DllImport("kernel32.dll")]
    private static extern uint GetLastError();
    
    private UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
        out MemoryBasicInformation lpBuffer)
    {
        UIntPtr retVal;

        // TODO: Need to change this to only check once.
        if (Is64Bit || IntPtr.Size == 8)
        {
            // 64 bit
            var tmp64 = new MemoryBasicInformation64();
            retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp64, new UIntPtr((uint)Marshal.SizeOf(tmp64)));

            lpBuffer.BaseAddress       = tmp64.BaseAddress;
            lpBuffer.AllocationBase    = tmp64.AllocationBase;
            lpBuffer.AllocationProtect = tmp64.AllocationProtect;
            lpBuffer.RegionSize        = (long)tmp64.RegionSize;
            lpBuffer.State             = tmp64.State;
            lpBuffer.Protect           = tmp64.Protect;
            lpBuffer.Type              = tmp64.Type;

            return retVal;
        }

        var tmp32 = new MemoryBasicInformation32();

        retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp32, new UIntPtr((uint)Marshal.SizeOf(tmp32)));

        lpBuffer.BaseAddress       = tmp32.BaseAddress;
        lpBuffer.AllocationBase    = tmp32.AllocationBase;
        lpBuffer.AllocationProtect = tmp32.AllocationProtect;
        lpBuffer.RegionSize        = tmp32.RegionSize;
        lpBuffer.State             = tmp32.State;
        lpBuffer.Protect           = tmp32.Protect;
        lpBuffer.Type              = tmp32.Type;

        return retVal;
    }

    [DllImport("kernel32.dll")]
    private static extern void GetSystemInfo(out SystemInfo lpSystemInfo);
#endif

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    [DllImport("kernel32.dll")]
    private static extern uint SuspendThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    private static extern int ResumeThread(IntPtr hThread);

    [DllImport("dbghelp.dll")]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        int processId,
        IntPtr hFile,
        MinidumpType dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callackParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess,
        UIntPtr lpBaseAddress,
        string lpBuffer,
        UIntPtr nSize,
        out IntPtr lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetPrivateProfileString(
        string lpAppName,
        string lpKeyName,
        string lpDefault,
        StringBuilder lpReturnedString,
        uint nSize,
        string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern bool VirtualFreeEx(
        IntPtr hProcess,
        UIntPtr lpAddress,
        UIntPtr dwSize,
        uint dwFreeType
    );

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern UIntPtr VirtualAllocEx(
        IntPtr hProcess,
        UIntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern UIntPtr GetProcAddress(
        IntPtr hModule,
        string procName
    );

    [DllImport("kernel32.dll", EntryPoint = "CloseHandle")]
    private static extern bool _CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern int CloseHandle(
        IntPtr hObject
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(
        string lpModuleName
    );

    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    private static extern int WaitForSingleObject(
        IntPtr handle,
        int milliseconds
    );

    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesWritten);

    // Added to avoid casting to UIntPtr
    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32")]
    private static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        UIntPtr lpStartAddress, // raw Pointer into remote process  
        UIntPtr lpParameter,
        uint dwCreationFlags,
        out IntPtr lpThreadId
    );

    [DllImport("kernel32")]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    // privileges
    private const int ProcessCreateThread = 0x0002;
    private const int ProcessQueryInformation = 0x0400;
    public const int ProcessVmOperation = 0x0008;
    private const int ProcessVmWrite = 0x0020;
    public const int ProcessVmRead = 0x0010;

    // used for memory allocation
    private const uint MemFree = 0x10000;
    private const uint MemCommit = 0x00001000;
    private const uint MemReserve = 0x00002000;

    private const uint PageReadwrite = 0x04;
    private const uint PageWritecopy = 0x08;
    private const uint PageExecuteReadwrite = 0x40;
    private const uint PageExecuteWritecopy = 0x80;
    private const uint PageExecute = 0x10;
    private const uint PageExecuteRead = 0x20;

    private const uint PageGuard = 0x100;
    private const uint PageNoaccess = 0x01;

    private const uint MemPrivate = 0x20000;
    private const uint MemImage = 0x1000000;

    #endregion

    /// <summary>
    /// The process handle that was opened. (Use OpenProcess function to populate this variable)
    /// </summary>
    public IntPtr PHandle;

    public Process? TheProc;

    internal enum MinidumpType
    {
        MiniDumpNormal = 0x00000000,
        MiniDumpWithDataSegs = 0x00000001,
        MiniDumpWithFullMemory = 0x00000002,
        MiniDumpWithHandleData = 0x00000004,
        MiniDumpFilterMemory = 0x00000008,
        MiniDumpScanMemory = 0x00000010,
        MiniDumpWithUnloadedModules = 0x00000020,
        MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
        MiniDumpFilterModulePaths = 0x00000080,
        MiniDumpWithProcessThreadData = 0x00000100,
        MiniDumpWithPrivateReadWriteMemory = 0x00000200,
        MiniDumpWithoutOptionalData = 0x00000400,
        MiniDumpWithFullMemoryInfo = 0x00000800,
        MiniDumpWithThreadInfo = 0x00001000,
        MiniDumpWithCodeSegs = 0x00002000
    }

    private static bool IsDigitsOnly(string str)
    {
        return str.All(c => c is >= '0' and <= '9');
    }

    /// <summary>
    /// Open the PC game process with all security and access rights.
    /// </summary>
    /// <param name="proc">Use process name or process ID here.</param>
    /// <returns></returns>
    public bool OpenProcess(int pid)
    {
        if (!IsAdmin())
        {
            Debug.WriteLine("WARNING: You are NOT running this program as admin! Visit https://github.com/erfg12/memory.dll/wiki/Administrative-Privileges");
            MessageBox.Show("WARNING: You are NOT running this program as admin!");
        }

        try
        {
            if (TheProc != null && TheProc.Id == pid)
                return true;

            if (pid <= 0)
            {
                Debug.WriteLine("ERROR: OpenProcess given proc ID 0.");
                return false;
            }

            TheProc = Process.GetProcessById(pid);

            if (TheProc is { Responding: false })
            {
                Debug.WriteLine("ERROR: OpenProcess: Process is not responding or null.");
                return false;
            }
            Process.EnterDebugMode();
            PHandle = OpenProcess(0x1F0FFF, true, pid);

            if (PHandle == IntPtr.Zero)
            {
                var eCode = Marshal.GetLastWin32Error();
            }

            _mainModule = TheProc.MainModule;

            GetModules();

            // Let's set the process to 64bit or not here (cuts down on api calls)
            Is64Bit = Environment.Is64BitOperatingSystem && IsWow64Process(PHandle, out var retVal) && !retVal;

            Debug.WriteLine("Program is operating at Administrative level. Process #" + TheProc + " is open and modules are stored.");

            return true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "OpenProcess Failed");
            Debug.WriteLine("ERROR: OpenProcess has crashed.");
            return false;
        }
    }

    #region CheckSeDebugPrivilege
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, ref Luid lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool PrivilegeCheck(
        IntPtr clientToken,
        ref PrivilegeSet requiredPrivileges,
        out bool pfResult);

    [StructLayout(LayoutKind.Sequential)]
    public struct Luid
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PrivilegeSet
    {
        public UInt32 PrivilegeCount;
        public UInt32 Control;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LuidAndAttributes[] Privilege;
    }

    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    private static int CheckSeDebugPrivilege(out bool isDebugEnabled)
    {
        isDebugEnabled = false;

        if (!OpenProcessToken(GetCurrentProcess(), 0x8 /*TOKEN_QUERY*/, out var tokenHandle))
            return Marshal.GetLastWin32Error();

        var luidDebugPrivilege = new Luid();
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", ref luidDebugPrivilege))
            return Marshal.GetLastWin32Error();

        var requiredPrivileges = new PrivilegeSet
        {
            PrivilegeCount = 1,
            Control        = 1 /* PRIVILEGE_SET_ALL_NECESSARY */,
            Privilege      = new LuidAndAttributes[1]
        };

        requiredPrivileges.Privilege[0].Luid       = luidDebugPrivilege;
        requiredPrivileges.Privilege[0].Attributes = 2 /* SE_PRIVILEGE_ENABLED */;

        if (!PrivilegeCheck(tokenHandle, ref requiredPrivileges, out var bResult))
            return Marshal.GetLastWin32Error();

        // bResult == true => SeDebugPrivilege is on; otherwise it's off
        isDebugEnabled = bResult;

        CloseHandle(tokenHandle);

        return 0;
    }
    #endregion


    /// <summary>
    /// Open the PC game process with all security and access rights.
    /// </summary>
    /// <param name="proc">Use process name or process ID here.</param>
    /// <returns></returns>
    public bool OpenProcess(string proc)
    {
        return OpenProcess(GetProcIdFromName(proc));
    }

    /// <summary>
    /// Check if program is running with administrative privileges. Read about it here: https://github.com/erfg12/memory.dll/wiki/Administrative-Privileges
    /// </summary>
    /// <returns></returns>
    private static bool IsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Check if opened process is 64bit. Used primarily for get64bitCode().
    /// </summary>
    /// <returns>True if 64bit false if 32bit.</returns>
    private bool Is64BitCheck()
    {
        return Is64Bit;
    }

    private bool Is64Bit { get; set; }

    /// <summary>
    /// Builds the process modules dictionary (names with addresses).
    /// </summary>
    private void GetModules()
    {
        if (TheProc == null)
            return;

        Modules.Clear();
        foreach (ProcessModule module in TheProc.Modules)
        {
            if (!string.IsNullOrEmpty(module.ModuleName) && !Modules.ContainsKey(module.ModuleName))
                Modules.Add(module.ModuleName, module.BaseAddress);
        }
    }

    public void SetFocus()
    {
        //int style = GetWindowLong(procs.MainWindowHandle, -16);
        //if ((style & 0x20000000) == 0x20000000) //minimized
        //    SendMessage(procs.Handle, 0x0112, (IntPtr)0xF120, IntPtr.Zero);
        if (TheProc != null) SetForegroundWindow(TheProc.MainWindowHandle);
    }

    /// <summary>
    /// Get the process ID number by process name.
    /// </summary>
    /// <param name="name">Example: "eqgame". Use task manager to find the name. Do not include .exe</param>
    /// <returns></returns>
    private static int GetProcIdFromName(string name) //new 1.0.2 function
    {
        var processlist = Process.GetProcesses();

        if (name.Contains(".exe"))
            name = name.Replace(".exe", "");

        return (from theprocess in processlist where theprocess.ProcessName.Equals(name, StringComparison.CurrentCultureIgnoreCase) select theprocess.Id).FirstOrDefault();
    }

    /// <summary>
    /// Convert a byte array to a literal string
    /// </summary>
    /// <param name="buffer">Byte array to convert to byte string</param>
    /// <returns></returns>
    public string ByteArrayToStringLiteral(byte[] buffer)
    {
        var build = new StringBuilder();
        var i = 1;
        foreach (var b in buffer)
        {
            build.Append($"0x{b:X}");
            if (i < buffer.Length)
                build.Append(' ');
            i++;
        }
        return build.ToString();
    }

    /// <summary>
    /// Get code from ini file.
    /// </summary>
    /// <param name="name">label for address or code</param>
    /// <param name="file">path and name of ini file</param>
    /// <returns></returns>
    private static string LoadCode(string name, string file)
    {
        var returnCode = new StringBuilder(1024);

        if (file != "")
            GetPrivateProfileString("codes", name, "", returnCode, (uint)returnCode.Capacity, file);
        else
            returnCode.Append(name);

        return returnCode.ToString();
    }

    private static int LoadIntCode(string name, string path)
    {
        try
        {
            var intValue = Convert.ToInt32(LoadCode(name, path), 16);
            return intValue >= 0 ? intValue : 0;
        }
        catch
        {
            Debug.WriteLine("ERROR: LoadIntCode function crashed!");
            return 0;
        }
    }

    /// <summary>
    /// Dictionary with our opened process module names with addresses.
    /// </summary>
    public readonly Dictionary<string, IntPtr> Modules = new();

    /// <summary>
    /// Make a named pipe (if not already made) and call to a remote function.
    /// </summary>
    /// <param name="func">remote function to call</param>
    /// <param name="name">name of the thread</param>
    public static void ThreadStartClient(string func, string name)
    {
        //ManualResetEvent SyncClientServer = (ManualResetEvent)obj;
        using var pipeStream = new NamedPipeClientStream(name);
        if (!pipeStream.IsConnected)
            pipeStream.Connect();

        //MessageBox.Show("[Client] Pipe connection established");
        using var sw = new StreamWriter(pipeStream);
        if (!sw.AutoFlush)
            sw.AutoFlush = true;
        sw.WriteLine(func);
    }

    private ProcessModule? _mainModule;

    /// <summary>
    /// Cut a string that goes on for too long or one that is possibly merged with another string.
    /// </summary>
    /// <param name="str">The string you want to cut.</param>
    /// <returns></returns>
    private static string CutString(string str)
    {
        var sb = new StringBuilder();
        foreach (var c in str)
        {
            if (c is >= ' ' and <= '~')
                sb.Append(c);
            else
                break;
        }
        return sb.ToString();
    }

    /// <summary>
    /// Clean up a string that has bad characters in it.
    /// </summary>
    /// <param name="str">The string you want to sanitize.</param>
    /// <returns></returns>
    public static string SanitizeString(string str)
    {
        var sb = new StringBuilder();
        foreach (var c in str.Where(c => c is >= ' ' and <= '~'))
        {
            sb.Append(c);
        }
        return sb.ToString();
    }

    #region readMemory
    /// <summary>
    /// Reads up to `length ` bytes from an address.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="length">The maximum bytes to read.</param>
    /// <param name="file">path and name of ini file.</param>
    /// <returns>The bytes read or null</returns>
    public byte[] ReadBytes(string code, long length, string file = "")
    {
        var memory = new byte[length];
        var theCode = Get64BitCode(code, file);

        if (!ReadProcessMemory(PHandle, theCode, memory, (UIntPtr)length, IntPtr.Zero))
        {
            Array.Clear(memory, 0, memory.Length);
            return memory;
        }

        return memory;
    }

    /// <summary>
    /// Reads up to `length ` bytes from an address.
    /// </summary>
    /// <param name="address"></param>
    /// <param name="length">The maximum bytes to read.</param>
    /// <param name="file">path and name of ini file.</param>
    /// <returns>The bytes read or null</returns>
    public byte[] ReadBytes(UIntPtr address, long length, string file = "")
    {
        var memory = new byte[length];

        if (!ReadProcessMemory(PHandle, address, memory, (UIntPtr)length, IntPtr.Zero))
        {
            Array.Clear(memory, 0, memory.Length);
            return memory;
        }

        return memory;
    }

    /// <summary>
    /// Read a float value from an address.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="file">path and name of ini file. (OPTIONAL)</param>
    /// <param name="round">Round the value to 2 decimal places</param>
    /// <returns></returns>
    public float ReadFloat(string code, string file = "", bool round = false)
    {
        var memory = new byte[4];

        var theCode = Get64BitCode(code, file);
        try
        {
            if (ReadProcessMemory(PHandle, theCode, memory, 4, IntPtr.Zero))
            {
                var address = BitConverter.ToSingle(memory, 0);
                var returnValue = address;
                if (round)
                    returnValue = (float)Math.Round(address, 2);
                return returnValue;
            }

            return 0;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Read a string value from an address.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="file">path and name of ini file. (OPTIONAL)</param>
    /// <param name="length">length of bytes to read (OPTIONAL)</param>
    /// <param name="zeroTerminated">terminate string at null char</param>
    /// <returns></returns>
    public string ReadString(string code, string file = "", int length = 32, bool zeroTerminated = true)
    {
        var memoryNormal = new byte[length];
        var theCode = Get64BitCode(code, file);
        if (ReadProcessMemory(PHandle, theCode, memoryNormal, (UIntPtr)length, IntPtr.Zero))
            return zeroTerminated ? Encoding.UTF8.GetString(memoryNormal).Split('\0')[0] : Encoding.UTF8.GetString(memoryNormal);

        return "";
    }

    /// <summary>
    /// Read a double value
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="file">path and name of ini file. (OPTIONAL)</param>
    /// <param name="round">Round the value to 2 decimal places</param>
    /// <returns></returns>
    public double ReadDouble(string code, string file = "", bool round = true)
    {
        var memory = new byte[8];

        var theCode = Get64BitCode(code, file);
        try
        {
            if (ReadProcessMemory(PHandle, theCode, memory, 8, IntPtr.Zero))
            {
                var address = BitConverter.ToDouble(memory, 0);
                var returnValue = address;
                if (round)
                    returnValue = Math.Round(address, 2);
                return returnValue;
            }

            return 0;
        }
        catch
        {
            return 0;
        }
    }

    public int ReadUIntPtr(UIntPtr code)
    {
        var memory = new byte[4];
        return ReadProcessMemory(PHandle, code, memory, 4, IntPtr.Zero) ? BitConverter.ToInt32(memory, 0) : 0;
    }

    /// <summary>
    /// Read an integer from an address.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="file">path and name of ini file. (OPTIONAL)</param>
    /// <returns></returns>
    public int ReadInt(string code, string file = "")
    {
        var memory = new byte[4];
        var theCode = Get64BitCode(code, file);
        try
        {
            return ReadProcessMemory(PHandle, theCode, memory, 4, IntPtr.Zero) ? BitConverter.ToInt32(memory, 0) : 0;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Read a long value from an address.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="file">path and name of ini file. (OPTIONAL)</param>
    /// <returns></returns>
    public long ReadLong(string code, string file = "")
    {
        var memory = new byte[16];

        var theCode = Get64BitCode(code, file);
        try
        {
            return ReadProcessMemory(PHandle, theCode, memory, 16, IntPtr.Zero) ? BitConverter.ToInt64(memory, 0) : 0;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Read a UInt value from address.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="file">path and name of ini file. (OPTIONAL)</param>
    /// <returns></returns>
    public ulong ReadUInt(string code, string file = "")
    {
        var memory = new byte[8];
        var theCode = Get64BitCode(code, file);
        try
        {
            return ReadProcessMemory(PHandle, theCode, memory, 8, IntPtr.Zero) ? BitConverter.ToUInt64(memory, 0) : 0;
        }
        catch
        {
            return 0;
        }

    }

    /// <summary>
    /// Reads a 2 byte value from an address and moves the address.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="moveQty">Quantity to move.</param>
    /// <param name="file">path and name of ini file (OPTIONAL)</param>
    /// <returns></returns>
    public int Read2ByteMove(string code, int moveQty, string file = "")
    {
        var memory = new byte[4];
        var theCode = Get64BitCode(code, file);

        var newCode = UIntPtr.Add(theCode, moveQty);

        return ReadProcessMemory(PHandle, newCode, memory, 2, IntPtr.Zero) ? BitConverter.ToInt32(memory, 0) : 0;
    }

    /// <summary>
    /// Reads an integer value from address and moves the address.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="moveQty">Quantity to move.</param>
    /// <param name="file">path and name of ini file (OPTIONAL)</param>
    /// <returns></returns>
    public int ReadIntMove(string code, int moveQty, string file = "")
    {
        var memory = new byte[4];
        var theCode = Get64BitCode(code, file);

        var newCode = UIntPtr.Add(theCode, moveQty);

        return ReadProcessMemory(PHandle, newCode, memory, 4, IntPtr.Zero) ? BitConverter.ToInt32(memory, 0) : 0;
    }

    /// <summary>
    /// Get UInt and move to another address by moveQty. Use in a for loop.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="moveQty">Quantity to move.</param>
    /// <param name="file">path and name of ini file (OPTIONAL)</param>
    /// <returns></returns>
    public ulong ReadUIntMove(string code, int moveQty, string file = "")
    {
        var memory = new byte[8];
        var theCode = Get64BitCode(code, file, 8);

        var newCode = UIntPtr.Add(theCode, moveQty);

        return ReadProcessMemory(PHandle, newCode, memory, 8, IntPtr.Zero) ? BitConverter.ToUInt64(memory, 0) : 0;
    }

    /// <summary>
    /// Read a 2 byte value from an address. Returns an integer.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="file">path and file name to ini file. (OPTIONAL)</param>
    /// <returns></returns>
    public int Read2Byte(string code, string file = "")
    {
        var memoryTiny = new byte[4];

        var theCode = Get64BitCode(code, file);

        try
        {
            return ReadProcessMemory(PHandle, theCode, memoryTiny, 2, IntPtr.Zero) ? BitConverter.ToInt32(memoryTiny, 0) : 0;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Read 1 byte from address.
    /// </summary>
    /// <param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    /// <param name="file">path and file name of ini file. (OPTIONAL)</param>
    /// <returns></returns>
    public int ReadByte(string code, string file = "")
    {
        var memoryTiny = new byte[4];

        var theCode = Get64BitCode(code, file);
        try
        {
            return ReadProcessMemory(PHandle, theCode, memoryTiny, 1, IntPtr.Zero) ? BitConverter.ToInt32(memoryTiny, 0) : 0;
        }
        catch
        {
            return 0;
        }
    }

    public int ReadPByte(UIntPtr address, string code, string file = "")
    {
        var memory = new byte[4];
        return ReadProcessMemory(PHandle, address + (UIntPtr)LoadIntCode(code, file), memory, 1, IntPtr.Zero) ? BitConverter.ToInt32(memory, 0) : 0;
    }

    public float ReadPFloat(UIntPtr address, string code, string file = "")
    {
        var memory = new byte[4];
        if (ReadProcessMemory(PHandle, address + (UIntPtr)LoadIntCode(code, file), memory, 4, IntPtr.Zero))
        {
            var spawn = BitConverter.ToSingle(memory, 0);
            return (float)Math.Round(spawn, 2);
        }

        return 0;
    }

    public int ReadPInt(UIntPtr address, string code, string file = "")
    {
        var memory = new byte[4];
        return ReadProcessMemory(PHandle, address + (UIntPtr)LoadIntCode(code, file), memory, 4, IntPtr.Zero) ? BitConverter.ToInt32(memory, 0) : 0;
    }

    public string ReadPString(UIntPtr address, string code, string file = "")
    {
        var memoryNormal = new byte[32];
        return ReadProcessMemory(PHandle, address + (UIntPtr)LoadIntCode(code, file), memoryNormal, 32, IntPtr.Zero) ? CutString(Encoding.ASCII.GetString(memoryNormal)) : "";
    }
    #endregion

    #region writeMemory
    ///<summary>
    ///Write to memory address. See https://github.com/erfg12/memory.dll/wiki/writeMemory() for more information.
    ///</summary>
    ///<param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    ///<param name="type">byte, 2bytes, bytes, float, int, string, double or long.</param>
    ///<param name="write">value to write to address.</param>
    ///<param name="file">path and name of .ini file (OPTIONAL)</param>
    public bool WriteMemory(string code, string type, string write, string file = "")
    {
        var memory = new byte[4];
        var size = 4;

        var theCode = Get64BitCode(code, file);

        switch (type)
        {
            case "float":
                memory = BitConverter.GetBytes(Convert.ToSingle(write));
                size   = 4;
                break;
            case "int":
                memory = BitConverter.GetBytes(Convert.ToInt32(write));
                size   = 4;
                break;
            case "byte":
                memory    = new byte[1];
                memory[0] = Convert.ToByte(write, 16);
                size      = 1;
                break;
            case "2bytes":
                memory    = new byte[2];
                memory[0] = (byte)(Convert.ToInt32(write) % 256);
                memory[1] = (byte)(Convert.ToInt32(write) / 256);
                size      = 2;
                break;
            //check if it's a proper array
            case "bytes" when write.Contains(',') || write.Contains(' '):
            {
                var stringBytes = write.Split(write.Contains(',') ? ',' : ' ');

                //Debug.WriteLine("write:" + write + " stringBytes:" + stringBytes);
                var c = stringBytes.Length;
                memory = new byte[c];
                for (var i = 0; i < c; i++)
                {
                    memory[i] = Convert.ToByte(stringBytes[i], 16);
                }
                size = stringBytes.Length;
                break;
            }
            //wasn't array, only 1 byte
            case "bytes":
                memory    = new byte[1];
                memory[0] = Convert.ToByte(write, 16);
                size      = 1;
                break;
            case "double":
                memory = BitConverter.GetBytes(Convert.ToDouble(write));
                size   = 8;
                break;
            case "long":
                memory = BitConverter.GetBytes(Convert.ToInt64(write));
                size   = 8;
                break;
            case "string":
                memory = new byte[write.Length];
                memory = Encoding.UTF8.GetBytes(write);
                size   = memory.Length;
                break;
        }
#if DEBUG
        var stackTrace = new StackTrace(true);
        var sf = stackTrace.GetFrame(1);
        if (sf != null)
            Debug.Write("DEBUG: Writing bytes[" + sf.GetMethod()?.Name + "():L" + sf.GetFileLineNumber() + "] [TYPE:" +
                        type + " ADDR:" + theCode.ToUInt64().ToString("X") + "] " + string.Join(",", memory) +
                        Environment.NewLine);
#endif
        return WriteProcessMemory(PHandle, theCode, memory, (UIntPtr)size, IntPtr.Zero);
    }

    /// <summary>
    /// Write to address and move by moveQty. Good for byte arrays. See https://github.com/erfg12/memory.dll/wiki/Writing-a-Byte-Array for more information.
    /// </summary>
    ///<param name="code">address, module + pointer + offset, module + offset OR label in .ini file.</param>
    ///<param name="type">byte, bytes, float, int, string or long.</param>
    /// <param name="write">byte to write</param>
    /// <param name="moveQty">quantity to move</param>
    /// <param name="file">path and name of .ini file (OPTIONAL)</param>
    /// <returns></returns>
    public bool WriteMove(string code, string type, string write, int moveQty, string file = "")
    {
        var memory = new byte[4];
        var size = 4;

        var theCode = Get64BitCode(code, file);

        switch (type)
        {
            case "float":
                memory = new byte[write.Length];
                memory = BitConverter.GetBytes(Convert.ToSingle(write));
                size   = write.Length;
                break;
            case "int":
                memory = BitConverter.GetBytes(Convert.ToInt32(write));
                size   = 4;
                break;
            case "double":
                memory = BitConverter.GetBytes(Convert.ToDouble(write));
                size   = 8;
                break;
            case "long":
                memory = BitConverter.GetBytes(Convert.ToInt64(write));
                size   = 8;
                break;
            case "byte":
                memory    = new byte[1];
                memory[0] = Convert.ToByte(write, 16);
                size      = 1;
                break;
            case "string":
                memory = new byte[write.Length];
                memory = Encoding.UTF8.GetBytes(write);
                size   = write.Length;
                break;
        }

        var newCode = UIntPtr.Add(theCode, moveQty);

        Debug.Write("DEBUG: Writing bytes [TYPE:" + type + " ADDR:[O]" + theCode + " [N]" + newCode + " MQTY:" + moveQty + "] " + string.Join(",", memory) + Environment.NewLine);
        Thread.Sleep(1000);
        return WriteProcessMemory(PHandle, newCode, memory, (UIntPtr)size, IntPtr.Zero);
    }

    /// <summary>
    /// Write byte array to addresses.
    /// </summary>
    /// <param name="code">address to write to</param>
    /// <param name="write">byte array to write</param>
    /// <param name="file">path and name of ini file. (OPTIONAL)</param>
    public void WriteBytes(string code, byte[] write, string file = "")
    {
        var theCode = Get64BitCode(code, file);
        WriteProcessMemory(PHandle, theCode, write, (UIntPtr)write.Length, IntPtr.Zero);
    }

    /// <summary>
    /// Write byte array to address
    /// </summary>
    /// <param name="address">Address to write to</param>
    /// <param name="write">Byte array to write to</param>
    private void WriteBytes(UIntPtr address, params byte[] write)
    {
        WriteProcessMemory(PHandle, address, write, (UIntPtr)write.Length, out var bytesRead);
    }

    #endregion
    /// <summary>
    /// Convert code from string to real address. If path is not blank, will pull from ini file.
    /// </summary>
    /// <param name="name">label in ini file OR code</param>
    /// <param name="path">path to ini file (OPTIONAL)</param>
    /// <param name="size">size of address (default is 16)</param>
    /// <returns></returns>
    private UIntPtr Get64BitCode(string name, string path = "", int size = 16)
    {
        var theCode = "";
        theCode = path != "" ? LoadCode(name, path) : name;

        if (theCode == "")
            return UIntPtr.Zero;
        var newOffsets = theCode;
        if (theCode.Contains('+'))
            newOffsets = theCode[(theCode.IndexOf('+') + 1)..];

        var memoryAddress = new byte[size];

        if (!theCode.Contains('+') && !theCode.Contains(',')) return new UIntPtr(Convert.ToUInt64(theCode, 16));

        if (newOffsets.Contains(','))
        {
            var offsetsList = new List<long>();

            var newerOffsets = newOffsets.Split(',');
            foreach (var oldOffsets in newerOffsets)
            {
                var test = oldOffsets;
                if (oldOffsets.Contains("0x")) test = oldOffsets.Replace("0x", "");
                long preParse = 0;
                if (!oldOffsets.Contains('-'))
                    preParse = long.Parse(test, NumberStyles.AllowHexSpecifier);
                else
                {
                    test     =  test.Replace("-", "");
                    preParse =  long.Parse(test, NumberStyles.AllowHexSpecifier);
                    preParse *= -1;
                }
                offsetsList.Add(preParse);
            }
            var offsets = offsetsList.ToArray();

            if (theCode.Contains("base") || theCode.Contains("main"))
            {
                if (_mainModule != null)
                    ReadProcessMemory(PHandle, (UIntPtr)(_mainModule.BaseAddress + offsets[0]), memoryAddress,
                        (UIntPtr)size, IntPtr.Zero);
            }
            else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains('+'))
            {
                var moduleName = theCode.Split('+');
                var altModule = IntPtr.Zero;
                if (!moduleName[0].Contains(".dll") && !moduleName[0].Contains(".exe"))
                    altModule = (IntPtr)long.Parse(moduleName[0], NumberStyles.HexNumber);
                else
                {
                    try
                    {
                        altModule = Modules[moduleName[0]];
                    }
                    catch
                    {
                        Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                        Debug.WriteLine("Modules: " + string.Join(",", Modules));
                    }
                }
                ReadProcessMemory(PHandle, (UIntPtr)(altModule + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
            }
            else // no offsets
                ReadProcessMemory(PHandle, (UIntPtr)offsets[0], memoryAddress, (UIntPtr)size, IntPtr.Zero);

            var num1 = BitConverter.ToInt64(memoryAddress, 0);

            UIntPtr base1 = 0;
            try
            {
                for (var i = 1; i < offsets.Length; i++)
                {
                    base1 = new UIntPtr(Convert.ToUInt64(num1 + offsets[i]));
                    ReadProcessMemory(PHandle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                    num1 = BitConverter.ToInt64(memoryAddress, 0);
                }
            }
            catch
            {
                return UIntPtr.Zero;
            }
            return base1;
        }

        {
            var trueCode = Convert.ToInt64(newOffsets, 16);
            var altModule = IntPtr.Zero;
            if (theCode.Contains("base") || theCode.Contains("main"))
            {
                if (_mainModule != null) altModule = _mainModule.BaseAddress;
            }
            else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains('+'))
            {
                var moduleName = theCode.Split('+');
                if (!moduleName[0].Contains(".dll") && !moduleName[0].Contains(".exe"))
                {
                    var theAddr = moduleName[0];
                    if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                    altModule = (IntPtr)long.Parse(theAddr, NumberStyles.HexNumber);
                }
                else
                {
                    try
                    {
                        altModule = Modules[moduleName[0]];
                    }
                    catch
                    {
                        Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                        Debug.WriteLine("Modules: " + string.Join(",", Modules));
                    }
                }
            }
            else
                altModule = Modules[theCode.Split('+')[0]];
            return (UIntPtr)(altModule + trueCode);
        }
    }

    /// <summary>
    /// Close the process when finished.
    /// </summary>
    public void CloseProcess()
    {
        CloseHandle(PHandle);
        TheProc = null;
    }

    /// <summary>
    /// Inject a DLL file.
    /// </summary>
    /// <param name="strDllName">path and name of DLL file.</param>
    public void InjectDll(string strDllName)
    {
        if (TheProc != null && TheProc.Modules.Cast<ProcessModule>().Any(pm => pm.ModuleName.StartsWith("inject", StringComparison.InvariantCultureIgnoreCase)))
        {
            return;
        }

        if (TheProc is { Responding: false })
            return;

        var lenWrite = strDllName.Length + 1;
        var allocMem = VirtualAllocEx(PHandle, (UIntPtr)null, (uint)lenWrite, MemCommit | MemReserve, PageReadwrite);

        WriteProcessMemory(PHandle, allocMem, strDllName, (UIntPtr)lenWrite, out _);
        var injector = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

        var hThread = CreateRemoteThread(PHandle, (IntPtr)null, 0, injector, allocMem, 0, out _);

        var result = WaitForSingleObject(hThread, 10 * 1000);
        if (result == 0x00000080L || result == 0x00000102L)
        {
            CloseHandle(hThread);
            return;
        }
        VirtualFreeEx(PHandle, allocMem, 0, 0x8000);

        CloseHandle(hThread);
    }

#if WINXP
#else
    /// <summary>
    /// Creates a code cave to write custom opcodes in target process
    /// </summary>
    /// <param name="code">Address to create the trampoline</param>
    /// <param name="newBytes">The opcodes to write in the code cave</param>
    /// <param name="replaceCount">The number of bytes being replaced</param>
    /// <param name="size">size of the allocated region</param>
    /// <param name="file">ini file to look in</param>
    /// <remarks>Please ensure that you use the proper replaceCount
    /// if you replace halfway in an instruction you may cause bad things</remarks>
    /// <returns>UIntPtr to created code cave for use for later deallocation</returns>
    public UIntPtr CreateCodeCave(string code, byte[] newBytes, int replaceCount, int size = 0x10000, string file = "")
    {
        var theCode = Get64BitCode(code, file);

        return CreateCodeCave(theCode, newBytes, replaceCount, size);
    }

    private UIntPtr CreateCodeCave(UIntPtr address, byte[] newBytes, int replaceCount, int size = 0x10000)
    {
        if (replaceCount < 5)
            return UIntPtr.Zero; // returning UIntPtr.Zero instead of throwing an exception
        // to better match existing code

        // if x64 we need to try to allocate near the address so we don't run into the +-2GB limit of the 0xE9 jmp

        var caveAddress = UIntPtr.Zero;
        var prefered = address;

        for (var i = 0; i < 10 && caveAddress == UIntPtr.Zero; i++)
        {
            caveAddress = VirtualAllocEx(PHandle, FindFreeBlockForRegion(prefered.ToUInt64(), (uint)newBytes.Length),
                (uint)size, MemCommit | MemReserve, PageExecuteReadwrite);

            if (caveAddress == UIntPtr.Zero)
                prefered = UIntPtr.Add(prefered, 0x10000);
        }

        // Failed to allocate memory around the address we wanted let windows handle it and hope for the best?
        if (caveAddress == UIntPtr.Zero)
            caveAddress = VirtualAllocEx(PHandle, UIntPtr.Zero, (uint)size, MemCommit | MemReserve,
                PageExecuteReadwrite);

        var nopsNeeded = replaceCount > 5 ? replaceCount - 5 : 0;

        // (to - from - 5)
        var offset = (int)((long)caveAddress - (long)address - 5);

        var jmpBytes = new byte[5 + nopsNeeded];
        jmpBytes[0] = 0xE9;
        BitConverter.GetBytes(offset).CopyTo(jmpBytes, 1);

        for (var i = 5; i < jmpBytes.Length; i++)
        {
            jmpBytes[i] = 0x90;
        }
        WriteBytes(address, jmpBytes);

        var caveBytes = new byte[5 + newBytes.Length];
        offset = (int)((long)address + jmpBytes.Length - ((long)caveAddress + newBytes.Length) - 5);

        newBytes.CopyTo(caveBytes, 0);
        caveBytes[newBytes.Length] = 0xE9;
        BitConverter.GetBytes(offset).CopyTo(caveBytes, newBytes.Length + 1);

        WriteBytes(caveAddress, caveBytes);

        return caveAddress;
    }

    // array of memory allocations
    private readonly List<MemoryAlloc> _memoryAllocs = [];

    /// <summary>
    /// Memory allocated
    /// </summary>
    private struct MemoryAlloc(ulong size)
    {
        public ulong AllocateNearThisAddress;
        public ulong Address;
        public ulong Pointer;
        public ulong Size = size;
        public ulong SizeLeft => Size - (Pointer - Address);
        public uint LastProtection;
    }

    public ulong Alloc(uint size, ulong allocateNearThisAddress)
    {
        GetSystemInfo(out var systemInfo);

        try
        {
            // check for existing alloc near this address
            var i = _memoryAllocs.Select((alloc, index) => new { alloc, index })
                .Where(pair => pair.alloc.AllocateNearThisAddress == allocateNearThisAddress)
                .Select(pair => pair.index).First();

            // get the alloc from the array
            var found = _memoryAllocs[i];
            // is there enough room
            if (found.SizeLeft >= size)
            {
                var ret = found.Pointer;
                found.Pointer    += size;
                _memoryAllocs[i] =  found;
                return ret;
            }
        }
        catch
        {
            // ignored
        }

        var addr = FindFreeBlockForRegion(allocateNearThisAddress, size);

        if (TheProc != null)
        {
            VirtualQueryEx(TheProc.Handle, new UIntPtr(addr), out var mbi);

            _memoryAllocs.Add(new MemoryAlloc
            {
                Address                 = addr.ToUInt64(),
                AllocateNearThisAddress = allocateNearThisAddress,
                Pointer                 = addr.ToUInt64() + size,
                Size                    = systemInfo.PageSize,
                LastProtection          = mbi.Protect
            });

            // if (VirtualAllocEx(TheProc.Handle, new UIntPtr(addr), size, MemReserve | MemCommit, PageExecuteReadwrite) ==
            //     null)
            //     throw new Exception("Couldn't allocate memory at " + addr);
        }

        return addr;
    }

    /*
    private UIntPtr FindFreeBlockForRegion(UIntPtr baseAddress, uint size)
    {
        UIntPtr minAddress = UIntPtr.Subtract(baseAddress, 0x70000000);
        UIntPtr maxAddress = UIntPtr.Add(baseAddress, 0x70000000);

        UIntPtr ret = UIntPtr.Zero;
        UIntPtr tmpAddress;

        GetSystemInfo(out SYSTEM_INFO si);

        if (Is64Bit)
        {
            if ((long)minAddress > (long)si.maximumApplicationAddress ||
                (long)minAddress < (long)si.minimumApplicationAddress)
                minAddress = si.minimumApplicationAddress;

            if ((long)maxAddress < (long)si.minimumApplicationAddress ||
                (long)maxAddress > (long)si.maximumApplicationAddress)
                maxAddress = si.maximumApplicationAddress;
        }
        else
        {
            minAddress = si.minimumApplicationAddress;
            maxAddress = si.maximumApplicationAddress;
        }

        UIntPtr current = minAddress;

        while (VirtualQueryEx(pHandle, current, out MEMORY_BASIC_INFORMATION mbi).ToUInt64() != 0)
        {
            if ((long)mbi.BaseAddress > (long)maxAddress)
                return UIntPtr.Zero;  // No memory found, let windows handle

            if (mbi.State == MEM_FREE && mbi.RegionSize > size)
            {
                if ((long)mbi.BaseAddress % si.allocationGranularity > 0)
                {
                    // The whole size can not be used
                    tmpAddress = mbi.BaseAddress;
                    int offset = (int)(si.allocationGranularity -
                                       ((long)tmpAddress % si.allocationGranularity));

                    // Check if there is enough left
                    if ((mbi.RegionSize - offset) >= size)
                    {
                        // yup there is enough
                        tmpAddress = UIntPtr.Add(tmpAddress, offset);

                        if ((long)tmpAddress < (long)baseAddress)
                        {
                            tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - offset - size));

                            if ((long)tmpAddress > (long)baseAddress)
                                tmpAddress = baseAddress;

                            // decrease tmpAddress until its alligned properly
                            tmpAddress = UIntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
                        }

                        // if the difference is closer then use that
                        if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
                            ret = tmpAddress;
                    }
                }
                else
                {
                    tmpAddress = mbi.BaseAddress;

                    if ((long)tmpAddress < (long)baseAddress) // try to get it the cloest possible
                                                              // (so to the end of the region - size and
                                                              // aligned by system allocation granularity)
                    {
                        tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - size));

                        if ((long)tmpAddress > (long)baseAddress)
                            tmpAddress = baseAddress;

                        // decrease until aligned properly
                        tmpAddress =
                            UIntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
                    }

                    if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
                        ret = tmpAddress;
                }
            }

            if (mbi.RegionSize % si.allocationGranularity > 0)
                mbi.RegionSize += si.allocationGranularity - (mbi.RegionSize % si.allocationGranularity);

            UIntPtr previous = current;
            current = UIntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);

            if ((long)current > (long)maxAddress)
                return ret;

            if ((long)previous > (long)current)
                return ret; // Overflow
        }

        return ret;
    }*/

    private UIntPtr FindFreeBlockForRegion(ulong @base, uint size)
    {
        // initialize minimum and maximum address space relative to the base address
        // maximum JMP instruction for 64-bit is a relative JMP using the RIP register
        // jump to offset of 32-bit value, max being 7FFFFFFF
        // cheat engine slices off the Fs to give just 70000000 for unknown reasons
        var minAddress = @base - 0x70000000; // 0x10000 (32-bit)
        var maxAddress = @base + 0x70000000; // 0xfffffffff (32-bit)

        // retrieve system info
        GetSystemInfo(out var systemInfo);

        // keep min and max values within the system range for a given application
        if (minAddress < systemInfo.MinimumApplicationAddress)
            minAddress = systemInfo.MinimumApplicationAddress;
        if (maxAddress > systemInfo.MaximumApplicationAddress)
            maxAddress = systemInfo.MaximumApplicationAddress;

        // address for the current loop
        var addr = minAddress;
        // address from the last loop
        // current result to be passed back from function
        ulong result = 0;

        // query information about pages in virtual address space into mbi
        while (TheProc != null && VirtualQueryEx(TheProc.Handle, new UIntPtr(addr), out var mbi).ToUInt64() != 0)
        {
            // the base address is past the max address
            if (mbi.BaseAddress.ToUInt64() > maxAddress)
                return UIntPtr.Zero; // throw new Exception("Base address is greater than max address.");

            // check if the state is free to allocate and the region size allocated is enough to fit our requested size
            if (mbi.State == MemFree && mbi.RegionSize > size)
            {
                // set address to the current base address
                var nAddr = mbi.BaseAddress.ToUInt64();
                // get potential offset from granuarltiy alignment
                var offset = systemInfo.AllocationGranularity - nAddr % systemInfo.AllocationGranularity;

                // checks base address if it's on the edge of the allocation granularity (page)
                if (mbi.BaseAddress.ToUInt64() % systemInfo.AllocationGranularity > 0)
                {
                    if ((ulong)mbi.RegionSize - offset >= size)
                    {
                        // increase by potential offset
                        nAddr += offset;

                        // address is under base address
                        if (nAddr < @base)
                        {
                            // move into the region
                            nAddr += (ulong)mbi.RegionSize - offset - size;
                            // prevent overflow past base address
                            if (nAddr > @base)
                                nAddr = @base;
                            // align to page
                            nAddr -= nAddr % systemInfo.AllocationGranularity;
                        }

                        // new address is less than the one found last loop
                        if (Math.Abs((long)(nAddr - @base)) < Math.Abs((long)(result - @base)))
                            result = nAddr;
                    }
                }
                else
                {
                    // address is under base address
                    if (nAddr < @base)
                    {
                        // move into the region
                        nAddr += (ulong)mbi.RegionSize - size;
                        // prevent overflow past base address
                        if (nAddr > @base)
                            nAddr = @base;
                        // align to page
                        nAddr -= nAddr % systemInfo.AllocationGranularity;
                    }

                    // new address is less than the one found last loop
                    if (Math.Abs((long)(nAddr - @base)) < Math.Abs((long)(result - @base)))
                        result = nAddr;
                }
            }

            // region size isn't aligned with allocation granularity increase by difference 
            if (mbi.RegionSize % systemInfo.AllocationGranularity > 0)
                mbi.RegionSize += systemInfo.AllocationGranularity - mbi.RegionSize % systemInfo.AllocationGranularity;

            // set old address
            var oldAddr = addr;
            // increase address to the next region from our base address
            addr = mbi.BaseAddress + (ulong)mbi.RegionSize;

            // address goes over max size or overflow
            if (addr > maxAddress || oldAddr > addr)
                return (UIntPtr)result;
        }

        return (UIntPtr)result; // maybe not a good idea not sure
    }
#endif

    [Flags]
    public enum ThreadAccess
    {
        Terminate = 0x0001,
        SuspendResume = 0x0002,
        GetContext = 0x0008,
        SetContext = 0x0010,
        SetInformation = 0x0020,
        QueryInformation = 0x0040,
        SetThreadToken = 0x0080,
        Impersonate = 0x0100,
        DirectImpersonation = 0x0200
    }

    public static void SuspendProcess(int pid)
    {
        var process = Process.GetProcessById(pid);

        if (process.ProcessName == string.Empty)
            return;

        foreach (ProcessThread pT in process.Threads)
        {
            var pOpenThread = OpenThread(ThreadAccess.SuspendResume, false, (uint)pT.Id);
            if (pOpenThread == IntPtr.Zero)
                continue;

            SuspendThread(pOpenThread);
            CloseHandle(pOpenThread);
        }
    }

    public static void ResumeProcess(int pid)
    {
        var process = Process.GetProcessById(pid);
        if (process.ProcessName == string.Empty)
            return;

        foreach (ProcessThread pT in process.Threads)
        {
            var pOpenThread = OpenThread(ThreadAccess.SuspendResume, false, (uint)pT.Id);
            if (pOpenThread == IntPtr.Zero)
                continue;

            var suspendCount = 0;
            do
            {
                suspendCount = ResumeThread(pOpenThread);
            } while (suspendCount > 0);
            CloseHandle(pOpenThread);
        }
    }

#if WINXP
#else
    private static async Task PutTaskDelay(int delay)
    {
        await Task.Delay(delay);
    }
#endif

    private static void AppendAllBytes(string path, byte[] bytes)
    {
        using var stream = new FileStream(path, FileMode.Append);
        stream.Write(bytes, 0, bytes.Length);
    }

    public byte[] FileToBytes(string path, bool dontDelete = false)
    {
        var newArray = File.ReadAllBytes(path);
        if (!dontDelete)
            File.Delete(path);
        return newArray;
    }

    private string MSize()
    {
        return Is64BitCheck() ? "x16" : "x8";
    }

    /// <summary>
    /// Convert a byte array to hex values in a string.
    /// </summary>
    /// <param name="ba">your byte array to convert</param>
    /// <returns></returns>
    public static string ByteArrayToHexString(byte[] ba)
    {
        var hex = new StringBuilder(ba.Length * 2);
        var i = 1;
        foreach (var b in ba)
        {
            if (i == 16)
            {
                hex.Append($"{b:x2}{Environment.NewLine}");
                i = 0;
            }
            else
                hex.Append($"{b:x2} ");
            i++;
        }
        return hex.ToString().ToUpper();
    }

    public static string ByteArrayToString(byte[] ba)
    {
        var hex = new StringBuilder(ba.Length * 2);
        foreach (var b in ba)
        {
            hex.Append($"{b:x2} ");
        }
        return hex.ToString();
    }

#if WINXP
#else

    private struct SystemInfo(
        ushort processorArchitecture,
        ushort reserved,
        uint pageSize,
        UIntPtr minimumApplicationAddress,
        UIntPtr maximumApplicationAddress,
        IntPtr activeProcessorMask,
        uint numberOfProcessors,
        uint processorType,
        uint allocationGranularity,
        ushort processorLevel,
        ushort processorRevision)
    {
        public ushort ProcessorArchitecture = processorArchitecture;
        private ushort _reserved = reserved;
        public uint PageSize = pageSize;
        public UIntPtr MinimumApplicationAddress = minimumApplicationAddress;
        public UIntPtr MaximumApplicationAddress = maximumApplicationAddress;
        public IntPtr ActiveProcessorMask = activeProcessorMask;
        public uint NumberOfProcessors = numberOfProcessors;
        public uint ProcessorType = processorType;
        public uint AllocationGranularity = allocationGranularity;
        public ushort ProcessorLevel = processorLevel;
        public ushort ProcessorRevision = processorRevision;
    }

    private struct MemoryBasicInformation32(
        UIntPtr baseAddress,
        UIntPtr allocationBase,
        uint allocationProtect,
        uint regionSize,
        uint state,
        uint protect,
        uint type)
    {
        public UIntPtr BaseAddress = baseAddress;
        public UIntPtr AllocationBase = allocationBase;
        public uint AllocationProtect = allocationProtect;
        public uint RegionSize = regionSize;
        public uint State = state;
        public uint Protect = protect;
        public uint Type = type;
    }

    public struct MemoryBasicInformation64(
        UIntPtr baseAddress,
        UIntPtr allocationBase,
        uint allocationProtect,
        uint alignment1,
        ulong regionSize,
        uint state,
        uint protect,
        uint type,
        uint alignment2)
    {
        public UIntPtr BaseAddress = baseAddress;
        public UIntPtr AllocationBase = allocationBase;
        public uint AllocationProtect = allocationProtect;
        public uint Alignment1 = alignment1;
        public ulong RegionSize = regionSize;
        public uint State = state;
        public uint Protect = protect;
        public uint Type = type;
        public uint Alignment2 = alignment2;
    }

    private struct MemoryBasicInformation(
        UIntPtr baseAddress,
        UIntPtr allocationBase,
        uint allocationProtect,
        long regionSize,
        uint state,
        uint protect,
        uint type)
    {
        public UIntPtr BaseAddress = baseAddress;
        public UIntPtr AllocationBase = allocationBase;
        public uint AllocationProtect = allocationProtect;
        public long RegionSize = regionSize;
        public uint State = state;
        public uint Protect = protect;
        public uint Type = type;
    }

    public static ulong GetMinAddress()
    {
        GetSystemInfo(out var si);
        return si.MinimumApplicationAddress;
    }

    /// <summary>
    /// Dump memory page by page to a dump.dmp file. Can be used with Cheat Engine.
    /// </summary>
    public bool DumpMemory(string file = "dump.dmp")
    {
        Debug.Write("[DEBUG] memory dump starting... (" + DateTime.Now.ToString("h:mm:ss tt") + ")" + Environment.NewLine);
        GetSystemInfo(out var sysInfo);

        var procMinAddress = sysInfo.MinimumApplicationAddress;
        var procMaxAddress = sysInfo.MaximumApplicationAddress;

        // saving the values as long ints, so I won't have to do a lot of casts later
        var procMinAddressL = (long)procMinAddress; //(Int64)procs.MainModule.BaseAddress;
        if (TheProc != null)
        {
            var procMaxAddressL = TheProc.VirtualMemorySize64 + procMinAddressL;

            //int arrLength = 0;
            if (File.Exists(file))
                File.Delete(file);

            while (procMinAddressL < procMaxAddressL)
            {
                VirtualQueryEx(PHandle, procMinAddress, out var memInfo);
                var buffer = new byte[memInfo.RegionSize];
                var test = (UIntPtr)memInfo.RegionSize;
                var test2 = (UIntPtr)(long)memInfo.BaseAddress;

                ReadProcessMemory(PHandle, test2, buffer, test, IntPtr.Zero);

                AppendAllBytes(file, buffer); //due to memory limits, we have to dump it then store it in an array.
                //arrLength += buffer.Length;

                procMinAddressL += memInfo.RegionSize;
                procMinAddress  =  new UIntPtr((ulong)procMinAddressL);
            }
        }

        Debug.Write("[DEBUG] memory dump completed. Saving dump file to " + file + ". (" + DateTime.Now.ToString("h:mm:ss tt") + ")" + Environment.NewLine);
        return true;
    }

    /// <summary>
    /// Array of byte scan.
    /// </summary>
    /// <param name="search">array of bytes to search for, OR your ini code label.</param>
    /// <param name="writable">Include writable addresses in scan</param>
    /// <param name="executable">Include executable addresses in scan</param>
    /// <param name="file">ini file (OPTIONAL)</param>
    /// <returns>IEnumerable of all addresses found.</returns>
    public IEnumerable<long> AoBScan(string search, bool writable = false, bool executable = true, string file = "")
    {
        return AoBScan(0, long.MaxValue, search, writable, executable, file);
    }

    /// <summary>
    /// Array of Byte scan.
    /// </summary>
    /// <param name="start">Your starting address.</param>
    /// <param name="end">ending address</param>
    /// <param name="search">array of bytes to search for, OR your ini code label.</param>
    /// <param name="file">ini file (OPTIONAL)</param>
    /// <param name="writable">Include writable addresses in scan</param>
    /// <param name="executable">Include executable addresses in scan</param>
    /// <returns>IEnumerable of all addresses found.</returns>
    public IEnumerable<long> AoBScan(long start, long end, string search, bool writable = false, bool executable = true, string file = "")
    {
        var memRegionList = new List<MemoryRegionResult>();

        var memCode = LoadCode(search, file);

        var stringByteArray = memCode.Split(' ');
        var mask = new byte[stringByteArray.Length];

        for (var i = 0; i < stringByteArray.Length; i++)
        {
            var ba = stringByteArray[i];

            if (ba == "??" || ba.Length == 1 && ba == "?")
            {
                mask[i]            = 0x00;
                stringByteArray[i] = "0x00";
            }
            else if (char.IsLetterOrDigit(ba[0]) && ba[1] == '?')
            {
                mask[i]            = 0xF0;
                stringByteArray[i] = ba[0] + "0";
            }
            else if (char.IsLetterOrDigit(ba[1]) && ba[0] == '?')
            {
                mask[i]            = 0x0F;
                stringByteArray[i] = "0" + ba[1];
            }
            else
                mask[i] = 0xFF;
        }

        GetSystemInfo(out var sysInfo);

        var procMinAddress = sysInfo.MinimumApplicationAddress;
        var procMaxAddress = sysInfo.MaximumApplicationAddress;

        if (start < (long)procMinAddress.ToUInt64())
            start = (long)procMinAddress.ToUInt64();

        if (end > (long)procMaxAddress.ToUInt64())
            end = (long)procMaxAddress.ToUInt64();

        Debug.WriteLine("[DEBUG] memory scan starting... (min:0x" + procMinAddress.ToUInt64().ToString(MSize()) + " max:0x" + procMaxAddress.ToUInt64().ToString(MSize()) + " time:" + DateTime.Now.ToString("h:mm:ss tt") + ")");
        var currentBaseAddress = new UIntPtr((ulong)start);

        //Debug.WriteLine("[DEBUG] start:0x" + start.ToString("X8") + " curBase:0x" + currentBaseAddress.ToUInt64().ToString("X8") + " end:0x" + end.ToString("X8") + " size:0x" + memInfo.RegionSize.ToString("X8") + " vAloc:" + VirtualQueryEx(pHandle, currentBaseAddress, out memInfo).ToUInt64().ToString());

        while (VirtualQueryEx(PHandle, currentBaseAddress, out var memInfo).ToUInt64() != 0 &&
               currentBaseAddress.ToUInt64() < (ulong)end &&
               currentBaseAddress.ToUInt64() + (ulong)memInfo.RegionSize >
               currentBaseAddress.ToUInt64())
        {
            var isValid = memInfo.State == MemCommit;
            isValid &= memInfo.BaseAddress.ToUInt64() < procMaxAddress.ToUInt64();
            isValid &= (memInfo.Protect & PageGuard) == 0;
            isValid &= (memInfo.Protect & PageNoaccess) == 0;
            isValid &= memInfo.Type is MemPrivate or MemImage;

            if (isValid)
            {
                var isWritable = (memInfo.Protect & PageReadwrite) > 0 ||
                                 (memInfo.Protect & PageWritecopy) > 0 ||
                                 (memInfo.Protect & PageExecuteReadwrite) > 0 ||
                                 (memInfo.Protect & PageExecuteWritecopy) > 0;

                var isExecutable = (memInfo.Protect & PageExecute) > 0 ||
                                   (memInfo.Protect & PageExecuteRead) > 0 ||
                                   (memInfo.Protect & PageExecuteReadwrite) > 0 ||
                                   (memInfo.Protect & PageExecuteWritecopy) > 0;

                isWritable   &= writable;
                isExecutable &= executable;

                isValid &= isWritable || isExecutable;
            }

            if (!isValid)
            {
                currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + (ulong)memInfo.RegionSize);
                continue;
            }

            var memRegion = new MemoryRegionResult
            {
                CurrentBaseAddress = currentBaseAddress,
                RegionSize         = memInfo.RegionSize,
                RegionBase         = memInfo.BaseAddress
            };

            currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + (ulong)memInfo.RegionSize);

            //Console.WriteLine("SCAN start:" + memRegion.RegionBase.ToString() + " end:" + currentBaseAddress.ToString());

            if (memRegionList.Count > 0)
            {
                var previousRegion = memRegionList[^1];

                if ((long)previousRegion.RegionBase + previousRegion.RegionSize == (long)memInfo.BaseAddress)
                {
                    memRegionList[^1] = previousRegion with { RegionSize = previousRegion.RegionSize + memInfo.RegionSize };

                    continue;
                }
            }

            memRegionList.Add(memRegion);
        }

        var bagResult = new ConcurrentBag<long>();

        Parallel.ForEach(memRegionList,
            (item, parallelLoopState, index) =>
            {
                var compareResults = CompareScan(item, stringByteArray, mask);

                foreach (var result in compareResults)
                    bagResult.Add(result);
            });

        Debug.WriteLine("[DEBUG] memory scan completed. (time:" + DateTime.Now.ToString("h:mm:ss tt") + ")");

        return bagResult.ToList().OrderBy(c => c);
    }

    /// <summary>
    /// Array of bytes scan
    /// </summary>
    /// <param name="code">Starting address or ini label</param>
    /// <param name="end">ending address</param>
    /// <param name="search">array of bytes to search for or your ini code label</param>
    /// <param name="file">ini file</param>
    /// <returns>First address found</returns>
    public long AoBScan(string code, long end, string search, string file = "")
    {
        var start = (long)Get64BitCode(code, file).ToUInt64();

        return AoBScan(start, end, search, true, true, file).FirstOrDefault();
    }

    private long[] CompareScan(MemoryRegionResult item, string[] aobToFind, byte[] mask)
    {
        if (mask.Length != aobToFind.Length)
            throw new ArgumentException($"{nameof(aobToFind)}.Length != {nameof(mask)}.Length");

        var buffer = new byte[item.RegionSize];
        ReadProcessMemory(PHandle, item.CurrentBaseAddress, buffer, (UIntPtr)item.RegionSize, out var bytesRead);


        var aobPattern = new byte[aobToFind.Length];

        for (var i = 0; i < aobToFind.Length; i++)
            aobPattern[i] = (byte)(Convert.ToByte(aobToFind[i], 16) & mask[i]);

        var result = 0 - aobToFind.Length;
        var ret = new List<long>();
        do
        {
            result = FindPattern(buffer, aobPattern, mask, result + aobToFind.Length);

            if (result >= 0)
                ret.Add((long)item.CurrentBaseAddress + result);

        } while (result != -1);

        return ret.ToArray();
    }

    private static int FindPattern(byte[] body, byte[] pattern, byte[] masks, int start = 0)
    {
        var foundIndex = -1;

        if (body.Length <= 0 || pattern.Length <= 0 || start > body.Length - pattern.Length ||
            pattern.Length > body.Length) return foundIndex;

        for (var index = start; index <= body.Length - pattern.Length; index++)
        {
            if ((body[index] & masks[0]) == (pattern[0] & masks[0]))
            {
                var match = true;
                for (var index2 = 1; index2 <= pattern.Length - 1; index2++)
                {
                    if ((body[index + index2] & masks[index2]) == (pattern[index2] & masks[index2])) continue;
                    match = false;
                    break;

                }

                if (!match) continue;

                foundIndex = index;
                break;
            }
        }

        return foundIndex;
    }

#endif
}