Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.ComponentModel;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class Ferrum2CtrlBreakResult {
    public bool ProcessKnown { get; internal set; }
    public bool SeparateConsole { get; internal set; }
    public bool HadConsole { get; internal set; }
    public bool FreeConsoleBeforeAttachResult { get; internal set; }
    public int FreeConsoleBeforeAttachWin32Error { get; internal set; }
    public bool AttachAttempted { get; internal set; }
    public bool AttachConsoleResult { get; internal set; }
    public int AttachConsoleWin32Error { get; internal set; }
    public bool SetConsoleCtrlHandlerResult { get; internal set; }
    public int SetConsoleCtrlHandlerWin32Error { get; internal set; }
    public bool GenerateConsoleCtrlEventResult { get; internal set; }
    public int GenerateConsoleCtrlEventWin32Error { get; internal set; }
    public bool ResetConsoleCtrlHandlerResult { get; internal set; }
    public int ResetConsoleCtrlHandlerWin32Error { get; internal set; }
    public bool FreeConsoleAfterResult { get; internal set; }
    public int FreeConsoleAfterWin32Error { get; internal set; }
    public long SendStartedTimestamp { get; internal set; }
    public long SendReturnedTimestamp { get; internal set; }
    public long InternalWaitStartedTimestamp { get; internal set; }
    public long InternalWaitReturnedTimestamp { get; internal set; }
    public double SendDurationMilliseconds { get; internal set; }
    public double InternalWaitMilliseconds { get; internal set; }
    public double TotalDurationMilliseconds { get; internal set; }
    public bool Succeeded { get; internal set; }
}

public static class Ferrum2WfpIdentity {
    private const uint ERROR_SUCCESS = 0;
    private const int MAX_APP_ID_BYTES = 131072;

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_BYTE_BLOB {
        public uint size;
        public IntPtr data;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr memory);

    public static byte[] GetAppId(string executablePath) {
        if (String.IsNullOrWhiteSpace(executablePath) || !Path.IsPathRooted(executablePath))
            throw new ArgumentException("an absolute executable path is required", "executablePath");
        IntPtr allocation = IntPtr.Zero;
        var status = FwpmGetAppIdFromFileName0(executablePath, out allocation);
        try {
            if (status != ERROR_SUCCESS)
                throw new Win32Exception(unchecked((int)status), "FwpmGetAppIdFromFileName0");
            if (allocation == IntPtr.Zero)
                throw new InvalidOperationException("FwpmGetAppIdFromFileName0 returned no allocation");
            var blob = (FWP_BYTE_BLOB)Marshal.PtrToStructure(allocation, typeof(FWP_BYTE_BLOB));
            if (blob.size == 0 || blob.size > MAX_APP_ID_BYTES || blob.data == IntPtr.Zero)
                throw new InvalidOperationException("FwpmGetAppIdFromFileName0 returned an invalid blob");
            var bytes = new byte[checked((int)blob.size)];
            Marshal.Copy(blob.data, bytes, 0, bytes.Length);
            return bytes;
        } finally {
            if (allocation != IntPtr.Zero) FwpmFreeMemory0(ref allocation);
        }
    }
}

public static class Ferrum2ProcessGroup {
    private static readonly object Sync = new object();
    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const uint FILE_APPEND_DATA = 0x00000004;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint OPEN_ALWAYS = 4;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    private static readonly Dictionary<uint, ProcessEntry> Processes = new Dictionary<uint, ProcessEntry>();
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool ConsoleCtrlHandler(uint controlType);
    private static readonly ConsoleCtrlHandler IgnoreConsoleControl = IgnoreControl;

    private static bool IgnoreControl(uint controlType) { return true; }
    private sealed class ProcessEntry {
        public IntPtr Handle;
        public bool SeparateConsole;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb; public string reserved; public string desktop; public string title;
        public int x; public int y; public int xSize; public int ySize; public int xChars; public int yChars;
        public int fill; public int flags; public short show; public short reserved2; public IntPtr reservedBytes;
        public IntPtr stdin; public IntPtr stdout; public IntPtr stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX {
        public STARTUPINFO startup;
        public IntPtr attributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES {
        public int length;
        public IntPtr securityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool inheritHandle;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr process; public IntPtr thread; public uint processId; public uint threadId; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref STARTUPINFO startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessExtended(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref STARTUPINFOEX startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        ref SECURITY_ATTRIBUTES securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount,
        uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute,
        IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GenerateConsoleCtrlEvent(uint control, uint group);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr handle, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr handle, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetConsoleCtrlHandler(ConsoleCtrlHandler handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint GetConsoleProcessList([Out] uint[] processes, uint count);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FreeConsole();

    private static bool HasConsole() {
        return GetConsoleProcessList(new uint[1], 1) != 0;
    }

    private static IntPtr OpenInheritable(string path, uint access, uint disposition) {
        var security = new SECURITY_ATTRIBUTES {
            length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
            securityDescriptor = IntPtr.Zero,
            inheritHandle = true
        };
        var handle = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ref security, disposition, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (handle == INVALID_HANDLE_VALUE)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW redirected stream");
        return handle;
    }

    public static int Start(string application, string arguments, string directory) {
        return Start(application, arguments, directory, null, null);
    }

    public static int Start(string application, string arguments, string directory, string stdoutPath, string stderrPath) {
        var separateConsole = !HasConsole();
        var startup = new STARTUPINFO(); startup.cb = Marshal.SizeOf(startup);
        if (separateConsole) startup.flags = STARTF_USESHOWWINDOW;
        var command = new StringBuilder("\"" + application + "\" " + arguments);
        var flags = separateConsole ? CREATE_NEW_CONSOLE : CREATE_NEW_PROCESS_GROUP;
        var redirect = !String.IsNullOrWhiteSpace(stdoutPath) || !String.IsNullOrWhiteSpace(stderrPath);
        if (redirect && (String.IsNullOrWhiteSpace(stdoutPath) || String.IsNullOrWhiteSpace(stderrPath)))
            throw new ArgumentException("stdout and stderr redirection paths must be supplied together");
        PROCESS_INFORMATION process;
        if (!redirect) {
            if (!CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, directory, ref startup, out process))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW");
        } else {
            IntPtr stdoutHandle = IntPtr.Zero;
            IntPtr stderrHandle = IntPtr.Zero;
            IntPtr stdinHandle = IntPtr.Zero;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr handleList = IntPtr.Zero;
            try {
                stdoutHandle = OpenInheritable(stdoutPath, FILE_APPEND_DATA, OPEN_ALWAYS);
                stderrHandle = OpenInheritable(stderrPath, FILE_APPEND_DATA, OPEN_ALWAYS);
                stdinHandle = OpenInheritable("NUL", GENERIC_READ, OPEN_EXISTING);
                var startupEx = new STARTUPINFOEX();
                startupEx.startup.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                startupEx.startup.flags = (separateConsole ? STARTF_USESHOWWINDOW : 0) | STARTF_USESTDHANDLES;
                startupEx.startup.stdin = stdinHandle;
                startupEx.startup.stdout = stdoutHandle;
                startupEx.startup.stderr = stderrHandle;
                IntPtr attributeBytes = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeBytes);
                if (attributeBytes == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList size");
                attributeList = Marshal.AllocHGlobal(attributeBytes);
                if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeBytes))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList");
                startupEx.attributeList = attributeList;
                handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handleList, 0 * IntPtr.Size, stdinHandle);
                Marshal.WriteIntPtr(handleList, 1 * IntPtr.Size, stdoutHandle);
                Marshal.WriteIntPtr(handleList, 2 * IntPtr.Size, stderrHandle);
                if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handleList, new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute handle list");
                if (!CreateProcessExtended(application, command, IntPtr.Zero, IntPtr.Zero, true,
                    flags | EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, directory, ref startupEx, out process))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW redirected");
            } finally {
                if (attributeList != IntPtr.Zero) {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
                if (stdinHandle != IntPtr.Zero && stdinHandle != INVALID_HANDLE_VALUE) CloseHandle(stdinHandle);
                if (stdoutHandle != IntPtr.Zero && stdoutHandle != INVALID_HANDLE_VALUE) CloseHandle(stdoutHandle);
                if (stderrHandle != IntPtr.Zero && stderrHandle != INVALID_HANDLE_VALUE) CloseHandle(stderrHandle);
            }
        }
        CloseHandle(process.thread);
        lock (Sync) Processes.Add(process.processId, new ProcessEntry { Handle = process.process, SeparateConsole = separateConsole });
        return checked((int)process.processId);
    }
    public static bool Wait(uint processId, uint milliseconds) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processId, out process)) return false;
        return WaitForSingleObject(process.Handle, milliseconds) == 0;
    }
    public static int ExitCode(uint processId) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processId, out process)) throw new InvalidOperationException();
        uint exitCode; if (!GetExitCodeProcess(process.Handle, out exitCode)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return unchecked((int)exitCode);
    }
    public static bool Terminate(uint processId) {
        ProcessEntry process; lock (Sync) if (!Processes.TryGetValue(processId, out process)) return false;
        return TerminateProcess(process.Handle, 1);
    }
    public static void Close(uint processId) {
        ProcessEntry process;
        lock (Sync) { if (!Processes.TryGetValue(processId, out process)) return; Processes.Remove(processId); }
        CloseHandle(process.Handle);
    }
    public static Ferrum2CtrlBreakResult BreakDetailed(uint processGroup) {
        var total = Stopwatch.StartNew();
        var result = new Ferrum2CtrlBreakResult();
        ProcessEntry process;
        lock (Sync) {
            if (!Processes.TryGetValue(processGroup, out process)) {
                total.Stop();
                result.TotalDurationMilliseconds = total.Elapsed.TotalMilliseconds;
                return result;
            }
        }
        result.ProcessKnown = true;
        result.SeparateConsole = process.SeparateConsole;
        result.HadConsole = HasConsole();
        var attached = false;
        try {
            if (process.SeparateConsole) {
                result.FreeConsoleBeforeAttachResult = FreeConsole();
                result.FreeConsoleBeforeAttachWin32Error = result.FreeConsoleBeforeAttachResult ? 0 : Marshal.GetLastWin32Error();
                result.AttachAttempted = true;
                result.AttachConsoleResult = AttachConsole(processGroup);
                result.AttachConsoleWin32Error = result.AttachConsoleResult ? 0 : Marshal.GetLastWin32Error();
                if (!result.AttachConsoleResult) return result;
                attached = true;
            }
            result.SetConsoleCtrlHandlerResult = SetConsoleCtrlHandler(IgnoreConsoleControl, true);
            result.SetConsoleCtrlHandlerWin32Error = result.SetConsoleCtrlHandlerResult ? 0 : Marshal.GetLastWin32Error();
            if (!result.SetConsoleCtrlHandlerResult) return result;
            try {
                result.SendStartedTimestamp = Stopwatch.GetTimestamp();
                result.GenerateConsoleCtrlEventResult = GenerateConsoleCtrlEvent(
                    1,
                    process.SeparateConsole ? 0 : processGroup
                );
                result.GenerateConsoleCtrlEventWin32Error = result.GenerateConsoleCtrlEventResult ? 0 : Marshal.GetLastWin32Error();
                result.SendReturnedTimestamp = Stopwatch.GetTimestamp();
                result.SendDurationMilliseconds = (result.SendReturnedTimestamp - result.SendStartedTimestamp) * 1000.0 / Stopwatch.Frequency;
                result.Succeeded = result.GenerateConsoleCtrlEventResult;
                return result;
            }
            finally {
                result.InternalWaitStartedTimestamp = Stopwatch.GetTimestamp();
                Thread.Sleep(250);
                result.InternalWaitReturnedTimestamp = Stopwatch.GetTimestamp();
                result.InternalWaitMilliseconds =
                    (result.InternalWaitReturnedTimestamp - result.InternalWaitStartedTimestamp) * 1000.0 / Stopwatch.Frequency;
                result.ResetConsoleCtrlHandlerResult = SetConsoleCtrlHandler(IgnoreConsoleControl, false);
                result.ResetConsoleCtrlHandlerWin32Error = result.ResetConsoleCtrlHandlerResult ? 0 : Marshal.GetLastWin32Error();
            }
        }
        finally {
            if (attached) {
                result.FreeConsoleAfterResult = FreeConsole();
                result.FreeConsoleAfterWin32Error = result.FreeConsoleAfterResult ? 0 : Marshal.GetLastWin32Error();
            }
            total.Stop();
            result.TotalDurationMilliseconds = total.Elapsed.TotalMilliseconds;
        }
    }
    public static bool Break(uint processGroup) { return BreakDetailed(processGroup).Succeeded; }
}

'@
