using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class Ferrum2PerfProcessGroup {
    private const uint CreateNewConsole = 0x00000010;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const int StartfUseShowWindow = 0x00000001;
    private const int StartfUseStdHandles = 0x00000100;
    private const uint FileAppendData = 0x00000004;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint CreateNew = 1;
    private const uint FileAttributeNormal = 0x00000080;
    private static readonly IntPtr ProcThreadAttributeHandleList = new IntPtr(0x00020002);
    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);
    private static readonly Dictionary<uint, IntPtr> Handles = new Dictionary<uint, IntPtr>();
    private static readonly object Sync = new object();
    private static readonly ManualResetEvent ConsoleControlReceived = new ManualResetEvent(false);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool ConsoleCtrlHandler(uint controlType);
    private static readonly ConsoleCtrlHandler IgnoreConsoleControl = IgnoreControl;

    private static bool IgnoreControl(uint controlType) {
        if (controlType == 1) ConsoleControlReceived.Set();
        return true;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo {
        public int cb; public string reserved; public string desktop; public string title;
        public int x; public int y; public int xSize; public int ySize; public int xChars;
        public int yChars; public int fill; public int flags; public short show;
        public short reserved2; public IntPtr reservedBytes; public IntPtr stdin;
        public IntPtr stdout; public IntPtr stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx {
        public StartupInfo startup;
        public IntPtr attributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes {
        public int length;
        public IntPtr securityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool inheritHandle;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation {
        public IntPtr process; public IntPtr thread; public uint processId; public uint threadId;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessExtended(string application, StringBuilder command,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags,
        IntPtr environment, string directory, ref StartupInfoEx startup,
        out ProcessInformation process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        ref SecurityAttributes securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList,
        int attributeCount, uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags,
        IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr handle, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr handle, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleCtrlHandler(ConsoleCtrlHandler handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GenerateConsoleCtrlEvent(uint control, uint group);

    private static IntPtr OpenInheritable(string path, uint access, uint disposition) {
        var security = new SecurityAttributes {
            length = Marshal.SizeOf(typeof(SecurityAttributes)),
            securityDescriptor = IntPtr.Zero,
            inheritHandle = true
        };
        var handle = CreateFileW(path, access,
            FileShareRead | FileShareWrite | FileShareDelete,
            ref security, disposition, FileAttributeNormal, IntPtr.Zero);
        if (handle == InvalidHandleValue)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW redirected stream");
        return handle;
    }

    public static int Start(string application, string arguments, string directory,
        string stdoutPath, string stderrPath) {
        if (String.IsNullOrWhiteSpace(stdoutPath) || String.IsNullOrWhiteSpace(stderrPath))
            throw new ArgumentException("stdout and stderr redirection paths are required");
        var command = new StringBuilder("\"" + application + "\" " + arguments);
        ProcessInformation process;
        IntPtr stdoutHandle = IntPtr.Zero;
        IntPtr stderrHandle = IntPtr.Zero;
        IntPtr stdinHandle = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        var attributeListInitialized = false;
        try {
            stdoutHandle = OpenInheritable(stdoutPath, FileAppendData, CreateNew);
            stderrHandle = OpenInheritable(stderrPath, FileAppendData, CreateNew);
            stdinHandle = OpenInheritable("NUL", GenericRead, OpenExisting);
            var startup = new StartupInfoEx();
            startup.startup.cb = Marshal.SizeOf(typeof(StartupInfoEx));
            startup.startup.flags = StartfUseShowWindow | StartfUseStdHandles;
            startup.startup.show = 0;
            startup.startup.stdin = stdinHandle;
            startup.startup.stdout = stdoutHandle;
            startup.startup.stderr = stderrHandle;
            IntPtr attributeBytes = IntPtr.Zero;
            var sizeProbe = InitializeProcThreadAttributeList(
                IntPtr.Zero, 1, 0, ref attributeBytes);
            var sizeProbeError = Marshal.GetLastWin32Error();
            if (sizeProbe || attributeBytes == IntPtr.Zero || sizeProbeError != 122)
                throw new Win32Exception(sizeProbeError,
                    "InitializeProcThreadAttributeList size");
            attributeList = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeBytes))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "InitializeProcThreadAttributeList");
            attributeListInitialized = true;
            startup.attributeList = attributeList;
            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleList, 0 * IntPtr.Size, stdinHandle);
            Marshal.WriteIntPtr(handleList, 1 * IntPtr.Size, stdoutHandle);
            Marshal.WriteIntPtr(handleList, 2 * IntPtr.Size, stderrHandle);
            if (!UpdateProcThreadAttribute(attributeList, 0,
                ProcThreadAttributeHandleList, handleList, new IntPtr(IntPtr.Size * 3),
                IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "UpdateProcThreadAttribute handle list");
            if (!CreateProcessExtended(application, command, IntPtr.Zero, IntPtr.Zero, true,
                CreateNewConsole | ExtendedStartupInfoPresent, IntPtr.Zero, directory,
                ref startup, out process))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "CreateProcessW redirected");
        } finally {
            if (attributeList != IntPtr.Zero) {
                if (attributeListInitialized) DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
            if (stdinHandle != IntPtr.Zero && stdinHandle != InvalidHandleValue)
                CloseHandle(stdinHandle);
            if (stdoutHandle != IntPtr.Zero && stdoutHandle != InvalidHandleValue)
                CloseHandle(stdoutHandle);
            if (stderrHandle != IntPtr.Zero && stderrHandle != InvalidHandleValue)
                CloseHandle(stderrHandle);
        }
        CloseHandle(process.thread);
        lock (Sync) Handles.Add(process.processId, process.process);
        return checked((int)process.processId);
    }
    public static bool Wait(uint processId, uint milliseconds) {
        IntPtr handle; lock (Sync) if (!Handles.TryGetValue(processId, out handle)) return false;
        return WaitForSingleObject(handle, milliseconds) == 0;
    }
    public static int ExitCode(uint processId) {
        IntPtr handle; lock (Sync) if (!Handles.TryGetValue(processId, out handle)) throw new InvalidOperationException();
        uint code; if (!GetExitCodeProcess(handle, out code)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return unchecked((int)code);
    }
    public static bool Break(uint processId) {
        IntPtr handle; lock (Sync) if (!Handles.TryGetValue(processId, out handle)) return false;
        FreeConsole();
        if (!AttachConsole(processId)) return false;
        try {
            if (!SetConsoleCtrlHandler(IgnoreConsoleControl, true)) return false;
            try {
                ConsoleControlReceived.Reset();
                var sent = GenerateConsoleCtrlEvent(1, 0);
                var senderObserved = sent && ConsoleControlReceived.WaitOne(5000);
                Thread.Sleep(250);
                return sent && senderObserved;
            } finally {
                SetConsoleCtrlHandler(IgnoreConsoleControl, false);
            }
        } finally {
            FreeConsole();
        }
    }
    public static bool Terminate(uint processId) {
        IntPtr handle; lock (Sync) if (!Handles.TryGetValue(processId, out handle)) return false;
        return TerminateProcess(handle, 1);
    }
    public static void Close(uint processId) {
        IntPtr handle;
        lock (Sync) { if (!Handles.TryGetValue(processId, out handle)) return; Handles.Remove(processId); }
        CloseHandle(handle);
    }
}
