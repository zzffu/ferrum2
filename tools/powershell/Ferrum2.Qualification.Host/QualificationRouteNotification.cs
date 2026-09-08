using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

public sealed class Ferrum2QualificationRouteNotification : IDisposable
{
    private const ushort AddressFamilyInet = 2;
    private IntPtr notificationHandle;
    private readonly EventWaitHandle signal;
    private readonly RouteChangeCallback callback;
    private int disposed;

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob
    {
        public uint size;
        public IntPtr data;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint FwpmGetAppIdFromFileName0(
        [MarshalAs(UnmanagedType.LPWStr)] string fileName,
        out IntPtr appId);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern void FwpmFreeMemory0(ref IntPtr memory);

    public static byte[] ApplicationId(string executablePath)
    {
        if (String.IsNullOrWhiteSpace(executablePath))
        {
            throw new ArgumentException(
                "Executable path is required",
                nameof(executablePath));
        }
        string fullPath = Path.GetFullPath(executablePath);
        uint status = FwpmGetAppIdFromFileName0(fullPath, out IntPtr appId);
        if (status != 0 || appId == IntPtr.Zero)
        {
            throw new Win32Exception(
                unchecked((int)status),
                "FwpmGetAppIdFromFileName0 failed");
        }
        try
        {
            FwpByteBlob blob = Marshal.PtrToStructure<FwpByteBlob>(appId);
            if (blob.size == 0 || blob.size > 65536 || blob.data == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    "FwpmGetAppIdFromFileName0 returned an invalid application ID");
            }
            byte[] result = new byte[checked((int)blob.size)];
            Marshal.Copy(blob.data, result, 0, result.Length);
            return result;
        }
        finally
        {
            FwpmFreeMemory0(ref appId);
        }
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void RouteChangeCallback(
        IntPtr callerContext,
        IntPtr routeRow,
        int notificationType);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint NotifyRouteChange2(
        ushort family,
        RouteChangeCallback callback,
        IntPtr callerContext,
        [MarshalAs(UnmanagedType.U1)] bool initialNotification,
        out IntPtr notificationHandle);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint CancelMibChangeNotify2(IntPtr notificationHandle);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint ConvertInterfaceIndexToLuid(
        uint interfaceIndex,
        out ulong interfaceLuid);

    public static ulong InterfaceLuid(uint interfaceIndex)
    {
        if (interfaceIndex == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(interfaceIndex));
        }
        uint status = ConvertInterfaceIndexToLuid(interfaceIndex, out ulong luid);
        if (status != 0 || luid == 0)
        {
            throw new Win32Exception(
                unchecked((int)status),
                "ConvertInterfaceIndexToLuid failed");
        }
        return luid;
    }

    [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint ConvertInterfaceAliasToLuid(string interfaceAlias, out ulong interfaceLuid);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint ConvertInterfaceLuidToGuid(ref ulong interfaceLuid, out Guid interfaceGuid);

    public static ulong InterfaceLuid(string interfaceAlias)
    {
        if (String.IsNullOrWhiteSpace(interfaceAlias))
            throw new ArgumentException("Interface alias is required", nameof(interfaceAlias));
        uint status = ConvertInterfaceAliasToLuid(interfaceAlias, out ulong luid);
        if (status != 0 || luid == 0)
            throw new Win32Exception(unchecked((int)status), "ConvertInterfaceAliasToLuid failed");
        return luid;
    }

    public static Guid InterfaceGuid(ulong interfaceLuid)
    {
        if (interfaceLuid == 0)
            throw new ArgumentOutOfRangeException(nameof(interfaceLuid));
        uint status = ConvertInterfaceLuidToGuid(ref interfaceLuid, out Guid guid);
        if (status != 0 || guid == Guid.Empty)
            throw new Win32Exception(unchecked((int)status), "ConvertInterfaceLuidToGuid failed");
        return guid;
    }

    public Ferrum2QualificationRouteNotification()
    {
        signal = new EventWaitHandle(false, EventResetMode.ManualReset);
        callback = OnRouteChanged;
        uint status = NotifyRouteChange2(
            AddressFamilyInet,
            callback,
            IntPtr.Zero,
            false,
            out notificationHandle);
        if (status != 0 || notificationHandle == IntPtr.Zero)
        {
            signal.Dispose();
            throw new Win32Exception(
                unchecked((int)status),
                "NotifyRouteChange2 failed");
        }
    }

    public bool Wait(int timeoutMilliseconds)
    {
        if (timeoutMilliseconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds));
        }
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(Ferrum2QualificationRouteNotification));
        }
        bool observed = signal.WaitOne(timeoutMilliseconds);
        GC.KeepAlive(callback);
        return observed;
    }

    private void OnRouteChanged(
        IntPtr callerContext,
        IntPtr routeRow,
        int notificationType)
    {
        if (Volatile.Read(ref disposed) == 0)
        {
            signal.Set();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        IntPtr owned = notificationHandle;
        notificationHandle = IntPtr.Zero;
        uint status = owned == IntPtr.Zero ? 0 : CancelMibChangeNotify2(owned);
        GC.KeepAlive(callback);
        signal.Dispose();
        if (status != 0)
        {
            throw new Win32Exception(
                unchecked((int)status),
                "CancelMibChangeNotify2 failed");
        }
        GC.SuppressFinalize(this);
    }
}
