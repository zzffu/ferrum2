using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

public sealed class Ferrum2QualificationRouteNotification : IDisposable
{
    private const ushort AddressFamilyInet = 2;
    private IntPtr notificationHandle;
    private readonly EventWaitHandle signal;
    private readonly RouteChangeCallback callback;
    private int disposed;

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
