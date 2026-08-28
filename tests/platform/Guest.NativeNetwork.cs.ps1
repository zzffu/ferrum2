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
internal static class Ferrum2NetworkBackgroundTaskCleanup {
    private const int TimeoutMilliseconds = 5000;

    internal static long CreateDeadline() {
        return Environment.TickCount64 + TimeoutMilliseconds;
    }

    internal static Exception Wait(Task task, long deadline, string name) {
        var remaining = deadline - Environment.TickCount64;
        var boundedMilliseconds = remaining <= 0
            ? 0
            : (int)Math.Min(remaining, (long)Int32.MaxValue);
        try {
            if (!task.Wait(boundedMilliseconds)) {
                return new TimeoutException(name + " did not stop within the bounded cleanup timeout");
            }
        } catch (AggregateException error) {
            return new InvalidOperationException(name + " faulted during bounded cleanup", error.Flatten());
        }
        return task.IsCompleted
            ? null
            : new TimeoutException(name + " did not report completion after bounded cleanup wait");
    }
}

public sealed class Ferrum2DnsResponder : IDisposable {
    private readonly UdpClient socket;
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly Task worker;
    private int requests;
    private int disposed;

    public Ferrum2DnsResponder(int port) : this("127.0.0.1", port) { }

    public Ferrum2DnsResponder(string address, int port) {
        socket = new UdpClient(new IPEndPoint(IPAddress.Parse(address), port));
        worker = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                var query = request.Buffer;
                if (query.Length < 17) continue;
                var questionEnd = 12;
                var validQuestion = false;
                while (questionEnd < query.Length) {
                    var labelLength = query[questionEnd++];
                    if (labelLength == 0) {
                        validQuestion = questionEnd + 4 <= query.Length;
                        questionEnd += 4;
                        break;
                    }
                    if (labelLength > 63 || questionEnd + labelLength > query.Length) break;
                    questionEnd += labelLength;
                }
                if (!validQuestion) continue;
                using (var response = new MemoryStream()) {
                    response.WriteByte(query[0]); response.WriteByte(query[1]);
                    response.WriteByte(0x81); response.WriteByte(0x80);
                    response.WriteByte(0); response.WriteByte(1);
                    response.WriteByte(0); response.WriteByte(1);
                    response.Write(new byte[4], 0, 4);
                    response.Write(query, 12, questionEnd - 12);
                    byte[] answer = { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 55 };
                    response.Write(answer, 0, answer.Length);
                    var bytes = response.ToArray();
                    await socket.SendAsync(bytes, bytes.Length, request.RemoteEndPoint).ConfigureAwait(false);
                }
                Interlocked.Increment(ref requests);
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        socket.Dispose();

        var deadline = Ferrum2NetworkBackgroundTaskCleanup.CreateDeadline();
        var workerFailure = Ferrum2NetworkBackgroundTaskCleanup.Wait(worker, deadline, "DNS responder worker");
        if (!worker.IsCompleted) {
            throw workerFailure ?? new TimeoutException("DNS responder worker did not report completion after bounded cleanup wait");
        }
        stopped.Dispose();
        if (workerFailure != null) throw workerFailure;
    }
}

[StructLayout(LayoutKind.Explicit, Size = 28)]
internal struct Ferrum2SockaddrInet {
    [FieldOffset(0)] internal ushort Family;
    [FieldOffset(2)] internal ushort Port;
    [FieldOffset(4)] internal uint Address;
}

[StructLayout(LayoutKind.Sequential)]
internal struct Ferrum2IpAddressPrefix {
    internal Ferrum2SockaddrInet Prefix;
    internal byte PrefixLength;
}

[StructLayout(LayoutKind.Sequential)]
internal struct Ferrum2IpForwardRow2 {
    internal ulong InterfaceLuid;
    internal uint InterfaceIndex;
    internal Ferrum2IpAddressPrefix DestinationPrefix;
    internal Ferrum2SockaddrInet NextHop;
    internal byte SitePrefixLength;
    internal uint ValidLifetime;
    internal uint PreferredLifetime;
    internal uint Metric;
    internal int Protocol;
    [MarshalAs(UnmanagedType.U1)] internal bool Loopback;
    [MarshalAs(UnmanagedType.U1)] internal bool AutoconfigureAddress;
    [MarshalAs(UnmanagedType.U1)] internal bool Publish;
    [MarshalAs(UnmanagedType.U1)] internal bool Immortal;
    internal uint Age;
    internal int Origin;
}

public sealed class Ferrum2UnderlayProbe {
    public ulong InterfaceLuid { get; internal set; }
    public uint InterfaceIndex { get; internal set; }
    public string DestinationPrefix { get; internal set; }
    public string SourceAddress { get; internal set; }
    public string NextHop { get; internal set; }
    public byte PrefixLength { get; internal set; }
    public uint RouteMetric { get; internal set; }
}

public sealed class Ferrum2CaptureRoute : IDisposable {
    private const uint ERROR_NOT_FOUND = 1168;
    private Ferrum2IpForwardRow2 intended;
    private bool disposed;

    internal Ferrum2CaptureRoute(Ferrum2IpForwardRow2 row) { intended = row; }

    public void Verify() {
        Ferrum2IpForwardRow2 current;
        var result = Ferrum2NetworkFeasibility.ReadRoute(intended, out current);
        if (result != 0) throw new Win32Exception(checked((int)result), "GetIpForwardEntry2");
        if (!Ferrum2NetworkFeasibility.MatchesOwned(intended, current))
            throw new InvalidOperationException("capture route readback mismatch");
    }

    public void Dispose() {
        if (disposed) return;
        Ferrum2IpForwardRow2 current;
        var result = Ferrum2NetworkFeasibility.ReadRoute(intended, out current);
        if (result == ERROR_NOT_FOUND) { disposed = true; return; }
        if (result != 0) throw new Win32Exception(checked((int)result), "GetIpForwardEntry2");
        if (!Ferrum2NetworkFeasibility.MatchesOwned(intended, current))
            throw new InvalidOperationException("capture route ownership changed");
        result = Ferrum2NetworkFeasibility.DeleteRoute(ref current);
        if (result != 0 && result != ERROR_NOT_FOUND)
            throw new Win32Exception(checked((int)result), "DeleteIpForwardEntry2");
        result = Ferrum2NetworkFeasibility.ReadRoute(intended, out current);
        if (result != ERROR_NOT_FOUND) throw new InvalidOperationException("capture route delete readback mismatch");
        disposed = true;
    }
}

public static class Ferrum2NetworkFeasibility {
    private const ushort AF_INET = 2;
    private const uint ERROR_NOT_FOUND = 1168;
    private const int IPPROTO_IP = 0;
    private const int IPPROTO_IPV6 = 41;
    private const int IP_UNICAST_IF = 31;
    private const int IPV6_UNICAST_IF = 31;

    [DllImport("iphlpapi.dll")]
    private static extern void InitializeIpForwardEntry(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint CreateIpForwardEntry2(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetIpForwardEntry2(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint DeleteIpForwardEntry2(ref Ferrum2IpForwardRow2 row);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestInterfaceEx(ref Ferrum2SockaddrInet destination, out uint interfaceIndex);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestRoute2(IntPtr interfaceLuid, uint interfaceIndex, IntPtr sourceAddress,
        ref Ferrum2SockaddrInet destination, uint addressSortOptions,
        out Ferrum2IpForwardRow2 bestRoute, out Ferrum2SockaddrInet bestSourceAddress);
    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int setsockopt(IntPtr socket, int level, int option, ref uint value, int valueLength);
    [DllImport("ws2_32.dll")]
    private static extern int WSAGetLastError();

    public static int RouteRowSize { get { return Marshal.SizeOf(typeof(Ferrum2IpForwardRow2)); } }

    private static Ferrum2SockaddrInet Address(string text) {
        var address = IPAddress.Parse(text);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("IPv4 is required", "text");
        return new Ferrum2SockaddrInet {
            Family = AF_INET,
            Address = BitConverter.ToUInt32(address.GetAddressBytes(), 0)
        };
    }

    private static string Address(Ferrum2SockaddrInet value) {
        if (value.Family != AF_INET) throw new InvalidOperationException("IPv4 readback is required");
        return new IPAddress(BitConverter.GetBytes(value.Address)).ToString();
    }

    private static Ferrum2IpForwardRow2 Key(Ferrum2IpForwardRow2 intended) {
        var key = new Ferrum2IpForwardRow2();
        InitializeIpForwardEntry(ref key);
        key.InterfaceIndex = intended.InterfaceIndex;
        key.DestinationPrefix = intended.DestinationPrefix;
        key.NextHop = intended.NextHop;
        return key;
    }

    internal static uint ReadRoute(Ferrum2IpForwardRow2 intended, out Ferrum2IpForwardRow2 current) {
        current = Key(intended);
        return GetIpForwardEntry2(ref current);
    }

    internal static uint DeleteRoute(ref Ferrum2IpForwardRow2 row) { return DeleteIpForwardEntry2(ref row); }

    internal static bool MatchesOwned(Ferrum2IpForwardRow2 expected, Ferrum2IpForwardRow2 actual) {
        return actual.InterfaceIndex == expected.InterfaceIndex &&
            actual.DestinationPrefix.Prefix.Family == AF_INET &&
            actual.DestinationPrefix.Prefix.Address == expected.DestinationPrefix.Prefix.Address &&
            actual.DestinationPrefix.PrefixLength == expected.DestinationPrefix.PrefixLength &&
            actual.NextHop.Family == AF_INET && actual.NextHop.Address == 0 &&
            actual.SitePrefixLength == expected.SitePrefixLength &&
            actual.ValidLifetime == expected.ValidLifetime &&
            actual.PreferredLifetime == expected.PreferredLifetime &&
            actual.Metric == expected.Metric && actual.Protocol == expected.Protocol &&
            actual.Loopback == expected.Loopback &&
            actual.AutoconfigureAddress == expected.AutoconfigureAddress &&
            actual.Publish == expected.Publish && actual.Immortal == expected.Immortal &&
            actual.Origin == expected.Origin;
    }

    public static Ferrum2CaptureRoute CreateCaptureRoute(uint interfaceIndex, string prefix, uint metric) {
        if (RouteRowSize != 104) throw new InvalidOperationException("MIB_IPFORWARD_ROW2 ABI size mismatch");
        var parts = prefix.Split('/');
        if (parts.Length != 2 || parts[1] != "1" || (parts[0] != "0.0.0.0" && parts[0] != "128.0.0.0"))
            throw new ArgumentException("an exact IPv4 /1 capture prefix is required", "prefix");
        var row = new Ferrum2IpForwardRow2();
        InitializeIpForwardEntry(ref row);
        row.InterfaceLuid = 0;
        row.InterfaceIndex = interfaceIndex;
        row.DestinationPrefix = new Ferrum2IpAddressPrefix { Prefix = Address(parts[0]), PrefixLength = 1 };
        row.NextHop = Address("0.0.0.0");
        row.SitePrefixLength = 0;
        row.ValidLifetime = UInt32.MaxValue;
        row.PreferredLifetime = UInt32.MaxValue;
        row.Metric = metric;
        row.Protocol = 3;
        row.Loopback = false;
        row.AutoconfigureAddress = false;
        row.Publish = false;
        row.Immortal = false;
        row.Age = 0;
        row.Origin = 0;
        Ferrum2IpForwardRow2 ignored;
        var result = ReadRoute(row, out ignored);
        if (result != ERROR_NOT_FOUND) {
            if (result == 0) throw new InvalidOperationException("capture route baseline not absent");
            throw new Win32Exception(checked((int)result), "GetIpForwardEntry2");
        }
        result = CreateIpForwardEntry2(ref row);
        if (result != 0) throw new Win32Exception(checked((int)result), "CreateIpForwardEntry2");
        var lease = new Ferrum2CaptureRoute(row);
        try { lease.Verify(); return lease; }
        catch { lease.Dispose(); throw; }
    }

    public static Ferrum2UnderlayProbe GetFixedRoute(string destinationText) {
        var destination = Address(destinationText);
        uint interfaceIndex;
        var result = GetBestInterfaceEx(ref destination, out interfaceIndex);
        if (result != 0) throw new Win32Exception(checked((int)result), "GetBestInterfaceEx");
        return GetConstrainedRoute(destinationText, interfaceIndex);
    }

    public static Ferrum2UnderlayProbe GetConstrainedRoute(string destinationText, uint interfaceIndex) {
        var destination = Address(destinationText);
        Ferrum2IpForwardRow2 route;
        Ferrum2SockaddrInet source;
        var result = GetBestRoute2(IntPtr.Zero, interfaceIndex, IntPtr.Zero, ref destination, 0, out route, out source);
        if (result != 0) throw new Win32Exception(checked((int)result), "GetBestRoute2");
        if (route.InterfaceIndex != interfaceIndex || source.Family != AF_INET || source.Address == 0)
            throw new InvalidOperationException("constrained best route identity mismatch");
        return new Ferrum2UnderlayProbe {
            InterfaceLuid = route.InterfaceLuid,
            InterfaceIndex = interfaceIndex,
            DestinationPrefix = Address(route.DestinationPrefix.Prefix),
            SourceAddress = Address(source),
            NextHop = Address(route.NextHop),
            PrefixLength = route.DestinationPrefix.PrefixLength,
            RouteMetric = route.Metric
        };
    }

    public static void Pin(Socket socket, uint interfaceIndex) {
        if (socket == null) throw new ArgumentNullException("socket");
        if (interfaceIndex == 0) throw new ArgumentOutOfRangeException("interfaceIndex");
        var value = interfaceIndex;
        var level = IPPROTO_IPV6;
        var option = IPV6_UNICAST_IF;
        var name = "IPV6_UNICAST_IF";
        if (socket.AddressFamily == AddressFamily.InterNetwork) {
            value = unchecked((uint)IPAddress.HostToNetworkOrder(unchecked((int)interfaceIndex)));
            level = IPPROTO_IP;
            option = IP_UNICAST_IF;
            name = "IP_UNICAST_IF";
        } else if (socket.AddressFamily != AddressFamily.InterNetworkV6) {
            throw new ArgumentException("an IPv4 or IPv6 socket is required", "socket");
        }
        if (setsockopt(socket.Handle, level, option, ref value, sizeof(uint)) != 0)
            throw new Win32Exception(WSAGetLastError(), name);
    }

    private static void SendAll(Socket socket, byte[] payload) {
        var offset = 0;
        while (offset < payload.Length) offset += socket.Send(payload, offset, payload.Length - offset, SocketFlags.None);
    }

    private static byte[] ReceiveExact(Socket socket, int length) {
        var received = new byte[length];
        var offset = 0;
        while (offset < length) {
            var count = socket.Receive(received, offset, length - offset, SocketFlags.None);
            if (count == 0) throw new EndOfStreamException("support listener closed before echo");
            offset += count;
        }
        return received;
    }

    private static void VerifySource(Socket socket, string expectedSource) {
        var local = socket.LocalEndPoint as IPEndPoint;
        if (local == null || local.Address.ToString() != expectedSource)
            throw new InvalidOperationException("pinned socket source mismatch");
    }

    public static void TcpEcho(string address, int port, uint interfaceIndex, string expectedSource, byte[] payload) {
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
            socket.SendTimeout = 5000; socket.ReceiveTimeout = 5000;
            Pin(socket, interfaceIndex);
            socket.Connect(IPAddress.Parse(address), port);
            VerifySource(socket, expectedSource);
            SendAll(socket, payload);
            var response = ReceiveExact(socket, payload.Length);
            if (!StructuralComparisons.StructuralEqualityComparer.Equals(payload, response))
                throw new InvalidDataException("support TCP echo mismatch");
        }
    }

    public static void UdpEcho(string address, int port, uint interfaceIndex, string expectedSource, byte[] payload) {
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) {
            socket.SendTimeout = 5000; socket.ReceiveTimeout = 5000;
            Pin(socket, interfaceIndex);
            socket.Connect(IPAddress.Parse(address), port);
            SendAll(socket, payload);
            VerifySource(socket, expectedSource);
            var response = ReceiveExact(socket, payload.Length);
            if (!StructuralComparisons.StructuralEqualityComparer.Equals(payload, response))
                throw new InvalidDataException("support UDP echo mismatch");
        }
    }
}
'@
