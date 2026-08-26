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
public sealed class Ferrum2TcpGateObservation {
    private long clientToServerBytes;
    private long serverToClientBytes;
    private int clientToServerEof;
    private int serverToClientEof;
    private int sessionComplete;
    private string clientToServerStage = "pending";
    private string serverToClientStage = "pending";
    private string clientToServerFault;
    private string serverToClientFault;

    public string ClientToServerBytes { get { return Interlocked.Read(ref clientToServerBytes) == 0 ? "zero" : "nonzero"; } }
    public string ServerToClientBytes { get { return Interlocked.Read(ref serverToClientBytes) == 0 ? "zero" : "nonzero"; } }
    public string ClientToServerStage { get { return Volatile.Read(ref clientToServerStage); } }
    public string ServerToClientStage { get { return Volatile.Read(ref serverToClientStage); } }
    public string ClientToServerEof { get { return Volatile.Read(ref clientToServerEof) == 0 ? "no" : "yes"; } }
    public string ServerToClientEof { get { return Volatile.Read(ref serverToClientEof) == 0 ? "no" : "yes"; } }
    public string ClientToServerFault { get { return Volatile.Read(ref clientToServerFault) ?? "none"; } }
    public string ServerToClientFault { get { return Volatile.Read(ref serverToClientFault) ?? "none"; } }
    public string SessionComplete { get { return Volatile.Read(ref sessionComplete) == 0 ? "no" : "yes"; } }

    internal void AddBytes(bool forward, int count) {
        if (forward) Interlocked.Add(ref clientToServerBytes, count);
        else Interlocked.Add(ref serverToClientBytes, count);
    }
    internal void MarkEof(bool forward) {
        if (forward) Volatile.Write(ref clientToServerEof, 1);
        else Volatile.Write(ref serverToClientEof, 1);
    }
    internal void SetStage(bool forward, string stage) {
        if (forward) Volatile.Write(ref clientToServerStage, stage);
        else Volatile.Write(ref serverToClientStage, stage);
    }
    internal void Fail(bool forward, string fault) {
        if (forward) Interlocked.CompareExchange(ref clientToServerFault, fault, null);
        else Interlocked.CompareExchange(ref serverToClientFault, fault, null);
    }
    internal void FailBoth(string fault) { Fail(true, fault); Fail(false, fault); }
    internal void Complete() { Volatile.Write(ref sessionComplete, 1); }
}

internal static class Ferrum2BackgroundTaskCleanup {
    internal const int TimeoutMilliseconds = 5000;

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

public sealed class Ferrum2TcpGate : IDisposable {
    private readonly TcpListener listener;
    private readonly int upstreamPort;
    private readonly ConcurrentDictionary<int, ManualResetEventSlim> releases = new ConcurrentDictionary<int, ManualResetEventSlim>();
    private readonly ConcurrentDictionary<int, Ferrum2TcpGateObservation> observations = new ConcurrentDictionary<int, Ferrum2TcpGateObservation>();
    private readonly ConcurrentBag<TcpClient> clients = new ConcurrentBag<TcpClient>();
    private readonly ConcurrentBag<Task> sessionTasks = new ConcurrentBag<Task>();
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly object clientSync = new object();
    private readonly Task acceptTask;
    private int accepted;
    private int disposed;

    public Ferrum2TcpGate(int listenPort, int upstreamPort) {
        this.upstreamPort = upstreamPort;
        listener = new TcpListener(IPAddress.Loopback, listenPort);
        listener.Start();
        acceptTask = Task.Run(AcceptLoop);
    }

    public int Accepted { get { return Volatile.Read(ref accepted); } }

    public bool WaitAccepted(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Accepted >= expected) return true;
            Thread.Sleep(10);
        }
        return Accepted >= expected;
    }

    public bool WaitCompleted(int index, int milliseconds) {
        Ferrum2TcpGateObservation observation;
        if (!observations.TryGetValue(index, out observation)) return false;
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (observation.SessionComplete == "yes") return true;
            Thread.Sleep(10);
        }
        return observation.SessionComplete == "yes";
    }

    public Ferrum2TcpGateObservation Observation(int index) {
        Ferrum2TcpGateObservation observation;
        return observations.TryGetValue(index, out observation) ? observation : null;
    }

    public void Release(int index) {
        ManualResetEventSlim release;
        if (!releases.TryGetValue(index, out release)) throw new InvalidOperationException("gate session missing");
        release.Set();
    }

    private async Task AcceptLoop() {
        try {
            while (!stopped.IsCancellationRequested) {
                var client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                if (!RegisterClient(client)) return;
                var index = Accepted + 1;
                var release = new ManualResetEventSlim(false);
                var observation = new Ferrum2TcpGateObservation();
                releases[index] = release;
                observations[index] = observation;
                Volatile.Write(ref accepted, index);
                var sessionTask = Task.Run(() => RunSession(client, release, observation));
                sessionTasks.Add(sessionTask);
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
    }

    private void RunSession(TcpClient client, ManualResetEventSlim release, Ferrum2TcpGateObservation observation) {
        try {
            release.Wait(stopped.Token);
            using (client)
            using (var upstream = new TcpClient(AddressFamily.InterNetwork)) {
                if (!RegisterClient(upstream)) return;
                upstream.Connect(IPAddress.Loopback, upstreamPort);
                observation.SetStage(true, "source_stream");
                observation.SetStage(false, "destination_stream");
                var clientStream = client.GetStream();
                observation.SetStage(true, "destination_stream");
                observation.SetStage(false, "source_stream");
                var upstreamStream = upstream.GetStream();
                var first = Pump(clientStream, upstreamStream, upstream.Client, observation, true);
                var second = Pump(upstreamStream, clientStream, client.Client, observation, false);
                Task.WaitAll(first, second);
            }
        } catch (OperationCanceledException) { observation.FailBoth("cancelled"); }
        catch (IOException) { observation.FailBoth("io"); }
        catch (ObjectDisposedException) { observation.FailBoth("disposed"); }
        catch (SocketException) { observation.FailBoth("socket"); }
        catch (InvalidOperationException) { observation.FailBoth("invalid_operation"); }
        catch (NotSupportedException) { observation.FailBoth("not_supported"); }
        catch (AggregateException) { observation.FailBoth("aggregate"); }
        catch (Exception) { observation.FailBoth("other"); }
        finally { observation.Complete(); }
    }

    private static async Task Pump(NetworkStream input, NetworkStream output, Socket destination, Ferrum2TcpGateObservation observation, bool forward) {
        try {
            var buffer = new byte[4096];
            while (true) {
                observation.SetStage(forward, "read");
                var count = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                if (count == 0) { observation.MarkEof(forward); break; }
                observation.SetStage(forward, "write");
                await output.WriteAsync(buffer, 0, count).ConfigureAwait(false);
                observation.AddBytes(forward, count);
            }
            observation.SetStage(forward, "shutdown");
            try { destination.Shutdown(SocketShutdown.Send); }
            catch (SocketException) { observation.Fail(forward, "socket"); }
        } catch (OperationCanceledException) { observation.Fail(forward, "cancelled"); }
        catch (IOException) { observation.Fail(forward, "io"); }
        catch (ObjectDisposedException) { observation.Fail(forward, "disposed"); }
        catch (SocketException) { observation.Fail(forward, "socket"); }
        catch (InvalidOperationException) { observation.Fail(forward, "invalid_operation"); }
        catch (NotSupportedException) { observation.Fail(forward, "not_supported"); }
        catch (Exception) { observation.Fail(forward, "other"); }
    }

    private void ReleaseSessions() {
        foreach (var release in releases.Values) release.Set();
    }

    private bool RegisterClient(TcpClient client) {
        lock (clientSync) {
            if (Volatile.Read(ref disposed) != 0) {
                client.Dispose();
                return false;
            }
            clients.Add(client);
            return true;
        }
    }

    private void CloseClients() {
        lock (clientSync) {
            TcpClient client;
            while (clients.TryTake(out client)) client.Dispose();
        }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        listener.Stop();
        ReleaseSessions();
        CloseClients();

        var deadline = Ferrum2BackgroundTaskCleanup.CreateDeadline();
        var failures = new List<Exception>();
        var acceptFailure = Ferrum2BackgroundTaskCleanup.Wait(acceptTask, deadline, "TCP gate accept task");
        if (acceptFailure != null) failures.Add(acceptFailure);
        if (!acceptTask.IsCompleted) throw failures[0];

        // AcceptLoop can win an accept race immediately before listener.Stop(). Once
        // it has joined, no later client or session can escape these final snapshots.
        ReleaseSessions();
        CloseClients();
        foreach (var sessionTask in sessionTasks.ToArray()) {
            var sessionFailure = Ferrum2BackgroundTaskCleanup.Wait(sessionTask, deadline, "TCP gate session task");
            if (sessionFailure != null) failures.Add(sessionFailure);
        }
        foreach (var sessionTask in sessionTasks) {
            if (!sessionTask.IsCompleted) {
                throw failures.Count == 1
                    ? failures[0]
                    : new AggregateException("TCP gate tasks did not complete during bounded cleanup", failures);
            }
        }

        foreach (var release in releases.Values) release.Dispose();
        stopped.Dispose();
        if (failures.Count == 1) throw failures[0];
        if (failures.Count > 1) throw new AggregateException("TCP gate tasks faulted during bounded cleanup", failures);
    }
}

public sealed class Ferrum2TcpProbe : IDisposable {
    private readonly TcpListener listener;
    private readonly string mode;
    private readonly Task worker;
    private readonly ManualResetEventSlim accepted = new ManualResetEventSlim(false);
    private readonly ManualResetEventSlim completed = new ManualResetEventSlim(false);
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly object clientSync = new object();
    private readonly object signalSync = new object();
    private TcpClient client;
    private byte[] received = new byte[0];
    private long echoBytes;
    private int readEof;
    private int sendShutdown;
    private int sessionComplete;
    private int readAttempts;
    private int disposed;
    private int signalsDisposed;
    private string fault;

    public Ferrum2TcpProbe(string address, int port, string mode) {
        this.mode = mode;
        listener = new TcpListener(IPAddress.Parse(address), port);
        listener.Start();
        worker = Task.Run(Run);
    }

    public bool WaitAccepted(int milliseconds) { return accepted.Wait(milliseconds); }
    public bool WaitCompleted(int milliseconds) { return completed.Wait(milliseconds); }
    public byte[] Received { get { return received; } }
    public long EchoByteCount { get { return Interlocked.Read(ref echoBytes); } }
    public string ReadEof { get { return Volatile.Read(ref readEof) == 0 ? "no" : "yes"; } }
    public string SendShutdown { get { return Volatile.Read(ref sendShutdown) == 0 ? "no" : "yes"; } }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }
    public string SessionComplete { get { return Volatile.Read(ref sessionComplete) == 0 ? "no" : "yes"; } }
    public int ReadAttempts { get { return Volatile.Read(ref readAttempts); } }
    public string WorkerStatus { get { return worker.Status.ToString(); } }
    public bool ListenerActive {
        get {
            if (Volatile.Read(ref disposed) != 0) return false;
            try { return listener.Server != null && listener.Server.IsBound; }
            catch (ObjectDisposedException) { return false; }
            catch (SocketException) { return false; }
        }
    }
    public bool AcceptedSocketConnected {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return false;
            try { return current.Connected; }
            catch (ObjectDisposedException) { return false; }
            catch (SocketException) { return false; }
        }
    }
    public bool AcceptedSocketOpen {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return false;
            try {
                var socket = current.Client;
                return socket != null && socket.Connected && !(socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0);
            }
            catch (ObjectDisposedException) { return false; }
            catch (SocketException) { return false; }
        }
    }
    public int AcceptedSocketAvailable {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return 0;
            try { return current.Client.Available; }
            catch (ObjectDisposedException) { return 0; }
            catch (SocketException) { return 0; }
        }
    }
    public string AcceptedSocketLocalEndpoint {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return null;
            try { return current.Client.LocalEndPoint == null ? null : current.Client.LocalEndPoint.ToString(); }
            catch (ObjectDisposedException) { return null; }
            catch (SocketException) { return null; }
        }
    }
    public string AcceptedSocketRemoteEndpoint {
        get {
            var current = Volatile.Read(ref client);
            if (current == null) return null;
            try { return current.Client.RemoteEndPoint == null ? null : current.Client.RemoteEndPoint.ToString(); }
            catch (ObjectDisposedException) { return null; }
            catch (SocketException) { return null; }
        }
    }
    public bool StallWaitActive {
        get { return mode == "stall" && accepted.IsSet && !completed.IsSet && worker.Status != TaskStatus.RanToCompletion; }
    }

    private void Signal(ManualResetEventSlim signal) {
        lock (signalSync) {
            if (Volatile.Read(ref signalsDisposed) == 0) signal.Set();
        }
    }

    private async Task Run() {
        try {
            var acceptedClient = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
            lock (clientSync) {
                if (Volatile.Read(ref disposed) != 0) {
                    acceptedClient.Dispose();
                    return;
                }
                Volatile.Write(ref client, acceptedClient);
            }
            Signal(accepted);
            if (mode == "stall") {
                stopped.Token.WaitHandle.WaitOne();
                return;
            }
            var stream = client.GetStream();
            using (var bytes = new MemoryStream()) {
                var buffer = new byte[4096];
                do {
                    Interlocked.Increment(ref readAttempts);
                    var count = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (count == 0) { Volatile.Write(ref readEof, 1); break; }
                    bytes.Write(buffer, 0, count);
                    if (mode == "capture") break;
                } while (!stopped.IsCancellationRequested);
                received = bytes.ToArray();
            }
            if (mode == "echo") {
                await stream.WriteAsync(received, 0, received.Length).ConfigureAwait(false);
                Interlocked.Add(ref echoBytes, received.Length);
                try {
                    client.Client.Shutdown(SocketShutdown.Send);
                    Volatile.Write(ref sendShutdown, 1);
                } catch (SocketException) { Interlocked.CompareExchange(ref fault, "socket", null); }
            }
        } catch (OperationCanceledException) { Interlocked.CompareExchange(ref fault, "cancelled", null); }
        catch (IOException) { Interlocked.CompareExchange(ref fault, "io", null); }
        catch (ObjectDisposedException) { Interlocked.CompareExchange(ref fault, "disposed", null); }
        catch (SocketException) { Interlocked.CompareExchange(ref fault, "socket", null); }
        catch (Exception) {
            Interlocked.CompareExchange(ref fault, "other", null);
            throw;
        }
        finally {
            Volatile.Write(ref sessionComplete, 1);
            Signal(completed);
        }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        listener.Stop();
        lock (clientSync) {
            var current = Volatile.Read(ref client);
            if (current != null) current.Dispose();
        }

        Exception workerFailure = null;
        var deadline = Ferrum2BackgroundTaskCleanup.CreateDeadline();
        workerFailure = Ferrum2BackgroundTaskCleanup.Wait(worker, deadline, "TCP probe worker");
        if (!worker.IsCompleted) {
            throw workerFailure ?? new TimeoutException("TCP probe worker did not report completion after bounded cleanup wait");
        }

        lock (signalSync) {
            Volatile.Write(ref signalsDisposed, 1);
            accepted.Dispose();
            completed.Dispose();
        }
        stopped.Dispose();
        if (workerFailure != null) throw workerFailure;
    }
}

public sealed class Ferrum2UdpGate : IDisposable {
    private readonly object sync = new object();
    private readonly object upstreamSync = new object();
    private readonly UdpClient socket;
    private readonly int upstreamPort;
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly Task worker;
    private UdpClient activeUpstream;
    private byte[] firstResponse;
    private IPEndPoint latestClient;
    private int requests;
    private int responses;
    private int disposed;
    private string fault;

    public Ferrum2UdpGate(string listenAddress, int listenPort, int upstreamPort) {
        this.upstreamPort = upstreamPort;
        socket = new UdpClient(new IPEndPoint(IPAddress.Parse(listenAddress), listenPort));
        worker = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }
    public int Responses { get { return Volatile.Read(ref responses); } }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }

    public bool WaitRequests(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Requests >= expected) return true;
            Thread.Sleep(10);
        }
        return Requests >= expected;
    }

    public bool ReplayFirstToLatest() {
        byte[] response;
        IPEndPoint client;
        lock (sync) {
            response = firstResponse;
            client = latestClient;
        }
        if (response == null || client == null) return false;
        socket.Send(response, response.Length, client);
        return true;
    }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                lock (sync) { latestClient = request.RemoteEndPoint; }
                Interlocked.Increment(ref requests);
                using (var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0))) {
                    if (!RegisterUpstream(upstream)) return;
                    try {
                        upstream.Connect(IPAddress.Loopback, upstreamPort);
                        await upstream.SendAsync(request.Buffer, request.Buffer.Length).ConfigureAwait(false);
                        var response = await upstream.ReceiveAsync().ConfigureAwait(false);
                        lock (sync) {
                            if (firstResponse == null) firstResponse = (byte[])response.Buffer.Clone();
                        }
                        await socket.SendAsync(response.Buffer, response.Buffer.Length, request.RemoteEndPoint).ConfigureAwait(false);
                        Interlocked.Increment(ref responses);
                    } finally {
                        UnregisterUpstream(upstream);
                    }
                }
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
        catch (Exception) {
            Interlocked.CompareExchange(ref fault, "other", null);
            throw;
        }
    }

    private bool RegisterUpstream(UdpClient upstream) {
        lock (upstreamSync) {
            if (Volatile.Read(ref disposed) != 0) {
                upstream.Dispose();
                return false;
            }
            activeUpstream = upstream;
            return true;
        }
    }

    private void UnregisterUpstream(UdpClient upstream) {
        lock (upstreamSync) {
            if (Object.ReferenceEquals(activeUpstream, upstream)) activeUpstream = null;
        }
    }

    private void CloseActiveUpstream() {
        lock (upstreamSync) {
            if (activeUpstream != null) activeUpstream.Dispose();
        }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        socket.Dispose();
        CloseActiveUpstream();

        var deadline = Ferrum2BackgroundTaskCleanup.CreateDeadline();
        var workerFailure = Ferrum2BackgroundTaskCleanup.Wait(worker, deadline, "UDP gate worker");
        if (!worker.IsCompleted) {
            throw workerFailure ?? new TimeoutException("UDP gate worker did not report completion after bounded cleanup wait");
        }
        stopped.Dispose();
        if (workerFailure != null) throw workerFailure;
    }
}

public sealed class Ferrum2UdpProbe : IDisposable {
    private readonly UdpClient socket;
    private readonly byte[] fixedResponse;
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly Task worker;
    private byte[] received = new byte[0];
    private IPEndPoint remoteEndpoint;
    private int requests;
    private int responses;
    private int disposed;
    private string fault;

    public Ferrum2UdpProbe(string address, int port) : this(address, port, null) { }

    public Ferrum2UdpProbe(string address, int port, byte[] responsePayload) {
        socket = new UdpClient(new IPEndPoint(IPAddress.Parse(address), port));
        fixedResponse = responsePayload == null ? null : (byte[])responsePayload.Clone();
        worker = Task.Run(Run);
    }

    public int Requests { get { return Volatile.Read(ref requests); } }
    public int Responses { get { return Volatile.Read(ref responses); } }
    public byte[] Received { get { return Volatile.Read(ref received); } }
    public IPEndPoint RemoteEndpoint {
        get {
            var endpoint = Volatile.Read(ref remoteEndpoint);
            return endpoint == null ? null : new IPEndPoint(endpoint.Address, endpoint.Port);
        }
    }
    public string Fault { get { return Volatile.Read(ref fault) ?? "none"; } }

    public bool WaitRequests(int expected, int milliseconds) {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline) {
            if (Requests >= expected) return true;
            Thread.Sleep(10);
        }
        return Requests >= expected;
    }

    public void SendTo(byte[] payload, IPEndPoint endpoint) {
        if (payload == null || endpoint == null) throw new ArgumentNullException();
        if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException("Ferrum2UdpProbe");
        socket.Send(payload, payload.Length, endpoint);
    }

    private async Task Run() {
        try {
            while (!stopped.IsCancellationRequested) {
                var request = await socket.ReceiveAsync().ConfigureAwait(false);
                Volatile.Write(ref received, (byte[])request.Buffer.Clone());
                Volatile.Write(ref remoteEndpoint, request.RemoteEndPoint);
                Interlocked.Increment(ref requests);
                var response = fixedResponse ?? request.Buffer;
                await socket.SendAsync(response, response.Length, request.RemoteEndPoint).ConfigureAwait(false);
                Interlocked.Increment(ref responses);
            }
        } catch (ObjectDisposedException) { }
        catch (SocketException) when (stopped.IsCancellationRequested) { }
        catch (Exception) {
            Interlocked.CompareExchange(ref fault, "other", null);
            throw;
        }
    }

    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        socket.Dispose();

        var deadline = Ferrum2BackgroundTaskCleanup.CreateDeadline();
        var workerFailure = Ferrum2BackgroundTaskCleanup.Wait(worker, deadline, "UDP probe worker");
        if (!worker.IsCompleted) {
            throw workerFailure ?? new TimeoutException("UDP probe worker did not report completion after bounded cleanup wait");
        }
        stopped.Dispose();
        if (workerFailure != null) throw workerFailure;
    }
}

'@
