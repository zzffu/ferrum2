function New-Ferrum2KillOnCloseJob {
    if ($null -eq ("Ferrum2.HyperV.KillOnCloseJob" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Ferrum2.HyperV
{
    public sealed class KillOnCloseJob : IDisposable
    {
        private const uint JobObjectExtendedLimitInformation = 9;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private IntPtr handle;

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimitInformation
        {
            public BasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicAccountingInformation
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            uint informationClass,
            ref ExtendedLimitInformation information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessInJob(
            IntPtr process,
            IntPtr job,
            out bool result);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(
            IntPtr job,
            uint informationClass,
            out BasicAccountingInformation information,
            uint informationLength,
            IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public KillOnCloseJob()
        {
            handle = CreateJobObject(IntPtr.Zero, null);
            if (handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
            }
            var information = new ExtendedLimitInformation();
            information.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            if (!SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    ref information,
                    (uint)Marshal.SizeOf<ExtendedLimitInformation>()))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(handle);
                handle = IntPtr.Zero;
                throw new Win32Exception(error, "SetInformationJobObject failed");
            }
        }

        public void Add(Process process)
        {
            if (handle == IntPtr.Zero || process == null)
            {
                throw new ObjectDisposedException(nameof(KillOnCloseJob));
            }
            if (!AssignProcessToJobObject(handle, process.Handle))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "AssignProcessToJobObject failed");
            }
        }

        public bool Contains(Process process)
        {
            if (handle == IntPtr.Zero || process == null)
            {
                throw new ObjectDisposedException(nameof(KillOnCloseJob));
            }
            bool result;
            if (!IsProcessInJob(process.Handle, handle, out result))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "IsProcessInJob failed");
            }
            return result;
        }

        public uint ActiveProcessCount
        {
            get
            {
                if (handle == IntPtr.Zero)
                {
                    throw new ObjectDisposedException(nameof(KillOnCloseJob));
                }
                BasicAccountingInformation information;
                if (!QueryInformationJobObject(
                        handle,
                        1,
                        out information,
                        (uint)Marshal.SizeOf<BasicAccountingInformation>(),
                        IntPtr.Zero))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "QueryInformationJobObject failed");
                }
                return information.ActiveProcesses;
            }
        }

        public bool WaitForEmpty(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds));
            }
            var stopwatch = Stopwatch.StartNew();
            do
            {
                if (ActiveProcessCount == 0)
                {
                    return true;
                }
                Thread.Sleep(10);
            }
            while (stopwatch.ElapsedMilliseconds < timeoutMilliseconds);
            return ActiveProcessCount == 0;
        }

        public void Terminate(uint exitCode)
        {
            if (handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(KillOnCloseJob));
            }
            if (!TerminateJobObject(handle, exitCode))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject failed");
            }
        }

        public void Dispose()
        {
            IntPtr owned = handle;
            handle = IntPtr.Zero;
            if (owned != IntPtr.Zero && !CloseHandle(owned))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle failed");
            }
            GC.SuppressFinalize(this);
        }

        ~KillOnCloseJob()
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
                handle = IntPtr.Zero;
            }
        }
    }
}
'@
    }
    return [Ferrum2.HyperV.KillOnCloseJob]::new()
}

function Invoke-BoundedPwshFile {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][ValidateRange(1, 21600)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9 -]{1,64}$')]
        [string]$Label,
        [Collections.IDictionary]$Environment = @{},
        [AllowNull()][Threading.EventWaitHandle]$StartGate = $null
    )

    $currentProcess = Get-Process -Id $PID -ErrorAction Stop
    $powerShellPath = [IO.Path]::GetFullPath([string]$currentProcess.Path)
    if ([IO.Path]::GetFileName($powerShellPath) -ine "pwsh.exe" -or
        -not (Test-Path -LiteralPath $powerShellPath -PathType Leaf)) {
        throw "$Label requires the current pwsh.exe"
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $powerShellPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }
    foreach ($key in @($Environment.Keys)) {
        $name = [string]$key
        $value = [string]$Environment[$key]
        if ($name -cnotmatch '^FERRUM2_[A-Z0-9_]{1,63}$' -or
            $value.Length -gt 256 -or $value.IndexOf([char]0) -ge 0) {
            throw "$Label child environment is invalid"
        }
        $startInfo.Environment[$name] = $value
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $job = New-Ferrum2KillOnCloseJob
    $started = $false
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutBytes = [IO.MemoryStream]::new()
    $stderrBytes = [IO.MemoryStream]::new()
    $boundedResult = $null
    $primaryFailure = $null
    $finalizationIssues = [Collections.Generic.List[string]]::new()
    try {
        if (-not $process.Start()) {
            throw "$Label did not start"
        }
        $started = $true
        try {
            $job.Add($process)
            if (-not $job.Contains($process)) {
                throw "$Label job membership readback failed"
            }
            if ($null -ne $StartGate -and -not $StartGate.Set()) {
                throw "$Label worker start gate could not be released"
            }
        } catch {
            try { $process.Kill($true) } catch { }
            [void]$process.WaitForExit(30000)
            throw "$Label could not enter the kill-on-close job: $($_.Exception.Message)"
        }
        $stdoutStream = $process.StandardOutput.BaseStream
        $stderrStream = $process.StandardError.BaseStream
        [byte[]]$stdoutBuffer = [byte[]]::new(8192)
        [byte[]]$stderrBuffer = [byte[]]::new(8192)
        $stdoutTask = $stdoutStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
        $stderrTask = $stderrStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
        $stdoutEof = $false
        $stderrEof = $false
        $streamFailure = $null
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $timeoutMilliseconds = [long]$TimeoutSeconds * 1000
        while ($stopwatch.ElapsedMilliseconds -lt $timeoutMilliseconds) {
            $madeProgress = $false
            if (-not $stdoutEof -and $stdoutTask.IsCompleted) {
                $madeProgress = $true
                try {
                    $count = [int]$stdoutTask.GetAwaiter().GetResult()
                    if ($count -eq 0) {
                        $stdoutEof = $true
                    } elseif ($stdoutBytes.Length + $count -gt 16777216) {
                        $streamFailure = "$Label stdout exceeded the 16 MiB boundary"
                    } else {
                        $stdoutBytes.Write($stdoutBuffer, 0, $count)
                        $stdoutTask = $stdoutStream.ReadAsync(
                            $stdoutBuffer,
                            0,
                            $stdoutBuffer.Length
                        )
                    }
                } catch {
                    $streamFailure = "$Label stdout read failed: $($_.Exception.Message)"
                }
            }
            if (-not $stderrEof -and $stderrTask.IsCompleted) {
                $madeProgress = $true
                try {
                    $count = [int]$stderrTask.GetAwaiter().GetResult()
                    if ($count -eq 0) {
                        $stderrEof = $true
                    } elseif ($stderrBytes.Length + $count -gt 16777216) {
                        $streamFailure = "$Label stderr exceeded the 16 MiB boundary"
                    } else {
                        $stderrBytes.Write($stderrBuffer, 0, $count)
                        $stderrTask = $stderrStream.ReadAsync(
                            $stderrBuffer,
                            0,
                            $stderrBuffer.Length
                        )
                    }
                } catch {
                    $streamFailure = "$Label stderr read failed: $($_.Exception.Message)"
                }
            }
            if ($null -ne $streamFailure -or
                ($process.HasExited -and $stdoutEof -and $stderrEof)) {
                break
            }
            if (-not $madeProgress) {
                Start-Sleep -Milliseconds 1
            }
        }
        $timedOut = $null -eq $streamFailure -and
            -not ($process.HasExited -and $stdoutEof -and $stderrEof)
        if ($null -ne $streamFailure -or $timedOut) {
            $terminationTrigger = if ($null -ne $streamFailure) {
                [string]$streamFailure
            } else {
                "$Label timed out after $TimeoutSeconds seconds"
            }
            $terminationIssues = [Collections.Generic.List[string]]::new()
            $jobHasActiveProcess = $true
            try {
                $jobHasActiveProcess = $job.ActiveProcessCount -ne 0
            } catch {
                $terminationIssues.Add(
                    "job accounting readback failed: $($_.Exception.Message)"
                )
            }
            if (-not $process.HasExited -or $jobHasActiveProcess) {
                try { $job.Terminate(57005) } catch {
                    $terminationIssues.Add("job termination failed: $($_.Exception.Message)")
                }
                if (-not $process.WaitForExit(30000)) {
                    try { $process.Kill($true) } catch {
                        $terminationIssues.Add("fallback tree kill failed: $($_.Exception.Message)")
                    }
                    if (-not $process.WaitForExit(10000)) {
                        $terminationIssues.Add("worker exit was not confirmed")
                    }
                }
            }
            foreach ($stream in @($stdoutStream, $stderrStream)) {
                try { $stream.Close() } catch {
                    $terminationIssues.Add("worker output close failed: $($_.Exception.Message)")
                }
            }
            if ($terminationIssues.Count -ne 0) {
                throw (
                    "$terminationTrigger; termination was not proven: " +
                    ($terminationIssues -join "; ")
                )
            }
            try {
                if (-not $job.WaitForEmpty(10000)) {
                    throw "termination left an active job process"
                }
            } catch {
                throw (
                    "$terminationTrigger; termination proof failed: " +
                        $_.Exception.Message
                )
            }
            throw "$terminationTrigger and was terminated"
        }
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $stdout = $utf8.GetString($stdoutBytes.ToArray())
        # Native Windows and Hyper-V failures can contribute localized system-code-page bytes to
        # stderr. It is diagnostic-only and any non-empty value still fails the worker contract;
        # preserve strict UTF-8 for the accepted stdout terminal while retaining readable errors.
        $stderr = [Text.UTF8Encoding]::new($false, $false).GetString(
            $stderrBytes.ToArray()
        )
        if (-not $job.WaitForEmpty(5000)) {
            $job.Terminate(57005)
            if (-not $job.WaitForEmpty(10000)) {
                throw "$Label completed with an unreaped job process"
            }
            throw "$Label completed while a descendant process remained active"
        }
        $boundedResult = [pscustomobject][ordered]@{
            ExitCode = [int]$process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    } catch {
        $primaryFailure = $_
    } finally {
        try {
            $cancellationRequired = $false
            if ($started) {
                try {
                    $cancellationRequired = -not $process.HasExited
                } catch {
                    $cancellationRequired = $true
                    $finalizationIssues.Add(
                        "$Label cancellation process readback failed: " +
                            $_.Exception.Message
                    )
                }
            }
            if ($started -and -not $cancellationRequired) {
                try {
                    $cancellationRequired = $job.ActiveProcessCount -ne 0
                } catch {
                    $cancellationRequired = $true
                    $finalizationIssues.Add(
                        "$Label cancellation job accounting failed: " +
                            $_.Exception.Message
                    )
                }
            }
            if ($cancellationRequired) {
                try { $job.Terminate(57005) } catch {
                    $finalizationIssues.Add(
                        "$Label cancellation job termination failed: " +
                            $_.Exception.Message
                    )
                }
                try {
                    if (-not $process.WaitForExit(30000)) {
                        $finalizationIssues.Add(
                            "$Label cancellation exit was not confirmed"
                        )
                    }
                } catch {
                    $finalizationIssues.Add(
                        "$Label cancellation exit readback failed: " +
                            $_.Exception.Message
                    )
                }
                try {
                    if (-not $job.WaitForEmpty(10000)) {
                        $finalizationIssues.Add(
                            "$Label cancellation left an active job process"
                        )
                    }
                } catch {
                    $finalizationIssues.Add(
                        "$Label cancellation job readback failed: " +
                            $_.Exception.Message
                    )
                }
            }
        } catch {
            $finalizationIssues.Add(
                "$Label cancellation finalization failed: $($_.Exception.Message)"
            )
        }
        foreach ($stream in @($stdoutStream, $stderrStream)) {
            if ($null -ne $stream) {
                try {
                    $stream.Dispose()
                } catch {
                    $finalizationIssues.Add(
                        "$Label worker output disposal failed: " +
                            $_.Exception.Message
                    )
                }
            }
        }
        foreach ($buffer in @($stdoutBytes, $stderrBytes)) {
            try {
                $buffer.Dispose()
            } catch {
                $finalizationIssues.Add(
                    "$Label worker buffer disposal failed: " +
                        $_.Exception.Message
                )
            }
        }
        try {
            $job.Dispose()
        } catch {
            $finalizationIssues.Add(
                "$Label worker job disposal failed: $($_.Exception.Message)"
            )
        }
        try {
            $process.Dispose()
        } catch {
            $finalizationIssues.Add(
                "$Label worker process disposal failed: $($_.Exception.Message)"
            )
        }
    }
    if ($null -ne $primaryFailure) {
        if ($finalizationIssues.Count -ne 0) {
            throw (
                "$Label failed: primary=$($primaryFailure.Exception.Message); " +
                    "finalization=$($finalizationIssues -join '; ')"
            )
        }
        throw $primaryFailure
    }
    if ($finalizationIssues.Count -ne 0) {
        throw "$Label finalization failed: $($finalizationIssues -join '; ')"
    }
    return $boundedResult
}

function Invoke-ApprovedVmWorkerEmergencyCleanup {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][ValidateRange(30, 900)]
        [int]$ShutdownTimeoutSeconds,
        [Parameter(Mandatory = $true)]
        [ValidateSet("StopOnly", "RestoreCheckpoint")]
        [string]$Mode
    )

    $issues = [Collections.Generic.List[string]]::new()
    $stopped = $false
    $restored = $false
    try {
        Stop-ApprovedVmEmergency -Authority $Authority `
            -TimeoutSeconds $ShutdownTimeoutSeconds
        $stopped = $true
    } catch {
        $issues.Add("initial exact-GUID stop failed: $($_.Exception.Message)")
    }
    if ($stopped -and $Mode -ceq "RestoreCheckpoint") {
        try {
            Restore-ApprovedCheckpointEmergency -Authority $Authority `
                -ShutdownTimeoutSeconds $ShutdownTimeoutSeconds
            $restored = $true
        } catch {
            $issues.Add("exact-checkpoint restore failed: $($_.Exception.Message)")
        }
    } elseif ($Mode -ceq "RestoreCheckpoint") {
        $issues.Add("exact-checkpoint restore was skipped because Off was not proven")
    } else {
        $restored = $true
    }
    try {
        Stop-ApprovedVmEmergency -Authority $Authority `
            -TimeoutSeconds $ShutdownTimeoutSeconds
    } catch {
        $issues.Add("post-restore exact-GUID stop failed: $($_.Exception.Message)")
    }
    try {
        $finalState = [string](Get-ApprovedVmEmergencyState -Authority $Authority).State
        if ($finalState -cne "Off") {
            $issues.Add("final exact-GUID state is $finalState")
        }
    } catch {
        $issues.Add("final exact-GUID readback failed: $($_.Exception.Message)")
    }
    if (-not $restored) {
        $issues.Add("the approved checkpoint restore was not proven")
    }
    if ($issues.Count -ne 0) {
        throw "bounded worker emergency cleanup failed: $($issues -join '; ')"
    }
}
