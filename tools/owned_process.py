"""Owned process-tree lifetime, including descendants surviving their leader."""
from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import time
import threading
from dataclasses import dataclass
from ctypes import wintypes

class OwnershipError(OSError):
    """The owned process tree could not be established or confirmed stopped."""


class ProcessTree:
    def __init__(self, process):
        self.process = process
        self.job = None
        if os.name != "nt":
            return
        # Pointer-sized fields are required on 64-bit Windows. Job kill-on-close
        # also covers descendants if their original parent exits first.
        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                        ("flags", wintypes.DWORD), ("minimum_working_set", ctypes.c_size_t),
                        ("maximum_working_set", ctypes.c_size_t), ("active_process_limit", wintypes.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]

        class Io(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

        class Limits(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", Io), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.job = self.kernel.CreateJobObjectW(None, None)
        limits = Limits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.job or not self.kernel.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self._release_job()
            raise OwnershipError("cannot establish owned process job")
        if not self.kernel.AssignProcessToJobObject(self.job, wintypes.HANDLE(int(process._handle))):
            self._release_job()
            raise OwnershipError("cannot assign child to owned process job")
        native = ctypes.WinDLL("ntdll")
        native.NtResumeProcess.argtypes = [wintypes.HANDLE]
        native.NtResumeProcess.restype = wintypes.LONG
        if native.NtResumeProcess(wintypes.HANDLE(int(process._handle))) != 0:
            self._release_job()
            raise OwnershipError("cannot resume owned child process")

    @classmethod
    def spawn(cls, argv, **kwargs):
        if os.name == "nt":
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | subprocess.CREATE_NEW_PROCESS_GROUP | 0x4
        else:
            kwargs.pop("creationflags", None)
            if not hasattr(os, "WNOWAIT"):
                raise OwnershipError("non-reaping process observation is unavailable")
            kwargs["start_new_session"] = True
        process = subprocess.Popen(argv, **kwargs)
        try:
            return cls(process)
        except BaseException:
            # A failed Windows admission still owns the suspended direct child.
            try:
                process.kill()
                process.wait(timeout=5)
            finally:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            raise

    def exited(self):
        if os.name == "nt":
            return self.process.poll() is not None
        return os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    def signal(self, number):
        try:
            if os.name == "nt":
                self.process.send_signal(number)
            else:
                os.killpg(self.process.pid, number)
            return True
        except ProcessLookupError:
            return True
        except OSError:
            return False

    @staticmethod
    def _group_live(group):
        with os.scandir("/proc") as entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                try:
                    with open(f"/proc/{entry.name}/stat", "rb") as stream:
                        raw = stream.read(4097)
                    if len(raw) > 4096:
                        raise OSError("unreadable process identity")
                    fields = raw.rsplit(b") ", 1)[1].split()
                    if int(fields[2]) == group and fields[0] not in {b"Z", b"X"}:
                        return True
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except (IndexError, ValueError) as error:
                    raise OSError("unreadable process identity") from error
        return False

    def _release_job(self):
        if self.job:
            if not self.kernel.CloseHandle(self.job):
                raise OwnershipError("cannot close owned process job")
            self.job = None

    def close(self, grace=5.0):
        """Final owned signal, confirmation, then reap; never signal after reap."""
        deadline = time.monotonic() + grace
        confirmed = True
        try:
            if os.name == "nt":
                self.kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
                self.kernel.TerminateJobObject.restype = wintypes.BOOL
                self.kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
                self.kernel.QueryInformationJobObject.restype = wintypes.BOOL
                if not self.kernel.TerminateJobObject(self.job, 1):
                    confirmed = False
                # JOBOBJECT_BASIC_ACCOUNTING_INFORMATION has ActiveProcesses
                # after four LARGE_INTEGER and two DWORD fields.
                class Accounting(ctypes.Structure):
                    _fields_ = [("times", ctypes.c_int64 * 4), ("faults", wintypes.DWORD),
                                ("total", wintypes.DWORD), ("active", wintypes.DWORD),
                                ("terminated", wintypes.DWORD)]
                def live():
                    value = Accounting()
                    if not self.kernel.QueryInformationJobObject(self.job, 1, ctypes.byref(value), ctypes.sizeof(value), None):
                        raise OwnershipError("cannot query owned process job")
                    return value.active != 0
            else:
                confirmed = self.signal(signal.SIGKILL)
                def live():
                    return self._group_live(self.process.pid)
            while live():
                if time.monotonic() >= deadline:
                    confirmed = False
                    break
                time.sleep(0.01)
        except OSError:
            confirmed = False
        finally:
            try:
                self.process.wait(timeout=max(0, deadline - time.monotonic()))
            except (OSError, subprocess.TimeoutExpired):
                confirmed = False
            if os.name == "nt":
                try:
                    self._release_job()
                except OSError:
                    confirmed = False
        return confirmed


@dataclass(frozen=True)
class Capture:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    failure: str | None
    cleanup_confirmed: bool


def capture(argv, *, deadline, stdout_cap, stderr_cap, cwd=None, env=None,
            creationflags=0, cleanup_grace=5.0, merge_stderr=False):
    """Capture bounded output while owning descendants and both pipe lifetimes."""
    if time.monotonic() >= deadline:
        return Capture(None, b"", b"", "timed_out", True)
    tree = ProcessTree.spawn(argv, cwd=cwd, env=env, creationflags=creationflags,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE)
    completed = {}
    readers = []
    overflow = threading.Event()
    failed = threading.Event()
    failure = None
    clean = False

    def drain(name, stream, cap):
        retained = bytearray()
        try:
            if stream is None:
                return
            while block := stream.read(8192):
                remaining = max(0, cap - len(retained))
                retained.extend(block[:remaining])
                if len(block) > remaining:
                    overflow.set()
        except OSError:
            failed.set()
        finally:
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                failed.set()
            completed[name] = bytes(retained)

    try:
        for name, cap in (("stdout", stdout_cap), ("stderr", stderr_cap)):
            reader = threading.Thread(target=drain, args=(name, getattr(tree.process, name), cap), daemon=True)
            reader.start()
            readers.append(reader)
        while True:
            if overflow.is_set():
                failure = "output_limit"
                break
            if failed.is_set():
                failure = "capture_failed"
                break
            if tree.exited() and len(completed) == 2:
                break
            if time.monotonic() >= deadline:
                failure = "timed_out"
                break
            time.sleep(0.01)
    except Exception:
        failure = "start_failed" if len(readers) != 2 else "capture_failed"
    finally:
        cleanup_deadline = time.monotonic() + cleanup_grace
        # Give wrappers such as sudo a bounded chance to forward termination
        # to their command before the final, non-cooperative group kill.
        if os.name != "nt" and failure is not None:
            tree.signal(signal.SIGTERM)
            time.sleep(min(0.1, cleanup_grace / 4))
        clean = tree.close(max(0, cleanup_deadline - time.monotonic()))
        for reader in readers:
            reader.join(max(0, cleanup_deadline - time.monotonic()))
            clean &= not reader.is_alive()
        for name in ("stdout", "stderr")[len(readers):]:
            stream = getattr(tree.process, name)
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    clean = False
    if failure is None:
        failure = "output_limit" if overflow.is_set() else "capture_failed" if failed.is_set() else None
    return Capture(tree.process.returncode, completed.get("stdout", b""),
                   completed.get("stderr", b""), failure, clean)
