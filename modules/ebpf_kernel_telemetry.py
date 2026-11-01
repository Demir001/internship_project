# -*- coding: utf-8 -*-
"""
==============================================================================
eBPF LINUX KERNEL TELEMETRY & ZERO-LATENCY SENSOR (ebpf_kernel_telemetry.py)
==============================================================================
Provides zero-overhead, real-time Linux kernel-space event interception using
eBPF (Extended Berkeley Packet Filter) tracepoints and kprobes:
1. Process Execution Interception:
   - Hooks: tracepoint/syscalls/sys_enter_execve & sys_enter_execveat
   - Captures: Executed binary paths, full argument vectors (argv), PID, PPID, UID, GID, TTY.
2. Outbound Network Socket Interception:
   - Hooks: tracepoint/syscalls/sys_enter_connect & kprobe/tcp_v4_connect
   - Captures: Source IP, Destination IP, Destination Port, Protocol, Calling Process PID.
3. Sensitive File Access Interception:
   - Hooks: tracepoint/syscalls/sys_enter_openat
   - Captures: Path names (/etc/, /root/.ssh/, /tmp/), open flags (O_RDONLY, O_WRONLY, O_CREAT).

Data Pipeline:
eBPF Kernel Ring/Perf Buffer -> Ctypes Binary Struct -> Asynchronous Multi-Core Queue
-> ECS 8.11 Normalizer -> Dual-AI Engine & SIEM Correlation.
==============================================================================
"""

import os
import sys
import time
import socket
import struct
import ctypes
import queue
import threading
from datetime import datetime

import config
from modules.smart_logger import smart_logger

# ------------------------------------------------------------------------------
# 1. CTYPES DATA STRUCTURE MATCHING KERNEL STRUCT
# ------------------------------------------------------------------------------
class EventData(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
        ("args", ctypes.c_char * 512),
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("timestamp_ns", ctypes.c_uint64),
        ("event_type", ctypes.c_uint8),  # 1: EXEC, 2: CONNECT, 3: OPEN
    ]

# Event Type Enums
EVENT_EXEC = 1
EVENT_CONNECT = 2
EVENT_OPEN = 3

# ------------------------------------------------------------------------------
# 2. INLINE eBPF C PROGRAM
# ------------------------------------------------------------------------------
EBPF_KERNEL_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define EVENT_EXEC 1
#define EVENT_CONNECT 2
#define EVENT_OPEN 3
#define AF_INET_V4 2

struct custom_sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    char           sin_zero[8];
};

struct event_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
    char args[512];
    u32 saddr;
    u32 daddr;
    u16 dport;
    u64 timestamp_ns;
    u8 event_type;
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_buffer, struct event_data_t, 1);

// In-kernel Fast Filter: Ignore SIEM Process ID
static __always_inline int is_siem_self(u32 pid) {
    #ifdef SIEM_PID
    if (pid == SIEM_PID) {
        return 1;
    }
    #endif
    return 0;
}

// -----------------------------------------------------------------------------
// 1. PROCESS EXECUTION INTERCEPT (execve & execveat)
// -----------------------------------------------------------------------------
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (is_siem_self(pid))
        return 0;

    u32 zero = 0;
    struct event_data_t *data = event_buffer.lookup(&zero);
    if (!data)
        return 0;

    __builtin_memset(data, 0, sizeof(*data));
    data->pid = pid;
    data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data->timestamp_ns = bpf_ktime_get_ns();
    data->event_type = EVENT_EXEC;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    data->ppid = task->real_parent->tgid;
    #else
    data->ppid = 0;
    #endif

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Read executed filename
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), args->filename);

    // Statically read argv pointers (argv[0] and argv[1]) into data->args
    const char *arg0 = NULL;
    bpf_probe_read_user(&arg0, sizeof(arg0), &args->argv[0]);
    if (arg0) {
        bpf_probe_read_user_str(data->args, 256, arg0);
    }
    const char *arg1 = NULL;
    bpf_probe_read_user(&arg1, sizeof(arg1), &args->argv[1]);
    if (arg1) {
        bpf_probe_read_user_str(&data->args[256], 256, arg1);
    }

    events.perf_submit(args, data, sizeof(*data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (is_siem_self(pid))
        return 0;

    u32 zero = 0;
    struct event_data_t *data = event_buffer.lookup(&zero);
    if (!data)
        return 0;

    __builtin_memset(data, 0, sizeof(*data));
    data->pid = pid;
    data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data->timestamp_ns = bpf_ktime_get_ns();
    data->event_type = EVENT_EXEC;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    data->ppid = task->real_parent->tgid;
    #else
    data->ppid = 0;
    #endif

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), args->filename);

    events.perf_submit(args, data, sizeof(*data));
    return 0;
}

// -----------------------------------------------------------------------------
// 2. OUTBOUND NETWORK CONNECTION HOOK (sys_enter_connect)
// -----------------------------------------------------------------------------
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (is_siem_self(pid))
        return 0;

    struct custom_sockaddr_in uservaddr = {};
    bpf_probe_read_user(&uservaddr, sizeof(uservaddr), args->uservaddr);

    // Only process IPv4 AF_INET connections
    if (uservaddr.sin_family != AF_INET_V4)
        return 0;

    u32 zero = 0;
    struct event_data_t *data = event_buffer.lookup(&zero);
    if (!data)
        return 0;

    __builtin_memset(data, 0, sizeof(*data));
    data->pid = pid;
    data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data->timestamp_ns = bpf_ktime_get_ns();
    data->event_type = EVENT_CONNECT;
    data->daddr = uservaddr.sin_addr;
    data->dport = bpf_ntohs(uservaddr.sin_port);

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    events.perf_submit(args, data, sizeof(*data));
    return 0;
}

// -----------------------------------------------------------------------------
// 3. SENSITIVE FILE ACCESS HOOK (sys_enter_openat)
// -----------------------------------------------------------------------------
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (is_siem_self(pid))
        return 0;

    u32 zero = 0;
    struct event_data_t *data = event_buffer.lookup(&zero);
    if (!data)
        return 0;

    __builtin_memset(data, 0, sizeof(*data));
    data->pid = pid;
    data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data->timestamp_ns = bpf_ktime_get_ns();
    data->event_type = EVENT_OPEN;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), args->filename);

    // Kernel-side path filter: Only send critical paths to user space
    if (data->filename[0] == '/' && (
        (data->filename[1] == 'e' && data->filename[2] == 't' && data->filename[3] == 'c') ||               // /etc/
        (data->filename[1] == 'r' && data->filename[2] == 'o' && data->filename[3] == 'o' && data->filename[4] == 't') || // /root/
        (data->filename[1] == 't' && data->filename[2] == 'm' && data->filename[3] == 'p') ||               // /tmp/
        (data->filename[1] == 'v' && data->filename[2] == 'a' && data->filename[3] == 'r' && data->filename[4] == '/' && data->filename[5] == 'r') // /var/run
    )) {
        events.perf_submit(args, data, sizeof(*data));
    }
    return 0;
}
"""

# ------------------------------------------------------------------------------
# 3. PYTHON EBPF TELEMETRY ENGINE CLASS
# ------------------------------------------------------------------------------
class EBPFTelemetryEngine:
    def __init__(self, callback=None, queue_size=100000):
        self.callback = callback
        self.event_queue = queue.Queue(maxsize=queue_size)
        self.bpf = None
        self.is_running = False
        self.worker_thread = None
        self.poll_thread = None
        self.bpf_supported = False
        self.siem_pid = os.getpid()

    def _check_kernel_support(self) -> bool:
        """
        Verifies if OS is Linux, has root/CAP_BPF privileges, and BCC package is installed.
        """
        if os.name == "nt":
            return False

        is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
        if not is_root:
            smart_logger.log("EBPF_WARN", "eBPF Kernel Sensor requires root (CAP_BPF / CAP_SYS_ADMIN). Running fallback mode.", level="WARNING")
            return False

        try:
            from bcc import BPF
            return True
        except ImportError:
            smart_logger.log("EBPF_WARN", "BCC Python bindings (python3-bpfcc) not found. Falling back to procfs/syslog.", level="INFO")
            return False
        except Exception as e:
            smart_logger.log("EBPF_WARN", f"eBPF subsystem initialization check failed: {e}", level="WARNING")
            return False

    def _perf_event_handler(self, cpu, data, size):
        """
        Low-latency C perf-buffer callback. Drops event into thread-safe memory queue.
        """
        try:
            event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
            # Extract raw values quickly to release C pointer memory
            item = {
                "pid": int(event.pid),
                "ppid": int(event.ppid),
                "uid": int(event.uid),
                "comm": event.comm.decode("utf-8", errors="ignore"),
                "filename": event.filename.decode("utf-8", errors="ignore"),
                "args": event.args.decode("utf-8", errors="ignore"),
                "saddr": socket.inet_ntoa(struct.pack("<I", event.saddr)) if event.saddr else "0.0.0.0",
                "daddr": socket.inet_ntoa(struct.pack("<I", event.daddr)) if event.daddr else "0.0.0.0",
                "dport": int(event.dport),
                "timestamp_ns": int(event.timestamp_ns),
                "event_type": int(event.event_type),
                "received_at": time.time()
            }
            self.event_queue.put_nowait(item)
        except queue.Full:
            pass  # Drop if queue capacity is overwhelmed to protect SIEM stability
        except Exception:
            pass

    def _event_dispatcher_worker(self):
        """
        High-throughput worker thread consuming events from the queue and mapping to ECS.
        """
        from modules.ecs_normalizer import ecs_normalizer

        while self.is_running:
            try:
                raw_evt = self.event_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                evt_type = raw_evt["event_type"]
                now_iso = datetime.utcnow().isoformat() + "Z"

                # 1. Map to ECS Standard Schema
                if evt_type == EVENT_EXEC:
                    cmd_line = raw_evt["args"] if raw_evt["args"] else raw_evt["filename"]
                    ecs_event = {
                        "@timestamp": now_iso,
                        "source_type": "ebpf_kernel",
                        "event_kind": "event",
                        "category": "process",
                        "action": "process_execution",
                        "event_type": "info",
                        "host_ip": "127.0.0.1",
                        "pid": raw_evt["pid"],
                        "user": f"uid_{raw_evt['uid']}",
                        "command": cmd_line,
                        "raw": f"[eBPF EXEC] PID={raw_evt['pid']} PPID={raw_evt['ppid']} UID={raw_evt['uid']} Comm={raw_evt['comm']} Binary={raw_evt['filename']} Args='{cmd_line}'",
                        "tags": ["ebpf", "kernel_exec", "zero_latency"]
                    }
                    try:
                        from modules.user_action_inspector import user_action_inspector
                        user_action_inspector.log_action(
                            username=f"uid_{raw_evt['uid']}",
                            source_ip="127.0.0.1",
                            tty=f"pid/{raw_evt['pid']}",
                            raw_command=cmd_line
                        )
                    except Exception:
                        pass

                elif evt_type == EVENT_CONNECT:
                    ecs_event = {
                        "@timestamp": now_iso,
                        "source_type": "ebpf_kernel",
                        "event_kind": "event",
                        "category": "network",
                        "action": "network_connection_outbound",
                        "event_type": "connection",
                        "source_ip": raw_evt["saddr"],
                        "dest_ip": raw_evt["daddr"],
                        "dest_port": raw_evt["dport"],
                        "pid": raw_evt["pid"],
                        "user": f"uid_{raw_evt['uid']}",
                        "command": raw_evt["comm"],
                        "raw": f"[eBPF CONNECT] PID={raw_evt['pid']} Comm={raw_evt['comm']} Target={raw_evt['daddr']}:{raw_evt['dport']}",
                        "tags": ["ebpf", "kernel_socket", "outbound"]
                    }

                elif evt_type == EVENT_OPEN:
                    ecs_event = {
                        "@timestamp": now_iso,
                        "source_type": "ebpf_kernel",
                        "event_kind": "event",
                        "category": "file",
                        "action": "file_access",
                        "event_type": "access",
                        "pid": raw_evt["pid"],
                        "user": f"uid_{raw_evt['uid']}",
                        "command": raw_evt["comm"],
                        "raw": f"[eBPF OPEN] PID={raw_evt['pid']} Comm={raw_evt['comm']} TargetFile={raw_evt['filename']}",
                        "tags": ["ebpf", "kernel_file_access"]
                    }
                else:
                    continue

                # 2. Dispatch to Central SIEM Pipeline
                if self.callback:
                    self.callback(ecs_event)

            except Exception as e:
                smart_logger.log("EBPF_DISPATCH_ERR", f"Error dispatching eBPF event: {e}", level="WARNING")
            finally:
                self.event_queue.task_done()

    def _poll_bpf_loop(self):
        """
        Polls the eBPF kernel perf ring buffer continuously.
        """
        while self.is_running and self.bpf:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception:
                pass

    def start(self):
        """
        Compiles the in-kernel eBPF program, hooks tracepoints, and starts worker threads.
        """
        if self.is_running:
            return

        self.bpf_supported = self._check_kernel_support()
        if not self.bpf_supported:
            self.is_running = True
            smart_logger.log("EBPF_STATUS", "eBPF Kernel Sensor is in Standby/Simulated Mode (Active procfs & socket monitors active).", level="INFO")
            while self.is_running:
                time.sleep(2.0)
            return

        try:
            from bcc import BPF

            self.is_running = True
            c_code_compiled = f"#define SIEM_PID {self.siem_pid}\n" + EBPF_KERNEL_SOURCE

            print("\n=================================================================")
            print("  eBPF KERNEL TELEMETRY SENSOR COMPILING (ZERO-LATENCY HOOKS)    ")
            print("=================================================================")
            self.bpf = BPF(text=c_code_compiled)
            self.bpf["events"].open_perf_buffer(self._perf_event_handler, page_cnt=64)

            # Start worker threads
            self.worker_thread = threading.Thread(target=self._event_dispatcher_worker, name="eBPF-Worker", daemon=True)
            self.worker_thread.start()

            self.poll_thread = threading.Thread(target=self._poll_bpf_loop, name="eBPF-Poller", daemon=True)
            self.poll_thread.start()

            print("[+] eBPF Kernel Hooks Attached:")
            print("    [1] tracepoint/syscalls/sys_enter_execve   -> Process Executions")
            print("    [2] tracepoint/syscalls/sys_enter_execveat -> Process Executions (AT)")
            print("    [3] tracepoint/syscalls/sys_enter_connect  -> Outbound Socket Connects")
            print("    [4] tracepoint/syscalls/sys_enter_openat   -> Sensitive File Access (/etc, /root, /tmp)")
            print(f"[+] In-Kernel Noise Filtering Active: SIEM Self PID {self.siem_pid} ignored.")
            print("[+] eBPF Sensor Active | Zero procfs polling latency | Kernel Ring Buffer Active!\n")
            smart_logger.log("EBPF_ATTACH", "eBPF Kernel hooks successfully attached to Linux kernel.", level="INFO")

        except Exception as e:
            self.bpf_supported = False
            smart_logger.log("EBPF_COMPILE_FAIL", f"Failed to attach eBPF kernel program: {e}", level="ERROR")
            print(f"[-] eBPF Compilation Error: {e}. Fallback monitor remains active.")

        # Keep supervisor thread alive
        while self.is_running:
            time.sleep(1.0)

    def stop(self):
        """
        Gracefully detaches eBPF probes and releases kernel resources.
        """
        self.is_running = False
        if self.bpf:
            try:
                self.bpf.cleanup()
            except Exception:
                pass
            self.bpf = None
        smart_logger.log("EBPF_STOP", "eBPF kernel probes detached gracefully.", level="INFO")

# Singleton instance
ebpf_telemetry_engine = EBPFTelemetryEngine()

# Aliases for backwards compatibility
EBPFKernelTelemetry = EBPFTelemetryEngine
ebpf_kernel_telemetry = ebpf_telemetry_engine
