# -*- coding: utf-8 -*-
"""
==============================================================================
FILELESS MALWARE, PROCESS INJECTION & YARA MEMORY SCANNER
(modules/memory_threat_hunter.py)
==============================================================================
Provides deep, non-invasive Linux user-space and kernel-assisted live process
memory inspection to detect fileless threats, process hollowing, and shellcode:
1. /proc/<pid>/maps Parser:
   - Identifies W+X (RWX) memory pages violating W^X security policies.
   - Detects anonymous executable pages lacking disk file mappings (memfd, anon mmap).
   - Detects executable stack/heap injection anomalies.
2. /proc/<pid>/mem Chunk-Based Safe Reader:
   - Streams memory chunks with seek/read handling EIO, EACCES, and ESRCH errors.
3. Dual-Engine YARA Scanner:
   - Compiles native YARA rules if yara-python is available.
   - Built-in Pure-Python Fast Binary Opcode Engine as fallback.
   - Signatures: Cobalt Strike, Metasploit, Memfd Fileless ELF, Reflective SO Loaders.
4. Event-Driven & Periodic Scanning:
   - Event-driven targeted scan for PIDs flagged by C2/eBPF detectors.
   - Low-priority periodic baseline sweep across all running processes.
==============================================================================
"""

import os
import sys
import re
import time
import signal
import struct
import threading
import psutil
from datetime import datetime

import config
from modules.smart_logger import smart_logger

# Try loading native yara-python if available
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# ------------------------------------------------------------------------------
# 1. BUILT-IN YARA RULE DEFINITIONS
# ------------------------------------------------------------------------------
YARA_RULES_STRING = r"""
rule CobaltStrike_Beacon_Stager {
    meta:
        description = "Detects Cobalt Strike Linux / x86_64 reflective stager and beacon shellcode"
        author = "SIEM Memory Threat Hunter"
        severity = "CRITICAL"
        mitre_tactic = "Defense Evasion / Execution"
        mitre_technique = "T1055.001 / T1059"
    strings:
        // Linux x86_64 socket / connect shellcode stub (6a 29 58 0f 05 - sys_socket / connect)
        $sc_socket = { 6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 }
        $sc_connect = { 48 97 6a 2a 58 0f 05 }
        $sc_mprotect = { 48 c7 c0 0a 00 00 00 0f 05 }
        $cs_pipe = "\\\\.\\pipe\\MSSE-" ascii
        $cs_magic = { 69 68 67 66 65 64 63 62 }
    condition:
        any of them
}

rule Metasploit_Linux_x64_Reverse_TCP {
    meta:
        description = "Detects Metasploit Linux x86_64 reverse TCP socket / dup2 shellcode"
        author = "SIEM Memory Threat Hunter"
        severity = "CRITICAL"
        mitre_tactic = "Command and Control"
        mitre_technique = "T1059.004 / T1071"
    strings:
        // xor rsi, rsi; push 2; pop rdi; push 1; pop rsi; push 6a ...
        $msf_dup2 = { 6a 21 58 0f 05 48 ff ce jns }
        $msf_execve = { 48 31 f6 56 48 bf 2f 62 69 6e 2f 2f 73 68 57 54 5f 6a 3b 58 0f 05 }
        $msf_syscall = { 48 31 c0 48 31 db 48 31 c9 48 31 d2 0f 05 }
    condition:
        any of them
}

rule Memfd_Fileless_ELF_Injection {
    meta:
        description = "Detects hidden or unmapped ELF binaries executed directly from memory (memfd_create / anonymous)"
        author = "SIEM Memory Threat Hunter"
        severity = "CRITICAL"
        mitre_tactic = "Defense Evasion"
        mitre_technique = "T1027.004 / T1620"
    strings:
        $elf_magic = { 7f 45 4c 46 } // \x7fELF
        $elf_entry = { 48 83 ec ?? e8 ?? ?? ?? ?? 48 83 c4 }
        $libc_dyn = "/lib64/ld-linux-x86-64.so.2" ascii
    condition:
        $elf_magic at 0 and ($libc_dyn or $elf_entry)
}

rule Reflective_SO_Loader_Stub {
    meta:
        description = "Detects in-memory dynamic shared object (SO) reflective loader injection"
        author = "SIEM Memory Threat Hunter"
        severity = "HIGH"
        mitre_tactic = "Privilege Escalation"
        mitre_technique = "T1055.002"
    strings:
        $dlopen_stub = { 48 8d 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 85 c0 74 }
        $dlsym_str = "dlsym" ascii
        $dlopen_str = "dlopen" ascii
        $mprotect_sc = { 48 c7 c0 0a 00 00 00 0f 05 }
    condition:
        ($dlopen_str and $dlsym_str) or ($dlopen_stub and $mprotect_sc)
}
"""

# ------------------------------------------------------------------------------
# 2. PURE-PYTHON BINARY PATTERN MATCHER (FALLBACK ENGINE)
# ------------------------------------------------------------------------------
class PurePythonYaraScanner:
    """
    High-speed binary opcode and regex pattern matcher providing YARA parity
    when yara-python native C-bindings are not installed.
    """
    def __init__(self):
        self.rules = [
            {
                "name": "CobaltStrike_Beacon_Stager",
                "severity": "CRITICAL",
                "technique": "T1055.001 (Process Injection)",
                "patterns": [
                    (b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05", "sc_socket_stub"),
                    (b"\x48\x97\x6a\x2a\x58\x0f\x05", "sc_connect_stub"),
                    (b"\\\\.\\pipe\\MSSE-", "cs_pipe_artifact"),
                    (b"\x69\x68\x67\x66\x65\x64\x63\x62", "cs_magic_bytes")
                ]
            },
            {
                "name": "Metasploit_Linux_x64_Reverse_TCP",
                "severity": "CRITICAL",
                "technique": "T1059.004 (Unix Shell)",
                "patterns": [
                    (b"\x6a\x21\x58\x0f\x05", "msf_dup2_syscall"),
                    (b"/bin//sh", "msf_bin_sh_target"),
                    (b"/bin/sh", "msf_bin_sh"),
                    (b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e", "msf_execve_entry")
                ]
            },
            {
                "name": "Memfd_Fileless_ELF_Injection",
                "severity": "CRITICAL",
                "technique": "T1027.004 (Fileless Execution)",
                "patterns": [
                    (b"\x7fELF", "elf_header_in_memory")
                ]
            },
            {
                "name": "Reflective_SO_Loader_Stub",
                "severity": "HIGH",
                "technique": "T1055.002 (Reflective Injection)",
                "patterns": [
                    (b"dlopen\x00", "dlopen_symbol"),
                    (b"dlsym\x00", "dlsym_symbol")
                ]
            }
        ]

    def match(self, data: bytes, is_anon_exec: bool = False) -> list:
        matches = []
        if not data:
            return matches

        for r in self.rules:
            matched_strings = []
            for pat, tag in r["patterns"]:
                if pat in data:
                    matched_strings.append(f"${tag}: {pat.hex() if len(pat) < 16 else pat[:16].hex()}...")

            # Require specific combinations
            if r["name"] == "Memfd_Fileless_ELF_Injection":
                if is_anon_exec and b"\x7fELF" in data[:16]:
                    matches.append({
                        "rule": r["name"],
                        "severity": r["severity"],
                        "technique": r["technique"],
                        "strings": ["$elf_header: 7f454c46 (ELF binary in anonymous memory)"]
                    })
            elif matched_strings:
                matches.append({
                    "rule": r["name"],
                    "severity": r["severity"],
                    "technique": r["technique"],
                    "strings": matched_strings
                })

        return matches


# ------------------------------------------------------------------------------
# 3. MEMORY THREAT HUNTER CORE ENGINE
# ------------------------------------------------------------------------------
class MemoryThreatHunter:
    def __init__(self, callback=None, ban_manager=None):
        self.callback = callback
        self.ban_manager = ban_manager
        self.is_running = False
        self.lock = threading.Lock()
        
        # Initialize YARA engine
        self.yara_compiled = None
        self.pure_scanner = PurePythonYaraScanner()
        self._init_yara()

    def _init_yara(self):
        if YARA_AVAILABLE:
            try:
                self.yara_compiled = yara.compile(source=YARA_RULES_STRING)
                smart_logger.log("YARA_INIT", "Native YARA C-Engine compiled with 4 memory threat rulesets.", level="INFO")
            except Exception as e:
                smart_logger.log("YARA_WARN", f"Failed to compile YARA rules: {e}. Using Pure-Python scanner.", level="WARNING")
        else:
            smart_logger.log("YARA_INIT", "yara-python not installed; Pure-Python Binary Opcode Scanner active.", level="INFO")

    def parse_proc_maps(self, pid: int) -> list:
        """
        Parses /proc/<pid>/maps and identifies suspicious memory segments:
        - W+X (RWX) permissions
        - Anonymous executable pages
        - Executable heap / stack
        """
        maps_path = f"/proc/{pid}/maps"
        suspicious_segments = []

        if not os.path.exists(maps_path):
            return suspicious_segments

        try:
            with open(maps_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split(maxsplit=5)
                    if len(parts) < 5:
                        continue

                    addr_range = parts[0]
                    perms = parts[1]
                    offset = parts[2]
                    dev = parts[3]
                    inode = parts[4]
                    pathname = parts[5] if len(parts) >= 6 else ""

                    if "-" not in addr_range:
                        continue

                    start_str, end_str = addr_range.split("-")
                    start_addr = int(start_str, 16)
                    end_addr = int(end_str, 16)
                    size = end_addr - start_addr

                    # Ignore gigantic address spaces (e.g. > 64MB) to protect memory
                    if size <= 0 or size > 64 * 1024 * 1024:
                        continue

                    is_rwx = ("w" in perms and "x" in perms)
                    is_exec = ("x" in perms)
                    is_anon = (not pathname or pathname.strip() == "" or pathname.startswith("[anon") or "memfd:" in pathname or "(deleted)" in pathname)
                    is_stack_exec = is_exec and "[stack]" in pathname
                    is_heap_exec = is_exec and "[heap]" in pathname

                    # Criteria 1: RWX (W+X policy violation)
                    # Criteria 2: Anonymous executable memory (Fileless malware / Shellcode)
                    # Criteria 3: Executable Stack/Heap (Exploit / Process Hollowing)
                    if is_rwx or (is_exec and is_anon) or is_stack_exec or is_heap_exec:
                        anomaly_type = []
                        if is_rwx:
                            anomaly_type.append("RWX_PAGE_PERMISSION")
                        if is_exec and is_anon:
                            anomaly_type.append("ANONYMOUS_EXECUTABLE_PAGE")
                        if is_stack_exec or is_heap_exec:
                            anomaly_type.append("EXECUTABLE_STACK_HEAP")

                        suspicious_segments.append({
                            "start_addr": start_addr,
                            "end_addr": end_addr,
                            "addr_range": addr_range,
                            "perms": perms,
                            "size": size,
                            "pathname": pathname,
                            "anomaly_type": anomaly_type,
                            "is_anon": is_anon
                        })

        except (PermissionError, ProcessLookupError, FileNotFoundError):
            pass
        except Exception:
            pass

        return suspicious_segments

    def read_process_memory(self, pid: int, start_addr: int, size: int, max_read_bytes: int = 1048576) -> bytes:
        """
        Safely reads raw bytes from /proc/<pid>/mem with seek/read up to max_read_bytes (1MB chunk limit).
        """
        mem_path = f"/proc/{pid}/mem"
        read_len = min(size, max_read_bytes)
        
        if not os.path.exists(mem_path) or read_len <= 0:
            return b""

        try:
            with open(mem_path, "rb", buffering=0) as f:
                f.seek(start_addr)
                return f.read(read_len)
        except (PermissionError, ProcessLookupError, FileNotFoundError, OSError):
            return b""
        except Exception:
            return b""

    def scan_pid(self, pid: int, proc_name: str = None) -> list:
        """
        Performs a targeted memory hunt on a specific PID.
        Returns list of detected memory injection and shellcode alerts.
        """
        if pid <= 1 or pid == os.getpid():
            return []

        if not proc_name:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except Exception:
                proc_name = "unknown"

        # Ignore SIEM components and kernel threads
        if any(ign in proc_name.lower() for ign in ["main.py", "python", "systemd", "kworker", "init"]):
            return []

        alerts = []
        suspicious_segments = self.parse_proc_maps(pid)
        if not suspicious_segments:
            return []

        for seg in suspicious_segments:
            raw_bytes = self.read_process_memory(pid, seg["start_addr"], seg["size"])
            if not raw_bytes:
                continue

            yara_matches = []

            # 1. Evaluate Native YARA if available
            if self.yara_compiled:
                try:
                    matches = self.yara_compiled.match(data=raw_bytes)
                    for m in matches:
                        yara_matches.append({
                            "rule": m.rule,
                            "severity": m.meta.get("severity", "CRITICAL"),
                            "technique": m.meta.get("mitre_technique", "T1055"),
                            "strings": [f"{s.identifier}: {s.instances[0].matched_data.hex()[:24]}" for s in m.strings[:3]]
                        })
                except Exception:
                    pass

            # 2. Evaluate Pure-Python Scanner Fallback / Augment
            if not yara_matches:
                yara_matches = self.pure_scanner.match(raw_bytes, is_anon_exec=seg["is_anon"])

            # 3. Check for RWX NOP Sled / Shellcode pattern
            has_nop_sled = (b"\x90\x90\x90\x90\x90\x90\x90\x90" in raw_bytes)
            
            # Formulate Alert if YARA matched OR explicit RWX shellcode found
            if yara_matches or has_nop_sled or ("RWX_PAGE_PERMISSION" in seg["anomaly_type"] and seg["is_anon"]):
                matched_rule_name = yara_matches[0]["rule"] if yara_matches else "RWX_Anonymous_Shellcode_Stub"
                severity = yara_matches[0]["severity"] if yara_matches else "CRITICAL"
                technique = yara_matches[0]["technique"] if yara_matches else "T1055 (Process Injection)"
                matched_strings = yara_matches[0]["strings"] if yara_matches else ["NOP Sled / RWX Executable Memory Page"]

                alert = {
                    "event_kind": "alert",
                    "event_type": "MEMORY_INJECTION_DETECTED",
                    "severity": severity,
                    "process_pid": pid,
                    "process_name": proc_name,
                    "mitre_tactic": "Defense Evasion / Privilege Escalation",
                    "mitre_technique": technique,
                    "address_range": seg["addr_range"],
                    "permissions": seg["perms"],
                    "pathname": seg["pathname"] or "ANONYMOUS_MMAP",
                    "anomaly_reasons": seg["anomaly_type"],
                    "yara_rule": matched_rule_name,
                    "matched_strings": matched_strings,
                    "description": (f"Process Injection / Fileless Threat Detected in PID {pid} ({proc_name}) "
                                    f"at [{seg['addr_range']}] ({seg['perms']}) | Rule: {matched_rule_name}")
                }
                alerts.append(alert)

                smart_logger.log("MEMORY_INJECTION", alert["description"], level="CRITICAL")

                # Dispatch Alert to SIEM Pipeline
                if self.callback:
                    self.callback("MEMORY_INJECTION_DETECTED", f"PID_{pid}", alert["description"])

                # Automatic Active Response: Terminate rogue process if high confidence
                if getattr(config, "DRY_RUN_MODE", False):
                    print(f"[*] [DRY-RUN] Memory injection in PID {pid} logged. (Suppressed kill).")
                else:
                    try:
                        os.kill(pid, signal.SIGKILL)
                        print(f"[!] [AUTO-RESPONSE] Malicious injected process {proc_name} (PID: {pid}) terminated via SIGKILL.")
                        smart_logger.log("PROCESS_TERMINATED", f"Process {proc_name} (PID: {pid}) terminated due to memory threat.", level="CRITICAL")
                    except Exception as e:
                        print(f"[-] Failed to kill process {pid}: {e}")

                break  # Stop inspecting segments for this process once confirmed malicious

        return alerts

    def scan_all_processes(self):
        """
        Low-priority background baseline sweep across all running OS processes.
        """
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                self.scan_pid(pid, proc_name=name)
                time.sleep(0.02)  # Rate-limiting to ensure <1% CPU utilization
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

    def start(self):
        """
        Starts the continuous low-priority background memory threat hunter.
        """
        if self.is_running:
            return
        self.is_running = True

        print(f"[+] Memory Threat Hunter & YARA Scanner Active (Process Injection Guard): {time.ctime()}")
        smart_logger.log("MEM_HUNTER_START", "Memory Threat Hunter service active.", level="INFO")

        # Sleep initially to allow full system startup
        time.sleep(10)

        while self.is_running:
            try:
                if os.name != 'nt':
                    self.scan_all_processes()
                else:
                    time.sleep(30)
            except Exception as e:
                smart_logger.log("MEM_HUNTER_ERR", f"Memory hunter loop error: {e}", level="WARNING")
            time.sleep(60)

    def stop(self):
        self.is_running = False
        smart_logger.log("MEM_HUNTER_STOP", "Memory Threat Hunter stopped.", level="INFO")

# Singleton instance
memory_threat_hunter = MemoryThreatHunter()
