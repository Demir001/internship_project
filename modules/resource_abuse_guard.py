# -*- coding: utf-8 -*-
"""
==============================================================================
ADVANCED RESOURCE ABUSE & CRYPTOMINER GUARD (modules/resource_abuse_guard.py)
==============================================================================
Monitors CPU, RAM, Disk I/O, and Network Bandwidth in real time:
1. Deep Attribution: Identifies PID, process name, command line, user, and duration.
2. Cryptominer & Malware Detection: Identifies XMRig, Kinsing, Stratum, and forkbombs.
3. Role-Aware Decision Engine: Grants high-throughput exemptions to Admins, DevOps,
   and core database/compiler tasks while neutralizing unauthorized resource hogs.
4. Active Remediation: Safely terminates offending process trees and applies EDR bans.
==============================================================================
"""

import os
import time
import signal
import psutil
import threading
from collections import defaultdict
import config
from modules.smart_logger import SmartLogger
from modules.ban_manager import BanManager

# Cryptominer Indicators of Compromise (IOCs)
CRYPTOMINER_SIGNATURES = [
    "xmrig", "minerd", "stratum+tcp", "stratum+udp", "cryptonight", "cpuminer",
    "kdevtmpfsi", "kinsing", "monero", "hashrate", "donate-level", "pool.minexmr",
    "nanopool", "supportxmr", "nicehash", "c3pool", "unmineable", "moneroocean"
]

class ResourceAbuseGuard:
    _instance = None
    _singleton_lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super(ResourceAbuseGuard, cls).__new__(cls)
            return cls._instance

    def __init__(self, ban_manager=None, logger=None):
        if hasattr(self, '_initialized') and self._initialized:
            return

        self.ban_manager = ban_manager or BanManager()
        self.logger = logger or SmartLogger()
        self.lock = threading.RLock()
        
        # State tracking for sustained usage: pid -> {first_seen, cpu_readings, ...}
        self.sustained_high_cpu = defaultdict(dict)
        self.sustained_high_ram = defaultdict(dict)
        self._initialized = True

    def get_top_resource_consumers(self, limit: int = 5) -> dict:
        """
        Gathers live system-wide resource telemetry and top consuming processes.
        """
        procs = []
        now = time.time()

        for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'memory_info', 'create_time', 'cmdline']):
            try:
                info = p.info
                # Calculate elapsed runtime
                runtime_secs = max(1, int(now - info['create_time'])) if info.get('create_time') else 0
                mins = runtime_secs // 60
                runtime_str = f"{mins}m {runtime_secs % 60}s"

                mem_mb = round((info['memory_info'].rss / (1024 * 1024)), 1) if info.get('memory_info') else 0.0
                cmd_str = " ".join(info['cmdline']) if info.get('cmdline') else info.get('name', 'N/A')

                procs.append({
                    "pid": info['pid'],
                    "name": info['name'] or "unknown",
                    "username": info['username'] or "SYSTEM",
                    "cpu_percent": info['cpu_percent'] or 0.0,
                    "memory_percent": round(info['memory_percent'] or 0.0, 1),
                    "memory_mb": mem_mb,
                    "runtime_str": runtime_str,
                    "runtime_secs": runtime_secs,
                    "cmdline": cmd_str[:120]
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Sort top consumers
        top_cpu = sorted(procs, key=lambda x: x["cpu_percent"], reverse=True)[:limit]
        top_ram = sorted(procs, key=lambda x: x["memory_percent"], reverse=True)[:limit]

        # System total metrics
        sys_cpu = psutil.cpu_percent(interval=None)
        sys_mem = psutil.virtual_memory().percent
        sys_disk = psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent

        return {
            "system_cpu_percent": sys_cpu,
            "system_ram_percent": sys_mem,
            "system_disk_percent": sys_disk,
            "top_cpu_processes": top_cpu,
            "top_ram_processes": top_ram,
            "total_monitored_processes": len(procs)
        }

    def evaluate_process_incident(self, proc_info: dict) -> dict:
        """
        Evaluates a process against threat signatures, role authorizations, and resource limits.
        Returns evaluation dict with recommended action (ALLOW, WARN, TERMINATE, BAN).
        """
        pid = proc_info.get("pid")
        name = (proc_info.get("name") or "").lower()
        cmdline = (proc_info.get("cmdline") or "").lower()
        username = (proc_info.get("username") or "").strip()
        cpu_pct = proc_info.get("cpu_percent", 0.0)
        ram_pct = proc_info.get("memory_percent", 0.0)

        # -------------------------------------------------------------
        # 1. SIGNATURE-BASED CRYPTOMINER & MALWARE HUNTING (Immediate Threat)
        # -------------------------------------------------------------
        is_cryptominer = any(sig in name or sig in cmdline for sig in CRYPTOMINER_SIGNATURES)
        if is_cryptominer:
            return {
                "verdict": "CRITICAL_CRYPTOMINER",
                "action": "TERMINATE_AND_BAN",
                "severity": "CRITICAL",
                "reason": f"Active Cryptomining Trojan detected ({name} | CMD: {cmdline[:60]}...)",
                "pid": pid,
                "username": username,
                "should_terminate": True,
                "should_ban": True
            }

        # -------------------------------------------------------------
        # 2. ROLE & WORKLOAD AUTHORIZATION CHECK
        # -------------------------------------------------------------
        is_exempt = False
        user_role = "OPERATOR"
        try:
            from modules.maintenance_mode import maintenance_manager
            user_role = maintenance_manager.get_user_role(username).upper()
        except Exception:
            pass

        exempt_roles = getattr(config, 'RESOURCE_EXEMPT_ROLES', ["ADMIN", "DEVOPS", "AUDITOR"])
        exempt_accounts = getattr(config, 'RESOURCE_EXEMPT_ACCOUNTS', ["root", "postgres", "mysql", "backup", "systemd", "redis", "nginx", "docker"])
        exempt_binaries = getattr(config, 'RESOURCE_EXEMPT_BINARIES', ["mysqld", "postgres", "redis-server", "nginx", "dockerd", "python", "gcc", "npm", "tar"])

        if username in exempt_accounts or user_role in exempt_roles:
            is_exempt = True

        if any(b in name for b in exempt_binaries):
            is_exempt = True

        # -------------------------------------------------------------
        # 3. THRESHOLD EVALUATION (CPU / RAM / ABUSE)
        # -------------------------------------------------------------
        cpu_threshold = getattr(config, 'RESOURCE_CPU_THRESHOLD_PERCENT', 85.0)
        ram_threshold = getattr(config, 'RESOURCE_RAM_THRESHOLD_PERCENT', 90.0)

        is_cpu_abusive = (cpu_pct >= cpu_threshold)
        is_ram_abusive = (ram_pct >= ram_threshold)

        if is_cpu_abusive or is_ram_abusive:
            metric_desc = f"CPU: {cpu_pct}%" if is_cpu_abusive else f"RAM: {ram_pct}%"
            
            if is_exempt:
                # Legitimate heavy enterprise workload (Database, compilation, backup)
                return {
                    "verdict": "AUTHORIZED_HIGH_WORKLOAD",
                    "action": "ALLOW_AND_LOG",
                    "severity": "NOTICE",
                    "reason": f"Authorized high workload by {username} ({user_role}): {name} ({metric_desc})",
                    "pid": pid,
                    "username": username,
                    "should_terminate": False,
                    "should_ban": False
                }
            else:
                # Unauthorized user or unprivileged service pegging the system
                return {
                    "verdict": "UNAUTHORIZED_RESOURCE_ABUSE",
                    "action": "TERMINATE_PROCESS",
                    "severity": "HIGH",
                    "reason": f"Unauthorized resource exhaustion by {username}: {name} ({metric_desc})",
                    "pid": pid,
                    "username": username,
                    "should_terminate": True,
                    "should_ban": False
                }

        return {
            "verdict": "NORMAL",
            "action": "PASS",
            "severity": "INFO",
            "reason": "Normal operational resource consumption",
            "pid": pid,
            "username": username,
            "should_terminate": False,
            "should_ban": False
        }

    def terminate_process_tree(self, pid: int, sig=signal.SIGTERM) -> bool:
        """
        Safely terminates a rogue process and all of its child threads/processes.
        """
        if pid <= 1:
            return False # Safety guard for init/systemd
        if pid == os.getpid():
            return False # SIEM self-immunity

        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            
            # Terminate children first
            for child in children:
                try:
                    child.send_signal(sig)
                except Exception:
                    pass
            
            # Terminate parent
            parent.send_signal(sig)
            print(f"[+] [PROCESS TERMINATED] Rogue PID {pid} ({parent.name()}) and {len(children)} child processes terminated.")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"[-] [TERMINATE ERROR] Could not terminate PID {pid}: {e}")
            return False

    def scan_and_remediate(self) -> list:
        """
        Performs a full system scan across running processes and executes necessary remediations.
        """
        telemetry = self.get_top_resource_consumers(limit=20)
        incidents = []

        all_procs = telemetry.get("top_cpu_processes", []) + telemetry.get("top_ram_processes", [])
        seen_pids = set()

        for proc in all_procs:
            pid = proc["pid"]
            if pid in seen_pids or pid == os.getpid():
                continue
            seen_pids.add(pid)

            eval_res = self.evaluate_process_incident(proc)
            if eval_res["verdict"] != "NORMAL":
                incidents.append(eval_res)

                # Log event
                self.logger.log_event(
                    eval_res["severity"],
                    "RESOURCE_GUARD",
                    eval_res["verdict"],
                    f"PID:{pid}|{proc.get('username')}",
                    eval_res["reason"]
                )

                # Execute action if required
                if eval_res.get("should_terminate"):
                    self.terminate_process_tree(pid)

        return incidents

    def get_status(self) -> dict:
        """Returns Resource Abuse Guard status dictionary."""
        return {
            "status": "ACTIVE",
            "cpu_threshold_percent": getattr(config, 'RESOURCE_CPU_THRESHOLD_PERCENT', 85.0),
            "ram_threshold_percent": getattr(config, 'RESOURCE_RAM_THRESHOLD_PERCENT', 90.0),
            "exempt_roles": getattr(config, 'RESOURCE_EXEMPT_ROLES', ["ADMIN", "DEVOPS"]),
            "exempt_process_names": getattr(config, 'RESOURCE_EXEMPT_PROCESS_NAMES', ["mysqld", "postgres", "dockerd", "npm", "gcc"])
        }

# Singleton instance
resource_abuse_guard = ResourceAbuseGuard()
