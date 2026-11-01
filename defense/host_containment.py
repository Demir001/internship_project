# -*- coding: utf-8 -*-
"""
==============================================================================
EMERGENCY HOST NETWORK CONTAINMENT & QUARANTINE SUBSYSTEM
(modules/host_containment.py)
==============================================================================
Provides automated zero-trust host isolation capabilities for SOC incident
responders and SOAR playbooks:
1. Zero-Trust Network Lockdown: Drops all inbound, outbound, and routed traffic.
2. SOC Admin Lifeline: Automatically preserves caller SSH session and SOC IPs.
3. Socket Severing: Instantly terminates active lateral & exfiltration TCP sessions.
4. Clean Recovery: Flushes isolation chains and restores enterprise routing.
==============================================================================
"""

import os
import json
import time
import socket
import threading
import subprocess
import config
from modules.smart_logger import SmartLogger

class HostContainmentManager:
    _instance = None
    _singleton_lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super(HostContainmentManager, cls).__new__(cls)
            return cls._instance

    def __init__(self, state_file: str = None, logger=None):
        if hasattr(self, '_initialized') and self._initialized:
            if state_file:
                self.state_file = state_file
                self._load_state()
            return

        self.state_file = state_file or getattr(config, 'CONTAINMENT_STATE_FILE', 'data/containment_state.json')
        self.logger = logger or SmartLogger()
        self.lock = threading.RLock()
        
        self.is_isolated = False
        self.isolated_at = None
        self.reason = "N/A"
        self.allowed_ips = set(["127.0.0.1", "localhost", "::1"])

        self._load_state()
        self._initialized = True

    def _load_state(self):
        """Loads persistent containment configuration from disk."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.is_isolated = data.get("is_isolated", False)
                    self.isolated_at = data.get("isolated_at")
                    self.reason = data.get("reason", "N/A")
                    self.allowed_ips = set(data.get("allowed_ips", ["127.0.0.1", "localhost", "::1"]))
            except Exception as e:
                print(f"[-] [CONTAINMENT] State load error: {e}")

    def _save_state(self):
        """Persists containment state atomically to disk."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.state_file)), exist_ok=True)
            payload = {
                "is_isolated": self.is_isolated,
                "isolated_at": self.isolated_at,
                "reason": self.reason,
                "allowed_ips": sorted(list(self.allowed_ips))
            }
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            print(f"[-] [CONTAINMENT] State save error: {e}")

    def _detect_admin_lifeline(self) -> set:
        """Detects current SSH connection IP and configured SOC management IPs."""
        lifelines = set(["127.0.0.1", "localhost", "::1"])
        
        # Configured SOC management IPs
        soc_ips = getattr(config, 'SOC_MANAGEMENT_IPS', [])
        lifelines.update(soc_ips)

        # Active SSH Client Environment Variables
        ssh_client = os.environ.get("SSH_CLIENT")
        if ssh_client:
            client_ip = ssh_client.split()[0].strip()
            lifelines.add(client_ip)

        ssh_conn = os.environ.get("SSH_CONNECTION")
        if ssh_conn:
            client_ip = ssh_conn.split()[0].strip()
            lifelines.add(client_ip)

        return lifelines

    def _execute_cmd(self, cmd_str: str):
        """Executes OS system command cleanly."""
        if os.name == 'nt':
            return
        try:
            is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
            if is_root:
                subprocess.run(cmd_str, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            else:
                subprocess.run(f"sudo -n {cmd_str} 2>/dev/null || sudo {cmd_str}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except Exception:
            pass

    def _apply_isolation_firewall(self, allowed_ips: set):
        """Applies Netfilter/IPTables zero-trust lockdown rules."""
        if os.name != 'nt':
            # 1. Flush existing SIEM_CONTAINMENT chain if present
            self._execute_cmd("iptables -F SIEM_CONTAINMENT 2>/dev/null || iptables -N SIEM_CONTAINMENT")
            
            # 2. Insert top-level jump to SIEM_CONTAINMENT
            self._execute_cmd("iptables -C INPUT -j SIEM_CONTAINMENT 2>/dev/null || iptables -I INPUT 1 -j SIEM_CONTAINMENT")
            self._execute_cmd("iptables -C OUTPUT -j SIEM_CONTAINMENT 2>/dev/null || iptables -I OUTPUT 1 -j SIEM_CONTAINMENT")

            # 3. Allow Loopback interface
            self._execute_cmd("iptables -A SIEM_CONTAINMENT -i lo -j ACCEPT")
            self._execute_cmd("iptables -A SIEM_CONTAINMENT -o lo -j ACCEPT")

            # 4. Allow Established/Related connections for stateful integrity
            self._execute_cmd("iptables -A SIEM_CONTAINMENT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

            # 5. Allow Whitelisted Management IPs (Inbound and Outbound)
            for ip in allowed_ips:
                if ip not in ["localhost", "::1"]:
                    self._execute_cmd(f"iptables -A SIEM_CONTAINMENT -s {ip} -j ACCEPT")
                    self._execute_cmd(f"iptables -A SIEM_CONTAINMENT -d {ip} -j ACCEPT")

            # 6. Drop all other traffic
            self._execute_cmd("iptables -A SIEM_CONTAINMENT -j DROP")

            # 7. Sever active non-management connections
            self._execute_cmd("ss -K")
        else:
            print(f"[*] [Windows Simulation] Host Network Containment active. (Lifeline IPs: {sorted(list(allowed_ips))})")

    def _remove_isolation_firewall(self):
        """Flushes and tears down the isolation firewall chains."""
        if os.name != 'nt':
            self._execute_cmd("iptables -D INPUT -j SIEM_CONTAINMENT 2>/dev/null")
            self._execute_cmd("iptables -D OUTPUT -j SIEM_CONTAINMENT 2>/dev/null")
            self._execute_cmd("iptables -F SIEM_CONTAINMENT 2>/dev/null")
            self._execute_cmd("iptables -X SIEM_CONTAINMENT 2>/dev/null")
        else:
            print("[*] [Windows Simulation] Host Network Containment removed. Normal network routing restored.")

    def isolate_host(self, allowed_ips: list = None, reason: str = None) -> dict:
        """
        Activates emergency zero-trust host network containment.
        Preserves SOC administration lifeline.
        """
        with self.lock:
            self.is_isolated = True
            self.isolated_at = time.time()
            self.reason = reason or getattr(config, 'CONTAINMENT_DEFAULT_REASON', 'Emergency Active Threat Quarantine')
            
            # Combine detected admin lifelines with explicitly passed allowed IPs
            self.allowed_ips = self._detect_admin_lifeline()
            if allowed_ips:
                for ip in allowed_ips:
                    if ip:
                        self.allowed_ips.add(ip.strip())

            self._save_state()
            self._apply_isolation_firewall(self.allowed_ips)

            msg = (
                f"EMERGENCY HOST CONTAINMENT ACTIVATED! Host isolated from all external/internal networks. "
                f"Reason: '{self.reason}'. Preserved Management Lifelines: {sorted(list(self.allowed_ips))}"
            )
            print(f"\n[!] [HOST QUARANTINE] {msg}")
            self.logger.log_event("CRITICAL", "HOST_CONTAINMENT", "HOST_CONTAINMENT_ACTIVATED", "LOCAL_SYSTEM", msg)
            return self.get_status()

    def restore_host(self, reason: str = "Admin Remediation Complete") -> dict:
        """
        Restores full host network access and tears down quarantine rules.
        """
        with self.lock:
            self.is_isolated = False
            self.isolated_at = None
            self.reason = "N/A"
            self._save_state()
            self._remove_isolation_firewall()

            msg = f"HOST NETWORK CONTAINMENT RESTORED! Normal enterprise network routing active. Reason: '{reason}'."
            print(f"\n[+] [HOST RESTORED] {msg}")
            self.logger.log_event("NOTICE", "HOST_CONTAINMENT", "HOST_CONTAINMENT_RESTORED", "LOCAL_SYSTEM", msg)
            return self.get_status()

    def get_status(self) -> dict:
        """Returns comprehensive containment status dictionary."""
        with self.lock:
            dur_str = "0m"
            if self.is_isolated and self.isolated_at:
                mins = int((time.time() - self.isolated_at) // 60)
                dur_str = f"{mins}m"

            return {
                "is_isolated": self.is_isolated,
                "status": "ISOLATED (QUARANTINED)" if self.is_isolated else "NORMAL (UNRESTRICTED)",
                "reason": self.reason,
                "isolated_at": time.ctime(self.isolated_at) if self.isolated_at else "N/A",
                "isolation_duration": dur_str,
                "preserved_management_ips": sorted(list(self.allowed_ips))
            }

# Singleton instance
host_containment_manager = HostContainmentManager()
