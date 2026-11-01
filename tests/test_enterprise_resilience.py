# -*- coding: utf-8 -*-
"""
==============================================================================
ENTERPRISE RESILIENCE & PRODUCTION MACRO TEST SUITE
(tests/test_enterprise_resilience.py)
==============================================================================
Verifies the 6 enterprise-grade resilience upgrades:
1. Infrastructure Scanner / Monitoring Exemption (Zabbix, Nessus, Prometheus).
2. Corporate NAT / CGNAT Egress Protection & Session-Level Revocation.
3. Role-Aware Admin & DevOps Diagnostic Tooling Exemption.
4. Port 22 Decoy Graded Tolerance Buffer & Informative Banner.
5. Non-Interactive Daemons (Cron, Systemd, Backup) Maintenance Immunity.
6. Historical Log Backfill & Replay Alert Suppression.
==============================================================================
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from modules.ban_manager import BanManager
from detection.honeypot_trap import HoneypotTrap
from modules.maintenance_mode import MaintenanceModeManager
from ueba.user_session_tracker import UserSessionTracker
from modules.stateful_correlation import StatefulCorrelationEngine
from modules.smart_logger import SmartLogger

class TestEnterpriseResilience(unittest.TestCase):
    def setUp(self):
        self.db_name = "test_resilience.db"
        self.logger = SmartLogger(log_dir="test_resilience_logs", db_name=self.db_name)
        self.ban_mgr = BanManager(db_name=self.db_name)
        self.ban_mgr.unban_all()

    def tearDown(self):
        self.ban_mgr.unban_all()
        # Clean test directory and database
        for root, dirs, files in os.walk("test_resilience_logs"):
            for f in files:
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass
        if os.path.exists("test_resilience_logs"):
            try:
                os.rmdir("test_resilience_logs")
            except Exception:
                pass
        if os.path.exists(self.db_name):
            try:
                os.remove(self.db_name)
            except Exception:
                pass

    def test_01_infrastructure_scanner_whitelist(self):
        """Verify Zabbix / Nessus probes are whitelisted without honeypot bans."""
        scanner_ip = "192.168.1.50"
        honeypot = HoneypotTrap(ban_manager=self.ban_mgr, logger=self.logger)
        
        # Scanner probes decoy port
        honeypot._handle_honeypot_intercept(scanner_ip, 22)
        self.assertFalse(self.ban_mgr.is_banned(scanner_ip))

    def test_02_corporate_egress_session_isolation(self):
        """Verify Corporate NAT Gateway IP is never firewall-dropped; session isolated instead."""
        corp_ip = "198.51.100.1" # In TRUSTED_CORPORATE_EGRESS_IPS
        
        # Attempt critical ban on corporate egress
        self.ban_mgr.ban_ip(corp_ip, criticality="CRITICAL", reason="Intern typed wrong command")
        
        # Corporate egress IP must NOT be actively banned in firewall
        self.assertFalse(self.ban_mgr.is_banned(corp_ip))

    def test_03_role_aware_admin_diagnostics(self):
        """Verify Admin/DevOps running diagnostic tools (cat /etc/shadow, strings /proc) are not banned."""
        session_tracker = UserSessionTracker(ban_manager=self.ban_mgr, logger=self.logger)
        
        # 1. Admin running inspection -> Low severity ADMIN_INSPECTION
        cat, score, is_anom, summary, ai_det, urgency = session_tracker.analyze_command_context("admin", "sudo cat /etc/shadow")
        self.assertEqual(cat, "ADMIN_INSPECTION")
        self.assertEqual(score, 0)
        self.assertEqual(urgency, "LOW")

        # 2. Unauthorized intern running same command -> Classified as attack
        cat2, score2, is_anom2, summary2, ai_det2, urgency2 = session_tracker.analyze_command_context("intern", "cat /etc/shadow")
        self.assertNotEqual(cat2, "ADMIN_INSPECTION")

    def test_04_port_22_decoy_graded_tolerance(self):
        """Verify Port 22 decoy gives 2 tolerance grace connections before applying zero-tolerance ban."""
        dev_ip = "85.90.10.77"
        honeypot = HoneypotTrap(ban_manager=self.ban_mgr, logger=self.logger)
        
        # Attempt 1 -> Grace tolerance (No ban)
        honeypot._handle_honeypot_intercept(dev_ip, 22)
        self.assertFalse(self.ban_mgr.is_banned(dev_ip))

        # Attempt 2 -> Grace tolerance (No ban)
        honeypot._handle_honeypot_intercept(dev_ip, 22)
        self.assertFalse(self.ban_mgr.is_banned(dev_ip))

        # Attempt 3 -> Exceeded tolerance threshold -> Zero-tolerance 24h ban
        honeypot._handle_honeypot_intercept(dev_ip, 22)
        self.assertTrue(self.ban_mgr.is_banned(dev_ip))

    def test_05_cron_and_systemd_daemon_maintenance_immunity(self):
        """Verify non-interactive cron jobs and daemons are never blocked during maintenance."""
        maint = MaintenanceModeManager(state_file="data/test_maint_res.json")
        maint.enable_maintenance(reason="Database Upgrade", allowed_users=["lead_admin"])
        
        # System daemons are authorized
        self.assertTrue(maint.is_user_authorized("cron"))
        self.assertTrue(maint.is_user_authorized("systemd"))
        self.assertTrue(maint.is_user_authorized("backup"))
        self.assertTrue(maint.is_user_authorized("postgres"))

        # Non-interactive background execution (tty=None) is not intercepted
        is_blocked = maint.handle_maintenance_violation(
            username="unauthorized_user",
            source_ip="127.0.0.1",
            tty=None, # Background non-interactive
            command="/usr/bin/backup_db.sh"
        )
        self.assertFalse(is_blocked)

        maint.disable_maintenance()
        if os.path.exists("data/test_maint_res.json"):
            try:
                os.remove("data/test_maint_res.json")
            except Exception:
                pass

    def test_06_historical_log_backfill_suppression(self):
        """Verify logs older than 15 minutes do not trigger live real-time attack chain alerts."""
        cep = StatefulCorrelationEngine()
        
        # Replay event from 1 hour ago
        from datetime import datetime, timezone, timedelta
        old_iso = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        
        ecs_event = {
            "@timestamp": old_iso,
            "source": {"ip": "185.220.101.5"},
            "user": {"name": "target_user"},
            "event": {"action": "ssh_login_failed"}
        }
        
        alert = cep.correlate_event(ecs_event)
        self.assertIsNone(alert, "Historical backfilled log triggered live alert!")

if __name__ == "__main__":
    unittest.main()
