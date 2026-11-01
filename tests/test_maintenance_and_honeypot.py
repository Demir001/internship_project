# -*- coding: utf-8 -*-
"""
==============================================================================
AUTOMATED TEST SUITE: MAINTENANCE DEFENSE, RBAC & PORT 22 HONEYPOT
(test_maintenance_and_honeypot.py)
==============================================================================
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from modules.maintenance_mode import MaintenanceModeManager
from modules.ban_manager import BanManager
from modules.smart_logger import SmartLogger
from detection.honeypot_trap import HoneypotTrap
from ueba.user_session_tracker import UserSessionTracker

class TestMaintenanceDefenseAndHoneypot(unittest.TestCase):
    def setUp(self):
        self.state_file = "data/test_maintenance_state.json"
        self.rbac_file = "data/test_rbac_roles.json"
        
        # Clean test state files
        for f in [self.state_file, self.rbac_file]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

        self.maint = MaintenanceModeManager(state_file=self.state_file, rbac_file=self.rbac_file)
        self.maint.disable_maintenance()
        self.ban_mgr = BanManager(db_name="test_security_events.db")
        self.logger = SmartLogger()

    def tearDown(self):
        self.maint.disable_maintenance()
        self.ban_mgr.unban_all()
        for f in [self.state_file, self.rbac_file, "test_security_events.db"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    def test_01_maintenance_mode_lifecycle(self):
        """Test enabling and disabling maintenance mode."""
        self.assertFalse(self.maint.is_maintenance_active())

        self.maint.enable_maintenance(reason="Kernel Upgrade", allowed_users=["devops", "lead_admin"])
        self.assertTrue(self.maint.is_maintenance_active())
        self.assertEqual(self.maint.reason, "Kernel Upgrade")
        self.assertTrue(self.maint.is_user_authorized("devops"))
        self.assertTrue(self.maint.is_user_authorized("lead_admin"))
        self.assertFalse(self.maint.is_user_authorized("unauthorized_intern"))

        self.maint.disable_maintenance()
        self.assertFalse(self.maint.is_maintenance_active())
        self.assertTrue(self.maint.is_user_authorized("unauthorized_intern"))

    def test_02_rbac_role_management(self):
        """Test RBAC role assignment and lookup."""
        self.maint.set_user_role("charlie", "AUDITOR")
        self.assertEqual(self.maint.get_user_role("charlie"), "AUDITOR")
        
        self.maint.set_user_role("alice", "ADMIN")
        self.assertEqual(self.maint.get_user_role("alice"), "ADMIN")

    def test_03_maintenance_violation_interception(self):
        """Test intercepting unauthorized commands during active maintenance."""
        self.maint.enable_maintenance(reason="Database Migration", allowed_users=["dba_lead"])
        
        events_emitted = []
        def callback(event_type, ip, msg):
            events_emitted.append((event_type, ip, msg))

        # Unauthorized user 'guest' attempts command
        violation = self.maint.handle_maintenance_violation(
            username="guest",
            source_ip="192.168.1.105",
            tty="pts/1",
            command="uptime",
            logger=self.logger,
            callback=callback
        )
        self.assertTrue(violation)
        self.assertEqual(len(events_emitted), 1)
        self.assertEqual(events_emitted[0][0], "MAINTENANCE_VIOLATION")

        # Authorized user 'dba_lead' attempts command
        allowed_violation = self.maint.handle_maintenance_violation(
            username="dba_lead",
            source_ip="192.168.1.100",
            tty="pts/0",
            command="uptime",
            logger=self.logger,
            callback=callback
        )
        self.assertFalse(allowed_violation)

    def test_04_port_22_ssh_decoy_honeypot_trap(self):
        """Test zero-tolerance 24-hour IP ban when scanner probes Port 22 decoy."""
        events = []
        def hp_callback(event, ip, msg):
            events.append((event, ip, msg))

        hp = HoneypotTrap(ban_manager=self.ban_mgr, callback=hp_callback, logger=self.logger)
        
        attacker_ip = "198.51.100.77"
        self.assertFalse(self.ban_mgr.is_banned(attacker_ip))

        # Attacker connects to decoy Port 22 repeatedly exceeding tolerance threshold (3 attempts)
        hp._handle_honeypot_intercept(attacker_ip, port=22) # attempt 1 (tolerated)
        hp._handle_honeypot_intercept(attacker_ip, port=22) # attempt 2 (tolerated)
        hp._handle_honeypot_intercept(attacker_ip, port=22) # attempt 3 (banned)

        self.assertTrue(self.ban_mgr.is_banned(attacker_ip))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "PORT_22_HONEYPOT_INTERCEPT")

if __name__ == "__main__":
    unittest.main()
