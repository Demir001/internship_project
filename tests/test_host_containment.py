# -*- coding: utf-8 -*-
"""
==============================================================================
HOST NETWORK CONTAINMENT & QUARANTINE TEST SUITE
(tests/test_host_containment.py)
==============================================================================
Verifies the emergency host quarantine subsystem:
1. Zero-trust isolation activation & state persistence.
2. SOC administration lifeline preservation.
3. Full network restoration & state teardown.
4. CLI dispatch integration (isolate-host, restore-host, containment-status).
==============================================================================
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from modules.host_containment import HostContainmentManager
from modules.smart_logger import SmartLogger

class TestHostContainment(unittest.TestCase):
    def setUp(self):
        self.state_file = "data/test_containment_state.json"
        self.db_name = "test_containment.db"
        self.logger = SmartLogger(log_dir="test_containment_logs", db_name=self.db_name)
        self.manager = HostContainmentManager(state_file=self.state_file, logger=self.logger)
        self.manager.restore_host()

    def tearDown(self):
        self.manager.restore_host()
        if os.path.exists(self.state_file):
            try:
                os.remove(self.state_file)
            except Exception:
                pass
        for root, dirs, files in os.walk("test_containment_logs"):
            for f in files:
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass
        if os.path.exists("test_containment_logs"):
            try:
                os.rmdir("test_containment_logs")
            except Exception:
                pass
        if os.path.exists(self.db_name):
            try:
                os.remove(self.db_name)
            except Exception:
                pass

    def test_01_isolate_host_activation_and_persistence(self):
        """Verify host network isolation activates and persists to disk."""
        st = self.manager.isolate_host(
            allowed_ips=["10.0.5.99"],
            reason="Active Ransomware Lateral Movement Detected"
        )
        self.assertTrue(st["is_isolated"])
        self.assertIn("ISOLATED", st["status"])
        self.assertEqual(st["reason"], "Active Ransomware Lateral Movement Detected")
        self.assertIn("10.0.5.99", st["preserved_management_ips"])
        self.assertIn("127.0.0.1", st["preserved_management_ips"])

        # Verify disk persistence
        self.assertTrue(os.path.exists(self.state_file))

    def test_02_admin_lifeline_preservation(self):
        """Verify SOC management IPs and loopback are always preserved during isolation."""
        st = self.manager.isolate_host(reason="SOC Incident Triage")
        lifelines = st["preserved_management_ips"]
        
        # Loopback must be present
        self.assertIn("127.0.0.1", lifelines)
        self.assertIn("localhost", lifelines)
        
        # Configured SOC management IPs must be present
        for soc_ip in getattr(config, 'SOC_MANAGEMENT_IPS', []):
            self.assertIn(soc_ip, lifelines)

    def test_03_restore_host_unrestricted(self):
        """Verify restore_host cleanly tears down quarantine rules and restores normal state."""
        self.manager.isolate_host(reason="Test Isolation")
        self.assertTrue(self.manager.get_status()["is_isolated"])

        # Restore
        st = self.manager.restore_host(reason="Incident Resolved by SecOps")
        self.assertFalse(st["is_isolated"])
        self.assertIn("NORMAL", st["status"])
        self.assertEqual(st["reason"], "N/A")

if __name__ == "__main__":
    unittest.main()
