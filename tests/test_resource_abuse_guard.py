# -*- coding: utf-8 -*-
"""
==============================================================================
SYSTEM RESOURCE ABUSE & CRYPTOMINER GUARD TEST SUITE
(tests/test_resource_abuse_guard.py)
==============================================================================
Verifies the ResourceAbuseGuard subsystem:
1. System telemetry gathering & process attribution (PID, username, runtime).
2. Signature-based Cryptominer detection (XMRig, Kinsing, Stratum).
3. Role-aware high-workload authorization (DevOps / Admin compiling/DB indexing).
4. Unauthorized user resource exhaustion detection.
5. Safe process tree termination logic.
==============================================================================
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from modules.resource_abuse_guard import ResourceAbuseGuard
from modules.smart_logger import SmartLogger

class TestResourceAbuseGuard(unittest.TestCase):
    def setUp(self):
        self.db_name = "test_resource_guard.db"
        self.logger = SmartLogger(log_dir="test_resource_logs", db_name=self.db_name)
        self.guard = ResourceAbuseGuard(logger=self.logger)

    def tearDown(self):
        for root, dirs, files in os.walk("test_resource_logs"):
            for f in files:
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass
        if os.path.exists("test_resource_logs"):
            try:
                os.rmdir("test_resource_logs")
            except Exception:
                pass
        if os.path.exists(self.db_name):
            try:
                os.remove(self.db_name)
            except Exception:
                pass

    def test_01_telemetry_and_attribution(self):
        """Verify process attribution gathers PID, user, CPU%, RAM%, and runtime."""
        telemetry = self.guard.get_top_resource_consumers(limit=5)
        self.assertIn("system_cpu_percent", telemetry)
        self.assertIn("system_ram_percent", telemetry)
        self.assertIn("top_cpu_processes", telemetry)
        self.assertIn("top_ram_processes", telemetry)
        self.assertGreater(telemetry["total_monitored_processes"], 0)

        # Check process attribution fields
        if telemetry["top_cpu_processes"]:
            top = telemetry["top_cpu_processes"][0]
            self.assertIn("pid", top)
            self.assertIn("username", top)
            self.assertIn("cpu_percent", top)
            self.assertIn("runtime_str", top)

    def test_02_signature_cryptominer_detection(self):
        """Verify known cryptominer signatures (xmrig, stratum) are flagged for termination & ban."""
        miner_proc = {
            "pid": 9876,
            "name": "xmrig_miner",
            "username": "unprivileged_user",
            "cpu_percent": 99.0,
            "memory_percent": 12.0,
            "cmdline": "./xmrig -o stratum+tcp://pool.supportxmr.com:3333 -u 48xyz"
        }
        res = self.guard.evaluate_process_incident(miner_proc)
        self.assertEqual(res["verdict"], "CRITICAL_CRYPTOMINER")
        self.assertEqual(res["action"], "TERMINATE_AND_BAN")
        self.assertTrue(res["should_terminate"])
        self.assertTrue(res["should_ban"])

    def test_03_role_aware_admin_heavy_workload_exemption(self):
        """Verify authorized admin compiling code or running DB is allowed as NOTICE."""
        heavy_devops_proc = {
            "pid": 5432,
            "name": "mysqld",
            "username": "postgres",
            "cpu_percent": 92.0, # Exceeds 85% threshold
            "memory_percent": 60.0,
            "cmdline": "/usr/sbin/mysqld --daemonize"
        }
        res = self.guard.evaluate_process_incident(heavy_devops_proc)
        self.assertEqual(res["verdict"], "AUTHORIZED_HIGH_WORKLOAD")
        self.assertEqual(res["action"], "ALLOW_AND_LOG")
        self.assertEqual(res["severity"], "NOTICE")
        self.assertFalse(res["should_terminate"])

    def test_04_unauthorized_user_resource_exhaustion(self):
        """Verify unprivileged user running rogue CPU/RAM hog is flagged for termination."""
        rogue_user_proc = {
            "pid": 7777,
            "name": "infinite_loop",
            "username": "guest_intern",
            "cpu_percent": 95.0,
            "memory_percent": 20.0,
            "cmdline": "python3 -c 'while True: pass'"
        }
        res = self.guard.evaluate_process_incident(rogue_user_proc)
        self.assertEqual(res["verdict"], "UNAUTHORIZED_RESOURCE_ABUSE")
        self.assertEqual(res["action"], "TERMINATE_PROCESS")
        self.assertTrue(res["should_terminate"])

if __name__ == "__main__":
    unittest.main()
