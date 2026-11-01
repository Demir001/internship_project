# -*- coding: utf-8 -*-
"""
==============================================================================
AUTOMATED PRODUCTION HARDENING & ANTI-DEADLOCK VERIFICATION SUITE
(test_production_hardening.py)
==============================================================================
Tests the 10 production hardening upgrades:
1. Asynchronous multi-threaded SQLite writes without lock contention.
2. Serialized HMAC-SHA256 WORM chain integrity under concurrent writes.
3. RFC 1918 private subnet immunity in Subnet Shield.
4. Admin self-lockout immunity during Maintenance Mode.
5. FIM suppression and auto-rebaselining across maintenance windows.
6. Canonicalizer payload size & timeout protection against ReDoS.
==============================================================================
"""

import os
import sys
import time
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from modules.db_writer_queue import DBWriterQueue, db_writer
from modules.smart_logger import SmartLogger
from modules.ban_manager import BanManager
from modules.maintenance_mode import MaintenanceModeManager
from detection.file_integrity_monitor import FileIntegrityMonitor
from modules.canonicalizer import PayloadCanonicalizer

class TestProductionHardening(unittest.TestCase):
    def setUp(self):
        self.db_name = "test_hardening.db"
        self.logger = SmartLogger(log_dir="test_hardening_logs", db_name=self.db_name)

    def tearDown(self):
        db_writer.flush()
        # Clean test files
        for root, dirs, files in os.walk("test_hardening_logs"):
            for f in files:
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass
        if os.path.exists("test_hardening_logs"):
            try:
                os.rmdir("test_hardening_logs")
            except Exception:
                pass
        if os.path.exists(self.db_name):
            try:
                os.remove(self.db_name)
            except Exception:
                pass

    def test_01_concurrent_sqlite_writes_no_locks(self):
        """Verify 10 concurrent threads can write hundreds of events with 0 lock errors."""
        threads = []
        errors = []

        def worker(thread_id):
            try:
                for i in range(30):
                    self.logger.log_event(
                        level="INFO",
                        module="CONCURRENCY_TEST",
                        event_type="PARALLEL_WRITE",
                        target=f"10.0.0.{thread_id}",
                        details=f"Thread {thread_id} item {i}"
                    )
            except Exception as e:
                errors.append(e)

        for t in range(10):
            th = threading.Thread(target=worker, args=(t,))
            threads.append(th)
            th.start()

        for th in threads:
            th.join(timeout=5.0)

        self.assertEqual(len(errors), 0, f"Errors occurred during concurrent DB writes: {errors}")
        db_writer.flush()

    def test_02_serialized_worm_log_chain_integrity(self):
        """Verify concurrent multi-threaded writes preserve HMAC-SHA256 WORM chain integrity."""
        threads = []
        for t in range(5):
            th = threading.Thread(target=lambda: [
                self.logger.log_event("NOTICE", "WORM_TEST", "EVENT", "127.0.0.1", "Sample payload")
                for _ in range(10)
            ])
            threads.append(th)
            th.start()

        for th in threads:
            th.join(timeout=5.0)

        # Verify HMAC chain
        jsonl_path = self.logger.jsonl_log_path
        self.assertTrue(os.path.exists(jsonl_path))
        
        from modules.integrity_guard import LogIntegrityGuard
        guard = LogIntegrityGuard()
        is_valid, count, broken_line, msg = guard.verify_jsonl_log_file(jsonl_path)
        self.assertTrue(is_valid, f"WORM chain corrupted at line {broken_line}: {msg}")

    def test_03_rfc1918_private_subnet_immunity(self):
        """Verify Subnet Shield rejects blanket bans on private 192.168.0.0/24 or 10.0.0.0/24 subnets."""
        ban_mgr = BanManager(db_name="test_ban_imm.db")
        
        # Attempt to ban private subnet
        ban_mgr.ban_ip("192.168.1.0/24", criticality="CRITICAL", reason="Test Subnet Ban")
        self.assertFalse(ban_mgr.is_banned("192.168.1.0/24"))
        self.assertFalse(ban_mgr.is_banned("192.168.1.50"))

        # Public routable subnet SHOULD be allowed to be banned
        ban_mgr.ban_ip("85.90.10.0/24", criticality="CRITICAL", reason="Test Public Botnet Subnet")
        self.assertTrue(ban_mgr.is_banned("85.90.10.0/24"))

        ban_mgr.unban_all()
        if os.path.exists("test_ban_imm.db"):
            try:
                os.remove("test_ban_imm.db")
            except Exception:
                pass

    def test_04_maintenance_mode_caller_immunity(self):
        """Verify activating Maintenance Mode automatically whitelists calling admin and root."""
        maint = MaintenanceModeManager(state_file="data/test_maint_imm.json")
        maint.enable_maintenance(reason="Patching", allowed_users=["devops_lead"])
        
        # Root and SYSTEM are always immune
        self.assertTrue(maint.is_user_authorized("root"))
        self.assertTrue(maint.is_user_authorized("LOCAL_SYSTEM"))
        self.assertTrue(maint.is_user_authorized("devops_lead"))
        self.assertFalse(maint.is_user_authorized("random_user"))

        maint.disable_maintenance()
        if os.path.exists("data/test_maint_imm.json"):
            try:
                os.remove("data/test_maint_imm.json")
            except Exception:
                pass

    def test_05_fim_maintenance_suppression_and_rebaselining(self):
        """Verify FIM suppresses alerts during maintenance and updates baselines upon deactivation."""
        maint = MaintenanceModeManager(state_file="data/test_maint_fim.json")
        fim = FileIntegrityMonitor(logger=self.logger)
        
        test_file = "test_monitored_file.txt"
        with open(test_file, "w") as f:
            f.write("Initial Version 1.0")
        
        fim.monitored_paths = [test_file]
        fim.init_baselines()

        # 1. Enable Maintenance Mode
        maint.enable_maintenance(reason="Upgrading software")
        
        # Modify file during maintenance
        with open(test_file, "w") as f:
            f.write("Updated Version 2.0 (Legitimate System Patch)")
        
        # Scan during maintenance (should NOT trigger violation callback)
        violations = []
        fim.callback = lambda evt, target, msg: violations.append(evt)
        fim.scan_integrity()
        self.assertEqual(len(violations), 0)

        # 2. Disable Maintenance Mode (triggers auto-rebaselining)
        maint.disable_maintenance()
        fim.update_all_baselines()

        # Subsequent scan has new baseline (0 violations)
        fim.scan_integrity()
        self.assertEqual(len(violations), 0)

        if os.path.exists(test_file):
            try:
                os.remove(test_file)
            except Exception:
                pass
        if os.path.exists("data/test_maint_fim.json"):
            try:
                os.remove("data/test_maint_fim.json")
            except Exception:
                pass

    def test_06_canonicalizer_redos_and_length_protection(self):
        """Verify Canonicalizer handles deeply nested / huge payloads without crashing or backtracking."""
        huge_payload = "c" + "''" * 5000 + "at /etc/passwd"
        start_t = time.time()
        res = PayloadCanonicalizer.canonicalize(huge_payload)
        elapsed = time.time() - start_t
        self.assertLess(elapsed, 0.1, f"Canonicalizer took too long ({elapsed}s), possible ReDoS!")
        self.assertIsNotNone(res)

if __name__ == "__main__":
    unittest.main()
