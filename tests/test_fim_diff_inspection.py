# -*- coding: utf-8 -*-
"""
==============================================================================
FIM LINE-BY-LINE UNIFIED DIFF & TAMPER INSPECTOR TEST SUITE
(tests/test_fim_diff_inspection.py)
==============================================================================
Verifies the enhanced FIM diff engine:
1. Baseline line snapshot capture.
2. Detection of unauthorized injected backdoor lines and deleted config lines.
3. Line-by-line unified diff extraction (added_lines, removed_lines).
4. SIEM alert diff enrichment.
==============================================================================
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from detection.file_integrity_monitor import FileIntegrityMonitor
from modules.smart_logger import SmartLogger

class TestFIMDiffInspection(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_fim_target.conf"
        self.db_name = "test_fim_diff.db"
        self.logger = SmartLogger(log_dir="test_fim_diff_logs", db_name=self.db_name)

        # Initial baseline file
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("# Security Configuration\nPermitRootLogin no\nPasswordAuthentication yes\nLogLevel INFO\n")

        self.fim = FileIntegrityMonitor(logger=self.logger)
        self.fim.monitored_paths = [self.test_file]
        self.fim.init_baselines()

    def tearDown(self):
        if os.path.exists(self.test_file):
            try:
                os.remove(self.test_file)
            except Exception:
                pass
        for root, dirs, files in os.walk("test_fim_diff_logs"):
            for f in files:
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass
        if os.path.exists("test_fim_diff_logs"):
            try:
                os.rmdir("test_fim_diff_logs")
            except Exception:
                pass
        if os.path.exists(self.db_name):
            try:
                os.remove(self.db_name)
            except Exception:
                pass

    def test_01_line_by_line_diff_detection(self):
        """Verify unauthorized edits produce exact added/removed line diffs."""
        # Attacker injects root backdoor and mutates PermitRootLogin
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("# Security Configuration\nPermitRootLogin yes\nPasswordAuthentication yes\nLogLevel INFO\nbackdoor:x:0:0::/root:/bin/bash\n")

        alerts = []
        self.fim.callback = lambda evt, target, msg: alerts.append((evt, target, msg))
        self.fim.scan_integrity()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][0], "FILE_INTEGRITY_VIOLATION")
        
        # Verify diff generated
        diff_text = alerts[0][2]
        self.assertIn("backdoor:x:0:0::/root:/bin/bash", diff_text)
        self.assertIn("PermitRootLogin yes", diff_text)

    def test_02_direct_generate_diff_utility(self):
        """Verify generate_diff directly computes added and removed lines."""
        old_lines = ["Port 2222\n", "PermitRootLogin no\n"]
        new_lines = ["Port 1337\n", "PermitRootLogin yes\n", "backdoor_key\n"]
        
        res = self.fim.generate_diff(old_lines, new_lines, file_path="sshd_config")
        self.assertIn("Port 1337", res["added_lines"])
        self.assertIn("backdoor_key", res["added_lines"])
        self.assertIn("Port 2222", res["removed_lines"])
        self.assertGreaterEqual(res["total_mutations"], 3)

if __name__ == "__main__":
    unittest.main()
