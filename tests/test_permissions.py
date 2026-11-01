# -*- coding: utf-8 -*-
"""
==============================================================================
AUTOMATED TEST SUITE: GRANULAR ROLE & PERMISSIONS (ALL COMBINATIONS)
(test_permissions.py)
==============================================================================
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from modules.permission_manager import (
    PermissionManager, PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_NETWORK, PERM_ADMIN, ALL_PERMISSIONS
)
from ueba.user_session_tracker import UserSessionTracker
from modules.ban_manager import BanManager

class TestGranularPermissions(unittest.TestCase):
    def setUp(self):
        self.test_file = "data/test_user_permissions.json"
        if os.path.exists(self.test_file):
            try:
                os.remove(self.test_file)
            except Exception:
                pass
        self.pm = PermissionManager(permissions_file=self.test_file)

    def tearDown(self):
        if os.path.exists(self.test_file):
            try:
                os.remove(self.test_file)
            except Exception:
                pass

    def test_01_permission_string_parsing_all_combinations(self):
        """Test parsing all single, combined, and synonym permission formats."""
        # 1. Single letter flags
        self.assertEqual(self.pm.parse_permissions_string("r"), {PERM_READ})
        self.assertEqual(self.pm.parse_permissions_string("w"), {PERM_WRITE})
        self.assertEqual(self.pm.parse_permissions_string("x"), {PERM_EXECUTE})
        self.assertEqual(self.pm.parse_permissions_string("n"), {PERM_NETWORK})
        self.assertEqual(self.pm.parse_permissions_string("a"), {PERM_ADMIN})

        # 2. Combinations
        self.assertEqual(self.pm.parse_permissions_string("rw"), {PERM_READ, PERM_WRITE})
        self.assertEqual(self.pm.parse_permissions_string("rx"), {PERM_READ, PERM_EXECUTE})
        self.assertEqual(self.pm.parse_permissions_string("rwx"), {PERM_READ, PERM_WRITE, PERM_EXECUTE})
        self.assertEqual(self.pm.parse_permissions_string("rwxn"), {PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_NETWORK})
        self.assertEqual(self.pm.parse_permissions_string("rwxna"), ALL_PERMISSIONS)

        # 3. Word keywords and lists
        self.assertEqual(self.pm.parse_permissions_string("read"), {PERM_READ})
        self.assertEqual(self.pm.parse_permissions_string("write"), {PERM_WRITE})
        self.assertEqual(self.pm.parse_permissions_string("read,write,network"), {PERM_READ, PERM_WRITE, PERM_NETWORK})
        self.assertEqual(self.pm.parse_permissions_string("all"), ALL_PERMISSIONS)
        self.assertEqual(self.pm.parse_permissions_string("none"), set())

    def test_02_command_classification(self):
        """Test classifying required permissions from command text."""
        # Read commands
        self.assertIn(PERM_READ, self.pm.classify_required_permissions("cat /var/log/syslog"))
        self.assertIn(PERM_READ, self.pm.classify_required_permissions("tail -n 20 /var/log/nginx/access.log"))
        self.assertIn(PERM_READ, self.pm.classify_required_permissions("ls -la /home/user"))

        # Write commands
        self.assertIn(PERM_WRITE, self.pm.classify_required_permissions("touch new_file.txt"))
        self.assertIn(PERM_WRITE, self.pm.classify_required_permissions("rm -rf /tmp/cache"))
        self.assertIn(PERM_WRITE, self.pm.classify_required_permissions("mkdir -p /var/www/test"))

        # Execute commands
        self.assertIn(PERM_EXECUTE, self.pm.classify_required_permissions("python3 app.py"))
        self.assertIn(PERM_EXECUTE, self.pm.classify_required_permissions("./start_server.sh"))
        self.assertIn(PERM_EXECUTE, self.pm.classify_required_permissions("node server.js"))

        # Network commands
        self.assertIn(PERM_NETWORK, self.pm.classify_required_permissions("curl https://api.endpoint.com"))
        self.assertIn(PERM_NETWORK, self.pm.classify_required_permissions("wget http://example.com/file.zip"))
        self.assertIn(PERM_NETWORK, self.pm.classify_required_permissions("ping 8.8.8.8"))

        # Admin commands
        self.assertIn(PERM_ADMIN, self.pm.classify_required_permissions("sudo systemctl restart nginx"))
        self.assertIn(PERM_ADMIN, self.pm.classify_required_permissions("sudo useradd -m newuser"))

    def test_03_granular_enforcement_matrices(self):
        """Test authorization enforcement across multiple users with different combinations."""
        # 1. Reader (r): Can read, cannot write, cannot network, cannot admin
        self.pm.set_user_permissions("reader_user", "r")
        allowed, missing, req = self.pm.check_command_permission("reader_user", "cat /etc/passwd")
        self.assertTrue(allowed)
        
        allowed, missing, req = self.pm.check_command_permission("reader_user", "rm /tmp/test.txt")
        self.assertFalse(allowed)
        self.assertIn(PERM_WRITE, missing)

        allowed, missing, req = self.pm.check_command_permission("reader_user", "curl https://example.com")
        self.assertFalse(allowed)
        self.assertIn(PERM_NETWORK, missing)

        # 2. Content Editor (rw): Can read and write, cannot execute scripts, cannot admin
        self.pm.set_user_permissions("editor_user", "rw")
        allowed, missing, req = self.pm.check_command_permission("editor_user", "nano document.txt")
        self.assertTrue(allowed)

        allowed, missing, req = self.pm.check_command_permission("editor_user", "python3 exploit.py")
        self.assertFalse(allowed)
        self.assertIn(PERM_EXECUTE, missing)

        # 3. Developer (rwxn): Can read, write, execute, network; cannot sudo/admin
        self.pm.set_user_permissions("dev_user", "rwxn")
        allowed, missing, req = self.pm.check_command_permission("dev_user", "git pull")
        self.assertTrue(allowed)

        allowed, missing, req = self.pm.check_command_permission("dev_user", "sudo iptables -F")
        self.assertFalse(allowed)
        self.assertIn(PERM_ADMIN, missing)

        # 4. Administrator (rwxna / all): Can do everything
        self.pm.set_user_permissions("admin_user", "all")
        allowed, missing, req = self.pm.check_command_permission("admin_user", "sudo systemctl restart nginx")
        self.assertTrue(allowed)

    def test_04_session_tracker_permission_interception(self):
        """Test that UserSessionTracker intercepts commands when permission is missing."""
        events = []
        def callback(evt, ip, msg):
            events.append((evt, ip, msg))

        ban_mgr = BanManager(db_name="test_perm_db.db")
        tracker = UserSessionTracker(ban_manager=ban_mgr, callback=callback)

        self.pm.set_user_permissions("restricted_intern", "r")
        tracker.start_session("restricted_intern", "192.168.1.55", "pts/3")

        # Attempt forbidden write command 'rm /tmp/data'
        tracker.record_command("restricted_intern", "192.168.1.55", "rm -rf /tmp/data", tty="pts/3")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "PERMISSION_DENIED")
        self.assertIn("lacks permission", events[0][2])

        # Attempt allowed read command 'cat /etc/hosts'
        tracker.record_command("restricted_intern", "192.168.1.55", "cat /etc/hosts", tty="pts/3")
        # No additional PERMISSION_DENIED event emitted
        self.assertEqual(len(events), 1)

        ban_mgr.unban_all()
        if os.path.exists("test_perm_db.db"):
            try:
                os.remove("test_perm_db.db")
            except Exception:
                pass

if __name__ == "__main__":
    unittest.main()
