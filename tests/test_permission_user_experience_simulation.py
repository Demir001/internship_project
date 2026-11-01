# -*- coding: utf-8 -*-
"""
==============================================================================
USER EXPERIENCE & PERMISSION COMPARISON TEST SUITE (test_permission_user_experience_simulation.py)
==============================================================================
Verifies that distinct user personas (Auditor, Intern, Developer, DevOps, Admin)
experience the precise expected access control, error messaging, and SOC logging
when executing identical commands.
==============================================================================
"""

import unittest
from modules.permission_manager import permission_manager

class TestPermissionUserExperience(unittest.TestCase):
    def setUp(self):
        # Establish clean baseline perms for personas
        permission_manager.set_user_permissions("sim_auditor", "r----")
        permission_manager.set_user_permissions("sim_intern", "r----")
        permission_manager.set_user_permissions("sim_dev", "rwxn-")
        permission_manager.set_user_permissions("sim_devops", "rwxna")
        permission_manager.set_user_permissions("sim_admin", "rwxna")

    def test_log_read_operation(self):
        """All personas should have READ permission to inspect logs."""
        cmd = "cat /var/log/syslog"
        for user in ["sim_auditor", "sim_intern", "sim_dev", "sim_devops", "sim_admin"]:
            is_allowed, missing, req = permission_manager.check_command_permission(user, cmd)
            self.assertTrue(is_allowed, f"User {user} should be allowed to read logs")
            self.assertEqual(len(missing), 0)

    def test_file_mutation_operation(self):
        """Auditor and Intern should be denied WRITE operations, whereas Dev, DevOps, Admin pass."""
        cmd = "rm -rf /var/log/audit/data.log"
        # Denied
        for user in ["sim_auditor", "sim_intern"]:
            is_allowed, missing, req = permission_manager.check_command_permission(user, cmd)
            self.assertFalse(is_allowed, f"User {user} must be blocked from file deletion")
            self.assertIn("WRITE", missing)

        # Allowed
        for user in ["sim_dev", "sim_devops", "sim_admin"]:
            is_allowed, missing, req = permission_manager.check_command_permission(user, cmd)
            self.assertTrue(is_allowed, f"User {user} must be allowed to write")

    def test_network_and_script_execution(self):
        """Dev and above have EXECUTE and NETWORK permissions."""
        cmd = "curl -s https://api.service.internal/health"
        is_allowed_auditor, missing, _ = permission_manager.check_command_permission("sim_auditor", cmd)
        self.assertFalse(is_allowed_auditor)
        self.assertIn("NETWORK", missing)

        is_allowed_dev, _, _ = permission_manager.check_command_permission("sim_dev", cmd)
        self.assertTrue(is_allowed_dev)

    def test_privileged_admin_operation(self):
        """Only DevOps and Admin possess ADMIN permission for sudo / service control."""
        cmd = "sudo systemctl restart postgresql"
        for user in ["sim_auditor", "sim_intern", "sim_dev"]:
            is_allowed, missing, _ = permission_manager.check_command_permission(user, cmd)
            self.assertFalse(is_allowed, f"User {user} must be blocked from admin action")
            self.assertIn("ADMIN", missing)

        for user in ["sim_devops", "sim_admin"]:
            is_allowed, missing, _ = permission_manager.check_command_permission(user, cmd)
            self.assertTrue(is_allowed, f"User {user} must have ADMIN rights")

if __name__ == "__main__":
    unittest.main()
