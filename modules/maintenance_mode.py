# -*- coding: utf-8 -*-
"""
==============================================================================
ENTERPRISE MAINTENANCE DEFENSE & RBAC AUTHORIZATION MANAGER
(maintenance_mode.py)
==============================================================================
Provides:
1. Dynamic Maintenance Mode defense (blocks unapproved users/actions during upgrades).
2. Role-Based Access Control (RBAC) user permission tracking.
3. Terminal session intercept and audit logging for maintenance violations.
==============================================================================
"""

import os
import sys
import time
import json
import threading
import subprocess
import config

class MaintenanceModeManager:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MaintenanceModeManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, state_file=None, rbac_file=None):
        if self._initialized:
            return

        self.state_file = state_file or getattr(config, 'MAINTENANCE_STATE_FILE', 'data/maintenance_state.json')
        self.rbac_file = rbac_file or getattr(config, 'RBAC_DATABASE_FILE', 'data/rbac_roles.json')
        self.lock = threading.RLock()

        self.is_enabled = getattr(config, 'ENABLE_MAINTENANCE_MODE', False)
        self.reason = getattr(config, 'MAINTENANCE_REASON', 'Routine Maintenance & Security Updates')
        self.start_time = None
        self.allowed_users = set(getattr(config, 'MAINTENANCE_ALLOWED_USERS', ["root", "admin", "devops"]))
        self.allowed_roles = set(getattr(config, 'MAINTENANCE_ALLOWED_ROLES', ["ADMIN", "DEVOPS"]))
        self.user_roles = dict(getattr(config, 'DEFAULT_USER_ROLES', {
            "root": "ADMIN",
            "admin": "ADMIN",
            "devops": "DEVOPS",
            "user": "OPERATOR",
            "auditor": "AUDITOR"
        }))

        self._load_state()
        self._load_rbac()
        self._initialized = True

    # --------------------------------------------------------------------------
    # STATE & RBAC PERSISTENCE
    # --------------------------------------------------------------------------

    def _load_state(self):
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.is_enabled = data.get("is_enabled", self.is_enabled)
                    self.reason = data.get("reason", self.reason)
                    self.start_time = data.get("start_time", None)
                    if "allowed_users" in data:
                        self.allowed_users = set(data["allowed_users"])
                    if "allowed_roles" in data:
                        self.allowed_roles = set(data["allowed_roles"])
        except Exception as e:
            print(f"[-] Maintenance State Load Warning: {e}")

    def _save_state(self):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.state_file)), exist_ok=True)
            state_data = {
                "is_enabled": self.is_enabled,
                "reason": self.reason,
                "start_time": self.start_time,
                "allowed_users": sorted(list(self.allowed_users)),
                "allowed_roles": sorted(list(self.allowed_roles)),
                "updated_at": time.ctime()
            }
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(state_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[-] Maintenance State Save Error: {e}")

    def _load_rbac(self):
        try:
            if os.path.exists(self.rbac_file):
                with open(self.rbac_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.user_roles.update(data)
        except Exception as e:
            print(f"[-] RBAC Roles Load Warning: {e}")

    def _save_rbac(self):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.rbac_file)), exist_ok=True)
            with open(self.rbac_file, 'w', encoding='utf-8') as f:
                json.dump(self.user_roles, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[-] RBAC Roles Save Error: {e}")

    # --------------------------------------------------------------------------
    # MAINTENANCE CONTROLS
    # --------------------------------------------------------------------------

    def is_maintenance_active(self) -> bool:
        """Returns True if maintenance defense is actively enforcing restrictions."""
        with self.lock:
            return self.is_enabled

    def is_user_authorized(self, username: str) -> bool:
        """
        Evaluates whether a given username is permitted to execute operations
        during active maintenance mode.
        """
        if not self.is_maintenance_active():
            return True

        if not username:
            return False

        clean_user = username.strip()

        with self.lock:
            # 0. Permanent Superuser & System Daemon Immunity (Cron, Backup, Systemd)
            daemons = getattr(config, 'SYSTEM_DAEMON_ACCOUNTS', ["cron", "systemd", "backup", "postgres", "mysql", "www-data", "nobody", "daemon"])
            if clean_user in ["root", "SYSTEM", "LOCAL_SYSTEM", "system"] or clean_user in daemons:
                return True

            # 1. Direct username whitelist check
            if clean_user in self.allowed_users:
                return True

            # 2. RBAC role-based authorization check
            user_role = self.user_roles.get(clean_user, "RESTRICTED").upper()
            if user_role in self.allowed_roles:
                return True

            return False

    def enable_maintenance(self, reason: str = None, allowed_users: list = None, allowed_roles: list = None):
        """Activates maintenance mode and persists settings with self-lockout immunity."""
        import getpass
        with self.lock:
            self.is_enabled = True
            self.start_time = time.time()
            if reason:
                self.reason = reason

            # Multi-Identity Binding: Automatically guarantee caller immunity
            caller_candidates = {"root", "admin", "devops"}
            try:
                current_os_user = getpass.getuser()
                if current_os_user:
                    caller_candidates.add(current_os_user)
            except Exception:
                pass

            for env_key in ["USER", "SUDO_USER", "LOGNAME"]:
                env_u = os.environ.get(env_key)
                if env_u:
                    caller_candidates.add(env_u.strip())

            self.allowed_users.update(caller_candidates)

            if allowed_users:
                self.allowed_users.update(allowed_users)
            if allowed_roles:
                self.allowed_roles.update(allowed_roles)
            self._save_state()
            print(f"[!] [MAINTENANCE MODE ACTIVATED] Reason: {self.reason} | Allowed Users: {sorted(list(self.allowed_users))}")

    def disable_maintenance(self):
        """Deactivates maintenance mode, restores normal operation, and triggers FIM re-baselining."""
        with self.lock:
            self.is_enabled = False
            self.start_time = None
            self._save_state()
            print("[+] [MAINTENANCE MODE DEACTIVATED] Normal enterprise operations restored.")

            # Trigger FIM Re-Baselining for any legitimate system updates made during maintenance
            try:
                from detection.file_integrity_monitor import FileIntegrityMonitor
                fim = FileIntegrityMonitor()
                fim.update_all_baselines()
            except Exception:
                pass

    def allow_user(self, username: str):
        """Whitelists a user for maintenance window operations."""
        with self.lock:
            self.allowed_users.add(username.strip())
            self._save_state()
            print(f"[+] User '{username}' granted maintenance mode access.")

    def deny_user(self, username: str):
        """Removes a user from maintenance window operations."""
        with self.lock:
            self.allowed_users.discard(username.strip())
            self._save_state()
            print(f"[-] User '{username}' revoked from maintenance mode access.")

    def get_status(self) -> dict:
        """Returns comprehensive status dictionary for SOC dashboards & CLI."""
        with self.lock:
            duration_str = "0m"
            if self.is_enabled and self.start_time:
                mins = int((time.time() - self.start_time) // 60)
                duration_str = f"{mins}m"

            return {
                "is_enabled": self.is_enabled,
                "status": "ACTIVE" if self.is_enabled else "STANDBY",
                "reason": self.reason,
                "start_time": time.ctime(self.start_time) if self.start_time else "N/A",
                "active_duration": duration_str,
                "allowed_users": sorted(list(self.allowed_users)),
                "allowed_roles": sorted(list(self.allowed_roles)),
                "total_roles_configured": len(self.user_roles)
            }

    # --------------------------------------------------------------------------
    # RBAC ROLE MANAGEMENT
    # --------------------------------------------------------------------------

    def get_user_role(self, username: str) -> str:
        with self.lock:
            return self.user_roles.get(username.strip(), "RESTRICTED")

    def set_user_role(self, username: str, role: str):
        with self.lock:
            clean_role = role.strip().upper()
            self.user_roles[username.strip()] = clean_role
            self._save_rbac()
            print(f"[+] User '{username}' assigned role '{clean_role}'.")

    def list_roles(self) -> dict:
        with self.lock:
            return dict(self.user_roles)

    # --------------------------------------------------------------------------
    # VIOLATION INTERCEPT & ENFORCEMENT
    # --------------------------------------------------------------------------

    def handle_maintenance_violation(self, username: str, source_ip: str, tty: str, command: str, logger=None, callback=None) -> bool:
        """
        Intercepts unauthorized user actions during maintenance.
        Returns True if an unauthorized violation was intercepted and blocked.
        """
        if not self.is_maintenance_active():
            return False

        if self.is_user_authorized(username):
            return False

        # Non-interactive background processes (cron, systemd, backup) are immune from maintenance termination
        if not tty or str(tty).strip() in ["None", "?", "cron", "systemd", ""]:
            return False

        # User is unauthorized during maintenance!
        clean_tty = tty.replace("/dev/", "").strip() if tty else "pts/0"
        violation_msg = (
            f"MAINTENANCE ACCESS DENIED: User '{username}' attempted '{command}' from {source_ip} on {clean_tty}. "
            f"Active Window: '{self.reason}'."
        )

        print(f"\n[!] [MAINTENANCE DEFENSE INTERCEPT] {violation_msg}")

        if logger:
            logger.log_event("WARNING", "MAINTENANCE_DEFENSE", "MAINTENANCE_VIOLATION", source_ip, violation_msg)

        if callback:
            callback("MAINTENANCE_VIOLATION", source_ip, violation_msg)

        # Terminate unauthorized interactive terminal session if enabled
        if getattr(config, 'MAINTENANCE_AUTO_KILL_UNAUTHORIZED', True) and os.name != 'nt' and clean_tty:
            try:
                try:
                    with open(f"/dev/{clean_tty}", "w") as tty_out:
                        tty_out.write(f"\r\n\033[2J\033[H\r\n[!] ACCESS DENIED: SYSTEM IS CURRENTLY UNDER MAINTENANCE.\r\n    Reason: {self.reason}\r\n    Contact security administration.\r\n\r\n")
                        tty_out.flush()
                except Exception:
                    pass

                is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
                kill_cmd = f"pkill -9 -t {clean_tty}" if is_root else f"sudo -n pkill -9 -t {clean_tty}"
                subprocess.run(kill_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            except Exception:
                pass

        return True

# Global Singleton Instance
maintenance_manager = MaintenanceModeManager()
maintenance_mode_manager = maintenance_manager
