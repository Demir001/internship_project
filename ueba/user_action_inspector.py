# -*- coding: utf-8 -*-
"""
==============================================================================
HUMAN-READABLE USER ACTION, FILE & SERVICE AUDITOR (user_action_inspector.py)
==============================================================================
Deeply parses user terminal and kernel commands to extract exact context:
1. Target Service / Daemon (systemctl, service, docker, init)
2. Target File / Configuration Path (nano, vim, cat, sed, chmod, rm, cp, mv)
3. Action Category (SERVICE_CONTROL, FILE_MODIFICATION, PACKAGE_MANAGEMENT, etc.)
4. Human-Readable Synthesized Summary (English)
5. Dedicated Activity Log output: logs/user_actions_readable.log
==============================================================================
"""

import os
import re
import time
import json
import threading
from datetime import datetime

import config
from modules.db_manager import get_db_connection
from modules.smart_logger import smart_logger

class UserActionInspector:
    def __init__(self, log_file="logs/user_actions_readable.log", db_name="security_events.db"):
        self.log_file = log_file
        self.db_name = db_name
        self.lock = threading.Lock()
        
        os.makedirs(os.path.dirname(self.log_file) if os.path.dirname(self.log_file) else ".", exist_ok=True)
        self.init_db()

    def init_db(self):
        """Initializes user action audit table in SQLite WAL mode."""
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""CREATE TABLE IF NOT EXISTS user_action_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    username TEXT,
                    source_ip TEXT,
                    tty TEXT,
                    action_type TEXT,
                    target_service TEXT,
                    target_file TEXT,
                    command TEXT,
                    status TEXT,
                    summary TEXT,
                    risk_level TEXT
                )""")
                conn.commit()
        except Exception as e:
            print(f"[-] User Action Audit DB Init Error: {e}")

    def inspect_command(self, username: str, source_ip: str, tty: str, raw_command: str, is_malicious: bool = False, risk_score: int = 0) -> dict:
        """
        Parses command syntax to extract target files, services, intent, and readable explanation.
        """
        cmd = (raw_command or "").strip()
        cmd_clean = re.sub(r'^(?:sudo\s+(?:-u\s+\w+\s+|-[a-z0-9]+\s+)*)', '', cmd).strip()
        tokens = cmd_clean.split()
        
        action_type = "COMMAND_EXECUTION"
        target_service = "N/A"
        target_file = "N/A"
        summary = ""
        risk_level = "CRITICAL" if risk_score >= 70 or is_malicious else ("WARNING" if risk_score >= 35 else "INFO")
        status_tag = "[SUSPICIOUS / MALICIOUS]" if is_malicious or risk_score >= 50 else "[SAFE OPERATION]"

        if not tokens:
            return {
                "action_type": action_type, "target_service": target_service,
                "target_file": target_file, "summary": "Empty command executed",
                "risk_level": "LOW", "status": "[SAFE OPERATION]"
            }

        base_cmd = os.path.basename(tokens[0]).lower()

        # ----------------------------------------------------------------------
        # 1. SERVICE & DAEMON CONTROL (systemctl, service, /etc/init.d/)
        # ----------------------------------------------------------------------
        if base_cmd in ["systemctl", "service"]:
            action_type = "SERVICE_CONTROL"
            if base_cmd == "systemctl" and len(tokens) >= 3:
                op = tokens[1].lower()
                target_service = tokens[2]
                if not target_service.endswith(".service") and "." not in target_service:
                    target_service += ".service"
                summary = f"Executed '{op}' operation on system service '{target_service}'."
            elif base_cmd == "service" and len(tokens) >= 3:
                target_service = tokens[1] + ".service"
                op = tokens[2].lower()
                summary = f"Managed service '{target_service}' with operation '{op}'."
            else:
                target_service = tokens[1] if len(tokens) > 1 else "systemd"
                summary = f"Executed system service control command: {cmd}"

        # ----------------------------------------------------------------------
        # 2. FILE EDITING & MODIFICATION (nano, vim, vi, gedit, sed, awk, tee)
        # ----------------------------------------------------------------------
        elif base_cmd in ["nano", "vim", "vi", "gedit", "emacs", "code", "micro"]:
            action_type = "FILE_MODIFICATION"
            target_files = [t for t in tokens[1:] if not t.startswith("-")]
            target_file = ", ".join(target_files) if target_files else "Unknown File"
            summary = f"Edited/opened file '{target_file}' using text editor '{base_cmd}'."

        elif base_cmd in ["touch", "mkdir"]:
            action_type = "FILE_CREATION"
            target_files = [t for t in tokens[1:] if not t.startswith("-")]
            target_file = ", ".join(target_files) if target_files else "New File/Directory"
            summary = f"Created new file or directory: '{target_file}'."

        # ----------------------------------------------------------------------
        # 3. FILE VIEWING & INSPECTION (cat, head, tail, less, more, grep, xxd)
        # ----------------------------------------------------------------------
        elif base_cmd in ["cat", "head", "tail", "less", "more", "nl", "xxd", "hexdump", "strings"]:
            action_type = "FILE_READ_INSPECTION"
            target_files = [t for t in tokens[1:] if not t.startswith("-")]
            target_file = ", ".join(target_files) if target_files else "Standard Input"
            if "/etc/shadow" in target_file or "shadow" in target_file:
                action_type = "SENSITIVE_CREDENTIAL_READ"
                summary = f"CRITICAL! Unauthorized password hash file ({target_file}) read attempt!"
            else:
                summary = f"Viewed contents of file '{target_file}' using '{base_cmd}'."

        # ----------------------------------------------------------------------
        # 4. FILE PERMISSIONS & OWNERSHIP (chmod, chown, chgrp)
        # ----------------------------------------------------------------------
        elif base_cmd in ["chmod", "chown", "chgrp"]:
            action_type = "FILE_PERMISSION_CHANGE"
            target_files = [t for t in tokens[1:] if not t.startswith("-")]
            perm_val = tokens[1] if len(tokens) > 1 else ""
            target_file = ", ".join(target_files[1:]) if len(target_files) > 1 else (target_files[0] if target_files else "N/A")
            summary = f"Modified permissions/ownership on '{target_file}' ({base_cmd} {perm_val})."

        # ----------------------------------------------------------------------
        # 5. FILE DELETION & MOVING (rm, mv, cp)
        # ----------------------------------------------------------------------
        elif base_cmd in ["rm", "unlink", "shred"]:
            action_type = "FILE_DELETION"
            target_files = [t for t in tokens[1:] if not t.startswith("-")]
            target_file = ", ".join(target_files) if target_files else "File"
            summary = f"Deleted file/directory '{target_file}' using '{base_cmd}'."

        elif base_cmd in ["mv", "cp"]:
            action_type = "FILE_MOVE_COPY"
            target_files = [t for t in tokens[1:] if not t.startswith("-")]
            target_file = " -> ".join(target_files) if len(target_files) >= 2 else ", ".join(target_files)
            summary = f"File {base_cmd} operation: '{target_file}'."

        # ----------------------------------------------------------------------
        # 6. PACKAGE MANAGEMENT (apt, dpkg, yum, dnf, pip, npm)
        # ----------------------------------------------------------------------
        elif base_cmd in ["apt", "apt-get", "dpkg", "yum", "dnf", "pip", "npm", "snap"]:
            action_type = "PACKAGE_MANAGEMENT"
            op = tokens[1] if len(tokens) > 1 else "operation"
            pkgs = " ".join([t for t in tokens[2:] if not t.startswith("-")])
            target_service = f"PackageManager ({base_cmd})"
            target_file = pkgs or "N/A"
            summary = f"Package manager ({base_cmd}) executed '{op}': {pkgs}."

        # ----------------------------------------------------------------------
        # 7. USER & ACCOUNT MANAGEMENT (useradd, usermod, passwd, groupadd)
        # ----------------------------------------------------------------------
        elif base_cmd in ["useradd", "adduser", "usermod", "userdel", "passwd", "groupadd", "gpasswd"]:
            action_type = "USER_ACCOUNT_MANAGEMENT"
            target_user = tokens[-1] if len(tokens) > 1 else "user"
            target_file = "/etc/passwd, /etc/shadow"
            summary = f"User account management executed ({base_cmd}) -> Target: {target_user}."

        # ----------------------------------------------------------------------
        # 8. CRON & SCHEDULING (crontab, at)
        # ----------------------------------------------------------------------
        elif base_cmd in ["crontab", "at"]:
            action_type = "CRON_SCHEDULE_MANAGEMENT"
            target_file = "/etc/crontab, /var/spool/cron"
            summary = f"Scheduled cron task modification executed: '{cmd}'."

        # ----------------------------------------------------------------------
        # 9. NETWORK TRANSFERS & PROBES (curl, wget, scp, rsync, ssh, ping)
        # ----------------------------------------------------------------------
        elif base_cmd in ["curl", "wget", "scp", "rsync", "ssh", "sftp", "ftp", "nc", "ncat", "socat"]:
            action_type = "NETWORK_OPERATION"
            urls_or_hosts = [t for t in tokens[1:] if not t.startswith("-") and (":" in t or "/" in t or "." in t)]
            target_file = ", ".join(urls_or_hosts) if urls_or_hosts else "Remote Host"
            summary = f"Network connection / data transfer initiated ({base_cmd}) -> {target_file}."

        # ----------------------------------------------------------------------
        # 10. SYSTEM MONITORING & OBSERVABILITY (df, free, top, htop, ps, uptime)
        # ----------------------------------------------------------------------
        elif base_cmd in ["df", "free", "top", "htop", "ps", "uptime", "dmesg", "journalctl", "netstat", "ss", "ip"]:
            action_type = "SYSTEM_OBSERVABILITY"
            summary = f"System observability & metric query executed ({base_cmd})."

        # ----------------------------------------------------------------------
        # 11. GENERAL EXECUTIONS (scripts, binaries, python, bash)
        # ----------------------------------------------------------------------
        else:
            action_type = "COMMAND_EXECUTION"
            summary = f"User executed command: {cmd}"

        return {
            "action_type": action_type,
            "target_service": target_service,
            "target_file": target_file,
            "summary": summary,
            "risk_level": risk_level,
            "status": status_tag
        }

    def log_action(self, username: str, source_ip: str, tty: str, raw_command: str, is_malicious: bool = False, risk_score: int = 0):
        """
        Formats and records user activity into human-readable logs and SQLite audit table.
        """
        parsed = self.inspect_command(username, source_ip, tty, raw_command, is_malicious, risk_score)
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        # 1. Format Structured Human-Readable Log Block
        readable_block = (
            f"\n{'='*85}\n"
            f"[{now_str}] [USER ACTION AUDIT] [USER: {username}] [IP: {source_ip}] [TTY: {tty}]\n"
            f"  ├─ ACTION TYPE    : {parsed['action_type']}\n"
            f"  ├─ TARGET SERVICE : {parsed['target_service']}\n"
            f"  ├─ AFFECTED FILE  : {parsed['target_file']}\n"
            f"  ├─ EXECUTED CMD   : {raw_command}\n"
            f"  ├─ SECURITY STATUS: {parsed['status']} ({parsed['risk_level']})\n"
            f"  └─ DESCRIPTION    : {parsed['summary']}\n"
            f"{'='*85}\n"
        )

        with self.lock:
            # Write to dedicated user action readable log file
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.log_file)), exist_ok=True)
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(readable_block)
            except Exception as e:
                print(f"[-] User Action Log Write Error: {e}")

            # Also persist in SQLite WAL database
            try:
                with get_db_connection(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""INSERT INTO user_action_audit
                        (timestamp, username, source_ip, tty, action_type, target_service, target_file, command, status, summary, risk_level)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (now_str, username, source_ip, tty, parsed["action_type"], parsed["target_service"],
                         parsed["target_file"], raw_command, parsed["status"], parsed["summary"], parsed["risk_level"]))
                    conn.commit()
            except Exception as e:
                print(f"[-] User Action Audit DB Error: {e}")

# Singleton Instance
user_action_inspector = UserActionInspector()
