# -*- coding: utf-8 -*-
"""
==============================================================================
MULTI-SESSION, IDLE INACTIVITY & ACTIVE COMMAND TRACKING ENGINE
(user_session_tracker.py)
==============================================================================
This module provides:
1. REAL-TIME NON-SUDO & SUDO TERMINAL PROCESS INTERCEPT:
   - Continuously samples active processes on terminal TTYs to analyze regular
     user keystrokes and shell commands without requiring 'sudo'.
2. MULTI-SESSION & IDLE TIMEOUT AUTO-KICK (15-Minute Threshold):
   - Monitors active terminal sessions and cleanly terminates idle sessions.
3. LOW-NOISE COMMAND BUFFERING:
   - Aggregates routine developer commands into periodic summaries to reduce noise.
4. HOSTILE INTRUSION INTERCEPT:
   - Detects destructive commands, reverse shells, or privilege escalation and
     immediately terminates the user's terminal session while applying an IP ban.
5. THREAD-SAFE SQLITE CONCURRENCY (WAL Mode & Busy Timeout).
6. ZOMBIE & STALE SESSION CLEANUP:
   - Automatically resolves stale sessions on boot or upon new login on the same TTY.
==============================================================================
"""

import os
import time
import psutil
import subprocess
import threading
import config
from modules.smart_logger import SmartLogger
from modules.ai_security_engine import AISecurityEngine
from modules.ban_manager import BanManager
from modules.db_manager import get_db_connection

class UserSessionTracker:
    def __init__(self, db_name="security_events.db", logger=None, ai_engine=None, ban_manager=None, callback=None):
        self.db_name = db_name
        self.logger = logger or SmartLogger()
        self.ai_engine = ai_engine or AISecurityEngine()
        self.ban_manager = ban_manager or BanManager(logger=self.logger)
        self.callback = callback
        
        self.active_sessions = {}
        self.seen_process_pids = set()
        self._cmd_analysis_cache = {}
        self.is_running = True
        self.lock = threading.RLock()
        
        self.init_db()
        self.cleanup_stale_sessions_on_boot()
        self._install_linux_shell_audit_hook()

    def _install_linux_shell_audit_hook(self):
        """
        Installs hardened system-wide interactive shell audit hook in /etc/profile.d and /etc/bash.bashrc.
        Includes __SIEM_LOCK reentrancy protection and non-blocking background dispatch.
        """
        if os.name != 'nt':
            try:
                is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
                if is_root:
                    hook_content = (
                        '# SIEM Hardened Interactive Shell Command Audit Hook\n'
                        '__siem_audit_hook() {\n'
                        '    local LAST_EXIT=$?\n'
                        '    [[ -n "$__SIEM_LOCK" ]] && return\n'
                        '    export __SIEM_LOCK=1\n'
                        '    local CMD\n'
                        '    CMD=$(HISTTIMEFORMAT= history 1 2>/dev/null | sed "s/^[ ]*[0-9]*[ ]*//")\n'
                        '    if [[ -n "$CMD" && "$CMD" != *"siem_audit"* && "$CMD" != *"logger "* ]]; then\n'
                        '        (logger -p auth.notice -t siem_audit "user=$USER tty=$(tty 2>/dev/null | sed \\"s#/dev/##\\") cmd=\\"$CMD\\" exit=$LAST_EXIT" &) 2>/dev/null\n'
                        '    fi\n'
                        '    unset __SIEM_LOCK\n'
                        '}\n'
                        'export PROMPT_COMMAND="__siem_audit_hook; $PROMPT_COMMAND"\n'
                    )
                    # 1. Write to /etc/profile.d/siem_audit.sh
                    hook_path = "/etc/profile.d/siem_audit.sh"
                    with open(hook_path, "w", encoding="utf-8") as f:
                        f.write(hook_content)
                    os.chmod(hook_path, 0o644)

                    # 2. Append to /etc/bash.bashrc so interactive subshells always load it
                    bashrc_path = "/etc/bash.bashrc"
                    if os.path.exists(bashrc_path):
                        with open(bashrc_path, "r", encoding="utf-8", errors="ignore") as f:
                            current_rc = f.read()
                        if "siem_audit" not in current_rc:
                            with open(bashrc_path, "a", encoding="utf-8") as f:
                                f.write("\n" + hook_content + "\n")

                    # 3. Kernel Auditd watches on sensitive files if auditctl exists
                    subprocess.run("auditctl -w /etc/shadow -p r -k siem_shadow 2>/dev/null", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run("auditctl -w /etc/sudoers -p r -k siem_sudoers 2>/dev/null", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    def init_db(self):
        """
        Initializes user session and activity log tables in WAL mode.
        """
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id TEXT PRIMARY KEY,
                    username TEXT,
                    source_ip TEXT,
                    tty_device TEXT,
                    login_time REAL,
                    logout_time REAL,
                    last_activity_time REAL,
                    total_commands INTEGER,
                    status TEXT
                )""")
                
                cursor.execute("""CREATE TABLE IF NOT EXISTS session_activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    username TEXT,
                    source_ip TEXT,
                    timestamp TEXT,
                    command TEXT,
                    category TEXT,
                    risk_score INTEGER,
                    summary TEXT,
                    mitre_id TEXT,
                    criticality TEXT
                )""")
                conn.commit()
        except Exception as e:
            print(f"[-] Session Database Initialization Error: {e}")

    def cleanup_stale_sessions_on_boot(self):
        """
        Marks unclosed sessions from previous reboots or crashes as CLOSED.
        """
        now = time.time()
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE user_sessions SET status = 'SYSTEM_REBOOT_CLOSED', logout_time = ? WHERE status = 'ACTIVE'", (now,))
                conn.commit()
        except Exception:
            pass

    def start_session(self, username, source_ip, tty="pts/0"):
        """
        Registers and logs a new active user terminal session.
        Preserves authentic remote IP when user escalates privileges via sudo su.
        """
        now = time.time()
        actual_ip = source_ip

        with self.lock:
            # If source_ip is LOCAL_SYSTEM, preserve existing authentic remote client IP on this TTY
            if source_ip in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                for (u, s_ip, t), sess in list(self.active_sessions.items()):
                    if t == tty and s_ip not in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                        actual_ip = s_ip
                        break

            session_id = f"SESS_{username}_{actual_ip}_{tty.replace('/', '_')}_{int(now * 1000)}"
            session_key = (username, actual_ip, tty)

            # Close/replace existing session on this TTY device
            for key in list(self.active_sessions.keys()):
                if key[2] == tty and key != session_key:
                    del self.active_sessions[key]
                    
            session_data = {
                "session_id": session_id,
                "username": username,
                "source_ip": actual_ip,
                "tty": tty,
                "login_time": now,
                "last_activity_time": now,
                "command_count": 0,
                "cumulative_risk": 0,
                "routine_buffer": []
            }
            self.active_sessions[session_key] = session_data

        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""INSERT INTO user_sessions 
                    (session_id, username, source_ip, tty_device, login_time, last_activity_time, total_commands, status)
                    VALUES (?, ?, ?, ?, ?, ?, 0, 'ACTIVE')""",
                    (session_id, username, actual_ip, tty, now, now))
                conn.commit()
        except Exception as e:
            print(f"[-] Session Database Write Error: {e}")

        msg = f"User '{username}' logged in successfully. (IP: {actual_ip} | Terminal: {tty})"
        self.logger.log_event("NOTICE", "SESSION_TRACKER", "USER_LOGIN", actual_ip, msg)
        print(f"[+] [SESSION STARTED] {msg}")

    def resolve_ip_by_tty(self, tty: str, fallback_user: str = None) -> str:
        """
        Resolves the authentic remote client IP (e.g. 192.168.42.190) from active sessions
        or OS utmp (psutil.users()) by matching the TTY/PTS device.
        """
        if not tty:
            return "LOCAL_SYSTEM"

        clean_tty = tty.replace("/dev/", "").strip()

        # 1. Match from in-memory active sessions
        with self.lock:
            for (u, s_ip, t), sess in self.active_sessions.items():
                clean_t = t.replace("/dev/", "").strip()
                if (clean_t == clean_tty or clean_tty in clean_t or clean_t in clean_tty) and s_ip not in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                    return s_ip
                if fallback_user and u == fallback_user and s_ip not in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                    return s_ip

        # 2. Query psutil.users() live from Linux utmp by TTY or Username
        try:
            import psutil
            for u in psutil.users():
                u_term = (u.terminal or "").replace("/dev/", "").strip()
                u_host = (u.host or "").strip()
                if u_host and u_host not in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1", ""]:
                    if u_term and (u_term == clean_tty or clean_tty in u_term or u_term in clean_tty):
                        return u_host
                    if fallback_user and u.name == fallback_user:
                        return u_host
        except Exception:
            pass

        return "LOCAL_SYSTEM"

    def record_command(self, username, source_ip, command, tty="pts/0"):
        """
        Analyzes command execution in user session and terminates hostile sessions.
        """
        now = time.time()
        
        with self.lock:
            # 1. Resolve authentic remote client IP from active session on matching TTY
            actual_ip = source_ip
            actual_user = username

            if source_ip in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                resolved_ip = self.resolve_ip_by_tty(tty, fallback_user=username)
                if resolved_ip and resolved_ip != "LOCAL_SYSTEM":
                    actual_ip = resolved_ip

            actual_key = (actual_user, actual_ip, tty)

            if actual_key not in self.active_sessions:
                self.start_session(actual_user, actual_ip, tty)
                actual_key = (actual_user, actual_ip, tty)
                
            session = self.active_sessions[actual_key]
            session["last_activity_time"] = now
            session["command_count"] += 1

            # 1.5. Maintenance Defense & Authorization Intercept
            try:
                from modules.maintenance_mode import maintenance_manager
                if maintenance_manager.is_maintenance_active():
                    if not maintenance_manager.is_user_authorized(actual_user):
                        maintenance_manager.handle_maintenance_violation(
                            username=actual_user,
                            source_ip=actual_ip,
                            tty=tty,
                            command=command,
                            logger=self.logger,
                            callback=getattr(self, 'callback', None)
                        )
                        return
            except Exception:
                pass

            # 1.6. Granular Access Control & Permission Enforcement (PBAC / RBAC)
            try:
                from modules.permission_manager import permission_manager
                is_allowed, missing_perms, req_perms = permission_manager.check_command_permission(actual_user, command)
                if not is_allowed:
                    missing_str = ", ".join(sorted(list(missing_perms)))
                    req_str = ", ".join(sorted(list(req_perms)))
                    perm_msg = f"PERMISSION DENIED: User '{actual_user}' lacks permission(s) [{missing_str}] for '{command}' (Required: {req_str})."
                    print(f"\n[!] [ACCESS CONTROL VIOLATION] {perm_msg}")
                    self.logger.log_event("WARNING", "ACCESS_CONTROL", "PERMISSION_DENIED", actual_ip, perm_msg)
                    if hasattr(self, 'callback') and self.callback:
                        self.callback("PERMISSION_DENIED", actual_ip, perm_msg)
                    session["cumulative_risk"] += 25
                    return
            except Exception:
                pass

            # 2. Analyze command context & AI classification
            category, risk_score, is_anomaly, summary, ai_res, criticality = self.analyze_command_context(actual_user, command)

            # Deep Human-Readable Action & Target Inspection (File, Service, Context)
            try:
                from modules.user_action_inspector import user_action_inspector
                user_action_inspector.log_action(
                    username=actual_user,
                    source_ip=actual_ip,
                    tty=tty,
                    raw_command=command,
                    is_malicious=is_anomaly,
                    risk_score=risk_score
                )
            except Exception:
                pass

            # 3. Buffer low-risk routine commands
            if not is_anomaly and risk_score == 0:
                session["routine_buffer"].append(command)
                if len(session["routine_buffer"]) >= 10:
                    self.flush_routine_buffer(session)
                return

            # 4. Log suspicious/hostile command event
            session["cumulative_risk"] += risk_score
            mitre_id = ai_res.get("mitre_id", "N/A")
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            try:
                with get_db_connection(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""INSERT INTO session_activity_logs 
                        (session_id, username, source_ip, timestamp, command, category, risk_score, summary, mitre_id, criticality)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (session["session_id"], actual_user, actual_ip, timestamp, command, category, risk_score, summary, mitre_id, criticality))
                    
                    cursor.execute("UPDATE user_sessions SET total_commands = ?, last_activity_time = ? WHERE session_id = ?",
                        (session["command_count"], now, session["session_id"]))
                    conn.commit()
            except Exception as e:
                print(f"[-] Command Logging Error: {e}")

            level = "CRITICAL" if criticality == "CRITICAL" else ("WARNING" if criticality == "HIGH" else "NOTICE")
            log_msg = f"Session [{session['session_id']}]: User '{actual_user}' executed '{command}'. (Summary: {summary})"
            self.logger.log_event(level, "USER_ACTIVITY", f"COMMAND_{category}", actual_ip, log_msg, ai_info=ai_res)

            # Immediate hostile action intercept & session kill
            if risk_score >= 70 or session["cumulative_risk"] >= 50:
                is_local_console = (actual_ip in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"] and tty in ["tty1", "tty2", "console", "/dev/tty1"])
                clean_tty = tty.replace("/dev/", "")
                
                if getattr(self, 'dry_run', False) or getattr(config, 'DRY_RUN_MODE', False):
                    print(f"[*] [DRY-RUN / WARNING ONLY] Hostile command intercepted for '{actual_user}' on {clean_tty}: '{command}'. (Dry-run mode: no kill/ban applied).")
                else:
                    # 1. Terminate hostile interactive terminal session
                    if not is_local_console and os.name != 'nt':
                        try:
                            current_siem_tty = ""
                            try:
                                current_siem_tty = (psutil.Process().terminal() or "").replace("/dev/", "")
                            except Exception:
                                pass

                            if clean_tty and clean_tty != current_siem_tty:
                                # Instantly wipe screen and scrollback buffer
                                try:
                                    with open(f"/dev/{clean_tty}", "w") as tty_out:
                                        tty_out.write("\033[2J\033[H\033[3J\r\n\r\n[!] ACCESS DENIED: SECURITY VIOLATION INTERCEPTED. TERMINAL KILLED.\r\n\r\n")
                                        tty_out.flush()
                                except Exception:
                                    pass

                                is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
                                kill_cmd = f"pkill -9 -t {clean_tty}" if is_root else f"sudo -n pkill -9 -t {clean_tty}"
                                subprocess.run(kill_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                        except Exception:
                            pass

                    # 2. Ban IP on firewall if network IP
                    if actual_ip not in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"] and not self.ban_manager.is_banned(actual_ip):
                        ban_reason = f"Hostile Terminal Command: '{command}' ({criticality} Level - Risk: {session['cumulative_risk']})"
                        self.ban_manager.ban_ip(ip=actual_ip, criticality=criticality, reason=ban_reason)
                
                session["cumulative_risk"] = 0

    def analyze_command_context(self, username, command):
        """
        Contextually inspects commands across Regex rules, AI Engine, and MITRE ATT&CK vectors.
        Fast in-memory cache enables sub-0.01ms evaluation for repetitive developer commands.
        """
        raw_cmd = command.strip()
        if hasattr(self, '_cmd_analysis_cache') and raw_cmd in self._cmd_analysis_cache:
            return self._cmd_analysis_cache[raw_cmd]

        raw_lower = raw_cmd.lower()
        from modules.canonicalizer import PayloadCanonicalizer
        cmd = PayloadCanonicalizer.canonicalize(command).strip()
        cmd_lower = cmd.lower()
        
        def _commit(cat, score, is_anom, summary, ai_det, urgency):
            res = (cat, score, is_anom, summary, ai_det, urgency)
            if hasattr(self, '_cmd_analysis_cache'):
                if len(self._cmd_analysis_cache) >= 10000:
                    self._cmd_analysis_cache.clear()
                self._cmd_analysis_cache[raw_cmd] = res
            return res

        # -------------------------------------------------------------
        # PHASE 1: SIEM Internal Daemons & Remote IDE Handshakes (Immediate Pass)
        # -------------------------------------------------------------
        if any(w in raw_lower for w in [
            "ufw ", "iptables ", "ip6tables ", "pkill ", "ss -k", "conntrack -d", "main.py", "manage.py",
            "landscape-sysinfo", "update-notifier", "update-motd", "motd-news", "apt-check", "systemd",
            "gpg-agent", "ssh-agent", "dbus", "snapd", "cloud-init", "locale", "dircolors",
            "ubuntu-advantage", "apt-esm-hook", "fwupd", "hwe-eol", "esm-cache", "lesspipe",
            "motd.ubuntu.com", "ubuntu.com", "canonical",
            "/etc/update-motd", "/usr/lib/ubuntu-advantage", "/usr/lib/update-notifier", "/usr/libexec",
            "siem_audit", ".vscode-server", ".cursor-server", ".windsurf-server", "vscode-remote", ".jb-server", ".idea-server",
            "sftp-server", "scp -t", "rsync "
        ]):
            return _commit("ROUTINE_COMMAND", 0, False, "Standard System Utility / Maintenance", {}, "LOW")

        # -------------------------------------------------------------
        # PHASE 1.5: Role-Aware Administrative & DevOps Diagnostics (Exempt from False Alarm)
        # -------------------------------------------------------------
        is_admin_or_devops = False
        try:
            from modules.maintenance_mode import maintenance_manager
            role = maintenance_manager.get_user_role(username).upper()
            is_admin_or_devops = (username in ["root", "admin", "devops"] or role in ["ADMIN", "DEVOPS", "AUDITOR"])
        except Exception:
            is_admin_or_devops = (username in ["root", "admin", "devops"])

        # Legitimate Admin Inspection (e.g. sudo cat /etc/shadow, strings /proc, find . -delete, python script)
        if is_admin_or_devops and not any(w in raw_lower for w in ["rm -rf /", ":(){ :|:& };:", "mkfs", "dd if=/dev/zero of=/dev/sd", "nc -e", "/dev/tcp"]):
            if any(w in raw_lower for w in [
                "cat /etc/shadow", "cat /etc/sudoers", "strings /proc", "find . -name", "find /var/log",
                "python ", "python3 ", "node ", "docker run", "docker exec", "git pull", "git push",
                "systemctl restart", "systemctl reload", "journalctl", "dmesg"
            ]):
                return _commit("ADMIN_INSPECTION", 0, False, f"Authorized Administrative Inspection by {username}", {}, "LOW")

        ai_res = self.ai_engine.analyze(raw_cmd)
        
        # -------------------------------------------------------------
        # PHASE 2: DETERMINISTIC HIGH-SEVERITY CYBER ATTACK SIGNATURES
        # -------------------------------------------------------------

        # A. Destructive System Wipes & Sabotage
        if any(w in raw_lower for w in [
            "rm -rf /", "rm -rf /*", "rm -rf /etc", "rm -rf /boot", "rm -rf /var", "rm -rf /usr",
            "rm -rf /bin", "rm -rf /sbin", "rm -rf /lib", "rm -rf /root", "dd if=/dev/zero of=/dev/",
            "dd if=/dev/urandom of=/dev/", "dd if=/dev/zero of=/proc/", "dd if=/dev/urandom of=/proc/",
            "mkfs.", "mkswap -f", "fdisk /dev/", "parted /dev/", "shred ", "openssl enc -aes-256-cbc",
            ":(){ :|:& };:", "forkbomb", "wipefs -a", "blkdiscard ", "sgdisk --zap-all",
            "cat /dev/urandom > /dev/mem", "cat /dev/zero > /dev/kmem", "chmod -r 000 /",
            "chown -r nobody:nogroup /", "find / -name '*.db' -delete", "find / -name '*.sql' -exec rm",
            "find /var/www -type f -delete", "head -c 100m /dev/urandom > /dev/sda"
        ]):
            return _commit("DESTRUCTIVE_MUTATION", 90, True, "Dangerous Destructive System Data Wipe Attempt", ai_res, "CRITICAL")

        # B. Reverse Shells & C2 Outbound Connections
        if any(w in raw_lower for w in [
            "nc -e", "ncat -e", "nc.traditional", "nc -c bash", "ncat --ssl", "/dev/tcp/", "/dev/udp/",
            "socat exec", "socat tcp-connect", "socat file:`tty`", "socket.socket", "fsockopen",
            "proc_open", "tcpsocket", "openssl s_client", "telnet ", "mknod ", "mkfifo ",
            "awk 'begin {s = \"/inet/tcp/", "lua5", "node -e 'const net", "pastebin.com/raw",
            "nc -lvvp", "ncat -lvvp", "socat tcp-listen", "ztcp", "tclsh <<<", "rcshell",
            "urllib.request", "| bash", "| sh", "| perl", "| python", "<(curl", "<(wget",
            "curl -k https://evil.corp", "curl -ns http", "fetch -o - http", "socket(s,pf_inet",
            "sockaddr_in(", "io::socket::inet", "| /bin/bash", "| /bin/sh"
        ]):
            return _commit("REVERSE_SHELL_ATTEMPT", 85, True, "Outbound Reverse Shell / C2 Connection Attempt", ai_res, "CRITICAL")

        # C. Sensitive Credential Access & Shadow File Stealing
        if any(s in cmd_lower or s in raw_lower for s in [
            "/etc/shadow", "/etc/gshadow", "/etc/security/opasswd", "/etc/master.passwd",
            "etc/shadow", "etc/gshadow", "s?ad*w", "sha\\", "wodahs/cte", "shadow.tar",
            "loot.zip", "/tmp/s.gz", "/tmp/s.bz2", "/tmp/s.xz", "shadow.bak", "shadow.gz",
            "unshadow ", "b=/shadow", "c\\a\\t", "s\\h\\a\\d\\o\\w"
        ]):
            return _commit("SENSITIVE_FILE_READ", 75, True, "Unauthorized Sensitive Credential File Read (/etc/shadow)", ai_res, "CRITICAL")

        # D. Privilege Escalation & GTFOBins Exploit Payloads
        if any(w in cmd_lower or w in raw_lower for w in [
            "chmod +s", "chmod 4755", "chmod 4777", "chmod u+s", "pkexec", "--checkpoint-action=exec",
            "checkpoint-action", "apt::update::pre-invoke", "nopasswd", "sudoers.d", "-c ':!", "-c \":!",
            "-c ':!/", "-c \":!/", "-exec /bin/sh", "-exec /bin/bash", "-exec /bin/zsh", "-exec sh",
            "-exec bash", "-exec zsh", "find . -exec /bin/sh", "gdb -nx", "gdb -p 1 -ex",
            "strace -o /dev/null /bin/sh", "env /bin/sh", "cp /bin/bash /tmp/", "cp /bin/sh /tmp/",
            "sudo -u#-1", "capsh --gid=0", "taskset 1 /bin/sh", "flock -u / /bin/sh", "unshare -r /bin/sh",
            "unshare -r /bin/bash", "nmap --interactive", "zip /tmp/test.zip /etc/hosts -t -tt",
            "less /etc/hosts !/bin/sh", "more /etc/hosts !/bin/sh", "man man !/bin/sh",
            "nano -s /bin/sh", "nano -s /bin/bash", "pico -s /bin/sh", "pico -s /bin/bash",
            "--eval '(term", "--eval \"(term", "os.system(\"/bin/bash\")", "os.system('/bin/bash')",
            "os.system(\"/bin/sh\")", "os.system('/bin/sh')",
            "sed -e '1w /dev/null' -e '1e /bin/sh'", "ed -p string /etc/hosts !/bin/sh", "ftp !/bin/sh",
            "chpasswd", "usermod -ag sudo", "usermod -u 0", "hacker:x:0:0:", ".rhosts", "authorized_keys",
            "chmod 777 /etc/", "busybox sh", "sudo -l && sudo su root", "system(\"/bin/sh\")",
            "exec \"/bin/sh\"", "os.execute(\"/bin/sh\")", "call (void)system", "chown root:root /tmp/rootshell"
        ]):
            return _commit("PRIVILEGE_ESCALATION", 75, True, "Privilege Elevation / GTFOBins Backdoor Manipulation", ai_res, "CRITICAL")

        # E. Process Memory Tampering, Rootkits & Log Evasion
        if any(w in cmd_lower or w in raw_lower for w in [
            "insmod ", "rmmod ", "modprobe -f", "modprobe rootkit", "diamorphine", "reptile", "suterusu",
            "mprotect ", "ptrace ", "memfd_create", "mount -o bind /dev/null /var/log",
            "kill -9 $(pgrep auditd)", "systemctl stop auditd", "service auditd stop", "ld_preload",
            "ld.so.preload", "dd if=/tmp/payload of=/proc/", "/dev/shm/.stealth", "/dev/shm/rootsh",
            "modprobe -r apparmor", "modprobe -r selinux", "setenforce 0", "/sys/fs/selinux/enforce",
            "dmesg -c", "history -c && history -w", "shred -u ~/.bash_history",
            "ln -sf /dev/null ~/.bash_history", "histfile=/dev/null", "histsize=0", "unset histfile",
            "kill -9 $$", "> /var/log/wtmp", "> /var/log/btmp", "> /var/log/lastlog", "touch -r /bin/ls /tmp/backdoor",
            "chattr +i /tmp/backdoor", "chattr +i /etc/ld.so.preload", "sysrq", "modprobe msr", "wrmsr ",
            "kexec ", "dd if=/dev/urandom of=/proc/kcore", "chmod 000 /var/log/audit", "/var/run/utmp",
            "/dev/null /var/log/"
        ]):
            return _commit("MEMORY_ROOTKIT_MUTATION", 80, True, "Kernel/Memory/Log Rootkit Anti-Forensics Manipulation", ai_res, "CRITICAL")

        # F. Obfuscated, Hex-Encoded & Evasive Shellcode Payloads
        if any(w in raw_lower for w in [
            "base64 -d", "base64 --decode", "xxd -p -r", "xxd -r -p", "zlib.decompress", "hex2bin",
            "pack(\"h*\"", "pack(\"u*\"", "\\x63\\x61\\x74", "\\x2f\\x62\\x69\\x6e", "\\057\\0142", "c''a\"\"t",
            "/???/??t", "ifs=,;", "${ifs}cat", "powershell -encodedcommand", "b32decode", "b85decode",
            "gzuncompress", "gzinflate", "rev <<<", "printf %s 'c' 'a' 't'", "marshal').loads",
            "eval \\$(printf '\\143\\141\\164"
        ]):
            return _commit("OBFUSCATED_EVASION", 75, True, "Obfuscated / Hex-Encoded Shellcode Execution Attempt", ai_res, "CRITICAL")

        # G. Offensive Port Scanners & Reconnaissance Tooling
        if any(w in raw_lower for w in [
            "nmap ", "masscan ", "zmap ", "hping3 ", "nikto ", "sqlmap ", "gobuster ", "dirsearch ",
            "ffuf ", "wfuzz ", "nuclei ", "wpscan ", "enum4linux ", "smbclient ", "smbmap ", "snmpwalk ",
            "onesixtyone ", "hydra ", "medusa ", "patator ", "ncrack ", "crowbar ", "amass ", "sublist3r ",
            "assetfinder ", "findomain ", "subfinder ", "dnsenum ", "fierce ", "dnsrecon ", "theharvester ",
            "responder "
        ]):
            return _commit("OFFENSIVE_RECON_SCAN", 70, True, "Offensive Security Scanner / Exploitation Framework Execution", ai_res, "HIGH")

        # H. Web Application Exploits & SQL Injections
        if any(w in raw_lower for w in [
            "union select", "union all select", "pg_sleep", "sleep(", "waitfor delay", "xp_cmdshell",
            "xp_dirtree", "information_schema", "extractvalue(", "updatexml(", "into outfile",
            "load_file(", "sqlite_master", "drop table", "truncate table", "benchmark(", "json_keys(",
            "gtid_subset(", "st_latfromgeohash", "st_longfromgeohash", "geometrycollection", "pg_user",
            "<script", "<img src=x", "<svg onload", "<iframe", "<body onload", "<object data=",
            "javascript:alert", "javascript:fetch", "<!entity xxe", "${jndi:", "{{config.",
            "{{''.__class__", "${t(java", "getruntime().exec", "<%= system", "{{7*7}}", "${7*7}",
            "#{7*7}", "#{", "#{\"", "#{'", "ognl", "_memberaccess", "/../..", "..\\..\\", "php://filter", "data://text/plain",
            "expect://", "phar://", "zip://", "/proc/self/environ", "/proc/self/cmdline",
            "/var/log/apache2/", "/var/log/nginx/", "<?php", "<?=`", "assert($_post",
            "call_user_func('system'", "mb_ereg_replace(", "lower:j", "getclass().forname", "win.ini",
            "opensymphony", "xwork2", "#context", "*{\""
        ]) or raw_cmd.startswith("#{") or raw_cmd.startswith("*{"):
            return _commit("WEB_APPLICATION_EXPLOIT", 80, True, "Web Application Injection / RCE Exploit Payload", ai_res, "CRITICAL")

        if ("python" in raw_lower or "perl" in raw_lower or "php" in raw_lower) and "-c " in raw_lower and any(k in raw_lower for k in ["socket", "pty", "subprocess", "exec", "b64decode", "zlib"]):
            return _commit("INLINE_INTERPRETER_EXEC", 75, True, "Inline Command-Line Code String Injection Execution", ai_res, "CRITICAL")

        # -------------------------------------------------------------
        # PHASE 3: COMPREHENSIVE BENIGN LINUX ADMIN, DEVOPS & NETWORKING
        # -------------------------------------------------------------
        benign_prefixes = [
            "uname", "cat /proc/", "lscpu", "lsblk", "lspci", "lsusb", "dmidecode", "free", "df",
            "uptime", "hostnamectl", "timedatectl", "localectl", "sysctl", "vmstat", "iostat",
            "mpstat", "sar", "cat /etc/os-release", "cat /etc/issue", "cat /etc/fstab", "cat /etc/hosts",
            "cat /etc/resolv.conf", "cat /etc/timezone", "cat /etc/environment", "cat /etc/sysctl.conf",
            "cat /etc/security/limits.conf", "cat /etc/crontab", "dmesg", "journalctl", "loginctl",
            "systemd-analyze", "arch", "lshw", "inxi", "smartctl", "hdparm", "findmnt", "lsmod",
            "modinfo", "locale", "ulimit", "ipcs", "ls", "tree", "find /", "stat ", "du ", "file ",
            "wc ", "head ", "tail ", "grep ", "sed ", "awk ", "cut ", "sort ", "uniq ", "diff ",
            "tar ", "gzip ", "zip ", "md5sum", "sha256sum", "cksum", "base64 -w", "split ", "cmp ",
            "comm ", "paste ", "join ", "tr ", "fold ", "expand ", "unexpand", "fmt ", "column ",
            "tac ", "nl ", "pr ", "csplit ", "basename ", "dirname ", "realpath ", "touch ", "mkdir ",
            "cp ", "mv ", "ln ", "readlink ", "mktemp ", "shuf ", "look ", "ip ", "ss ", "netstat ",
            "ping ", "traceroute ", "dig ", "nslookup ", "host ", "curl ", "wget ", "sudo ufw",
            "sudo iptables", "sudo ip6tables", "ethtool", "tcpdump", "iperf3", "arp", "route", "mtr",
            "whois", "nc -z", "lsof", "fuser", "bridge", "nmcli", "iwconfig", "resolvectl", "nft",
            "socat - tcp-listen", "nethogs", "iftop", "bmon", "iptraf-ng", "apt", "dpkg", "snap",
            "flatpak", "pip", "npm", "yarn", "cargo", "gem", "composer", "go ", "rustc", "ruby",
            "perl", "lua", "java", "mvn", "gradle", "clang", "valgrind", "nvm", "pyenv", "rbenv",
            "sdk", "brew", "systemctl", "ps", "pstree", "pgrep", "htop", "top", "pidof", "nice",
            "kill", "watch", "pwdx", "taskset", "chrt", "ionice", "prlimit", "renice", "skill",
            "pkill", "nginx", "apache2", "psql", "mysql", "redis-cli", "memcached-tool", "rabbitmqctl",
            "docker", "kubectl", "helm", "caddy", "haproxy", "traefik", "mongosh", "influx", "etcdctl",
            "consul", "vault", "nomad", "elasticsearch", "kafka", "zookeeper", "pg_isready", "mysqladmin",
            "clickhouse", "sqlline", "minikube", "kind", "podman", "buildah", "skopeo", "nerdctl",
            "containerd", "git", "make", "gcc", "g++", "pytest", "node", "terraform", "packer",
            "ansible", "cmake", "ninja", "clang-tidy", "cppcheck", "black", "flake8", "mypy", "eslint",
            "prettier", "tsc", "trivy", "sonarqube-scanner", ".vscode-server", ".cursor-server",
            ".windsurf-server", ".jb-server", "sftp-server", "scp -t", "rsync", "ssh-keygen", "ssh-copy-id",
            "ssh-add", "ssh -o", "ssh-keyscan", "ssh -t", "sftp", "code ", "id", "who", "w", "last",
            "lastlog", "groups", "sudo -l", "sudo chown", "sudo chmod", "sudo adduser", "sudo usermod",
            "chsh", "passwd", "crontab", "logrotate", "chage", "gpasswd", "deluser", "groupadd",
            "groupdel", "getent", "visudo", "pam-auth-update", "faillock", "pwck", "grpck", "setfacl",
            "getfacl", "setcap", "getcap", "lsattr", "chattr", "useradd", "userdel", "newusers",
            "vipw", "vigr", "lastb", "users", "finger", "clear", "history", "env", "export", "alias",
            "ssh ", "ssh-keysign", "ssh-pkcs11-helper", "gpg "
        ]
        
        first_token = raw_lower.split()[0] if raw_lower.split() else ""
        if (any(w in raw_lower for w in benign_prefixes) or first_token in benign_prefixes) and not raw_lower.startswith("dmesg -c"):
            return _commit("ROUTINE_COMMAND", 0, False, "Standard System Utility / Maintenance", {}, "LOW")

        # -------------------------------------------------------------
        # PHASE 4: AI SECURITY ENGINE ANOMALY / ZERO-DAY CLASSIFICATION
        # -------------------------------------------------------------
        if ai_res.get("is_attack"):
            verdict = ai_res.get("verdict", "ATTACK")
            title = ai_res.get("incident_title", "Cyber Threat Detected")
            cat = ai_res.get("incident_category", "AI_ANOMALY")
            urgency = ai_res.get("urgency", "HIGH")
            score = 75 if urgency == "CRITICAL" else 60
            return _commit(f"AI_{cat}", score, True, f"AI {verdict}: {title}", ai_res, urgency)

        return _commit("ROUTINE_COMMAND", 0, False, "Routine Normal User / Developer Activity", ai_res, "LOW")

    def sync_active_os_sessions(self):
        """
        Queries the OS for all active interactive terminal sessions (pts/0, pts/1, pts/2...)
        and maps them dynamically to authentic client IP addresses.
        """
        try:
            for u in psutil.users():
                term = u.terminal or "pts/0"
                host = u.host or "LOCAL_SYSTEM"
                username = u.name or "unknown"
                clean_term = term.replace("/dev/", "")
                
                with self.lock:
                    session_key = (username, host, clean_term)
                    if session_key not in self.active_sessions:
                        self.start_session(username, host, clean_term)
        except Exception:
            pass

    def sample_active_terminal_processes(self):
        """
        Samples active processes executing across terminal TTYs to catch non-sudo commands.
        Dynamically resolves parent SSH socket connections when sessions are unknown.
        """
        self.sync_active_os_sessions()

        siem_pid = os.getpid()
        siem_tty = ""
        try:
            siem_tty = (psutil.Process().terminal() or "").replace("/dev/", "")
        except Exception:
            pass

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    pid = proc.info.get('pid')
                    if not pid or pid == siem_pid or pid in self.seen_process_pids:
                        continue

                    # Skip SIEM child and descendant processes
                    try:
                        curr = proc
                        is_siem_descendant = False
                        for _ in range(4):
                            p = curr.parent()
                            if not p:
                                break
                            if p.pid == siem_pid:
                                is_siem_descendant = True
                                break
                            curr = p
                        if is_siem_descendant:
                            continue
                    except Exception:
                        pass

                    cmdline_list = proc.info.get('cmdline')
                    if not cmdline_list:
                        continue

                    p_name = (proc.info.get('name') or '').lower()
                    if p_name in [
                        "sshd", "systemd", "login", "init", "ps", "sleep", "journalctl",
                        "main.py", "main_warning_only.py", "manage.py", "auditd", "rsyslogd",
                        "cron", "crond", "snapd", "dbus-daemon", "polkitd", "networkmanager"
                    ]:
                        continue

                    cmdline_str = " ".join(cmdline_list).strip()
                    if not cmdline_str:
                        continue

                    cmdline_lower = cmdline_str.lower()
                    if any(util in cmdline_lower for util in [
                        "manage.py", "main.py", "main_warning_only.py", "simulate_test.py",
                        "landscape-sysinfo", "update-notifier", "update-motd", "motd-news",
                        "apt-check", "gpg-agent", "ssh-agent", "dbus", "snapd", "cloud-init", "locale", "dircolors",
                        "ubuntu-advantage", "apt-esm-hook", "fwupd", "hwe-eol", "esm-cache", "lesspipe",
                        "motd.ubuntu.com", "ubuntu.com", "canonical",
                        "/etc/update-motd", "/usr/lib/ubuntu-advantage", "/usr/lib/update-notifier", "/usr/libexec",
                        "siem_audit"
                    ]):
                        continue

                    # Filter out interactive user login shells (unless running inline scripts via -c / -e)
                    cmd_tokens = [t.lower() for t in cmdline_list]
                    base_binary = os.path.basename(cmdline_list[0]).lower().lstrip("-")
                    if any(base_binary.startswith(s) for s in ["bash", "sh", "zsh", "dash", "csh", "tcsh", "fish", "login"]):
                        if not any(flag in cmd_tokens for flag in ["-c", "-e", "-i>&", "/dev/tcp"]):
                            continue

                    # Extract direct TTY device; IGNORE background daemons with no terminal
                    tty = None
                    try:
                        if hasattr(proc, 'terminal'):
                            tty = proc.terminal()
                    except Exception:
                        pass

                    if not tty:
                        continue

                    clean_tty = tty.replace("/dev/", "")
                    if clean_tty == siem_tty and p_name.startswith("python"):
                        continue

                    # 1. Match against known active sessions on this TTY
                    matched_session = None
                    with self.lock:
                        for (username, source_ip, session_tty), session in list(self.active_sessions.items()):
                            clean_session_tty = session_tty.replace("/dev/", "")
                            if clean_tty == clean_session_tty:
                                matched_session = (username, source_ip, session_tty)
                                break

                    # 2. If session is not pre-registered, resolve authentic remote client IP from SSH process tree
                    if not matched_session:
                        user_name = proc.info.get('username') or 'unknown'
                        source_ip = 'LOCAL_SYSTEM'
                        try:
                            curr_proc = proc
                            for _ in range(5):
                                if not curr_proc:
                                    break
                                parent = curr_proc.parent()
                                if parent and "sshd" in parent.name().lower():
                                    for conn in parent.connections(kind='inet'):
                                        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                                            source_ip = conn.raddr.ip
                                            break
                                    break
                                curr_proc = parent
                        except Exception:
                            pass
                        matched_session = (user_name, source_ip, clean_tty)

                    # 3. Process & analyze non-sudo command
                    target_user, target_ip, target_tty = matched_session
                    self.seen_process_pids.add(pid)
                    if len(self.seen_process_pids) > 10000:
                        self.seen_process_pids.clear()

                    self.record_command(username=target_user, source_ip=target_ip, command=cmdline_str, tty=target_tty)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass

    def flush_routine_buffer(self, session):
        """
        Flushes and summarizes buffered routine commands into a single log entry.
        """
        if not session["routine_buffer"]:
            return
            
        count = len(session["routine_buffer"])
        sample_cmds = ", ".join(session["routine_buffer"][:3])
        session["routine_buffer"].clear()

        summary_msg = f"Session [{session['session_id']}]: User '{session['username']}' executed {count} routine commands. (Samples: {sample_cmds}...)"
        self.logger.log_event("INFO", "SESSION_SUMMARY", "ROUTINE_ACTIVITY", session["source_ip"], summary_msg)

    def end_session(self, username, source_ip, tty="pts/0"):
        """
        Closes user session and flushes pending routine command buffers.
        """
        session_key = (username, source_ip, tty)
        now = time.time()
        
        with self.lock:
            if session_key in self.active_sessions:
                session = self.active_sessions[session_key]
                self.flush_routine_buffer(session)
                
                try:
                    with get_db_connection(self.db_name) as conn:
                        cursor = conn.cursor()
                        cursor.execute("UPDATE user_sessions SET logout_time = ?, status = 'ENDED' WHERE session_id = ?",
                            (now, session["session_id"]))
                        conn.commit()
                except Exception as e:
                    print(f"[-] Session Close Error: {e}")

                msg = f"User '{username}' logged out. (IP: {source_ip} | Terminal: {tty})"
                self.logger.log_event("NOTICE", "SESSION_TRACKER", "USER_LOGOUT", source_ip, msg)
                print(f"[*] [SESSION CLOSED] {msg}")
                
                del self.active_sessions[session_key]

    def check_idle_session_timeouts(self):
        """
        Kicks sessions exceeding IDLE_SESSION_TIMEOUT_SECONDS of inactivity.
        """
        now = time.time()
        timeout_seconds = getattr(config, 'IDLE_SESSION_TIMEOUT_SECONDS', 900)
        
        sessions_to_kick = []
        with self.lock:
            for session_key, session in list(self.active_sessions.items()):
                idle_time = now - session["last_activity_time"]
                if idle_time >= timeout_seconds:
                    sessions_to_kick.append((session_key, session, idle_time))

        for session_key, session, idle_time in sessions_to_kick:
            username = session["username"]
            source_ip = session["source_ip"]
            tty = session["tty"]
            idle_minutes = int(idle_time // 60)

            # Never kick local console sessions (LOCAL_SYSTEM / localhost) or protected IPs
            if source_ip in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"] or self.ban_manager.is_protected_ip(source_ip):
                continue

            print(f"\n[!] [KICKED DUE TO INACTIVITY] User: {username} | Terminal: {tty} | Idle Duration: {idle_minutes} Minutes")

            try:
                if os.name != 'nt':
                    clean_tty = tty.replace("/dev/", "")
                    is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
                    kill_cmd = f"pkill -9 -t {clean_tty}" if is_root else f"sudo -n pkill -9 -t {clean_tty}"
                    subprocess.run(kill_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                else:
                    print(f"[*] [Windows Simulation] Session for user '{username}' on terminal {tty} terminated.")
            except Exception as e:
                print(f"[-] Session Termination Error ({tty}): {e}")

            try:
                with get_db_connection(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE user_sessions SET logout_time = ?, status = 'INACTIVE_TIMEOUT_KICKED' WHERE session_id = ?",
                        (now, session["session_id"]))
                    conn.commit()
            except Exception as e:
                print(f"[-] Session Timeout Database Update Error: {e}")

            kick_msg = f"User '{username}' automatically kicked out after {idle_minutes} minutes of inactivity (idle session timeout)."
            self.logger.log_event("WARNING", "SESSION_TRACKER", "IDLE_SESSION_KICKED", source_ip, kick_msg)

            with self.lock:
                if session_key in self.active_sessions:
                    del self.active_sessions[session_key]

    def start(self):
        """
        Starts the continuous terminal process sampling and session timeout service.
        """
        print(f"[+] Terminal Process & Session Activity Tracker Active: {time.ctime()}")
        last_timeout_check = 0
        while self.is_running:
            try:
                # 1. High-speed process sampling (captures non-sudo terminal commands)
                self.sample_active_terminal_processes()

                # 2. Periodic idle timeout check (every 10 seconds)
                now = time.time()
                if now - last_timeout_check >= 10:
                    self.check_idle_session_timeouts()
                    last_timeout_check = now
            except Exception as e:
                print(f"[-] Session Tracking Loop Error: {e}")
            time.sleep(0.05)
