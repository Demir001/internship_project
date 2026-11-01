# -*- coding: utf-8 -*-
"""
==============================================================================
GRANULAR ROLE & PERMISSION-BASED ACCESS CONTROL (PBAC / RBAC) ENGINE
(permission_manager.py)
==============================================================================
Provides:
1. Atomic Permission Flags: READ (r), WRITE (w), EXECUTE (x), NETWORK (n), ADMIN (a).
2. Support for all 32 combinations (r, rw, rx, rwx, rwxn, rwxna, none, all, etc.).
3. Deep command AST/Token classifier to detect required permissions.
4. Fast in-memory caching and persistent JSON storage (data/user_permissions.json).
==============================================================================
"""

import os
import re
import json
import threading
import config

# Standard Permission Types
PERM_READ = "READ"       # r: View/Read files, logs, directories
PERM_WRITE = "WRITE"     # w: Create, modify, delete files & folders
PERM_EXECUTE = "EXECUTE" # x: Execute binaries, interpreters, scripts
PERM_NETWORK = "NETWORK" # n: Sockets, HTTP, SSH, download/upload, probes
PERM_ADMIN = "ADMIN"     # a: System administration, service control, sudo/root

ALL_PERMISSIONS = {PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_NETWORK, PERM_ADMIN}

# Permission Letter Mapping
PERM_CHAR_MAP = {
    'r': PERM_READ,
    'w': PERM_WRITE,
    'x': PERM_EXECUTE,
    'n': PERM_NETWORK,
    'a': PERM_ADMIN
}

class PermissionManager:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(PermissionManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, permissions_file=None):
        if self._initialized:
            return

        self.permissions_file = permissions_file or getattr(config, 'USER_PERMISSIONS_FILE', 'data/user_permissions.json')
        self.lock = threading.RLock()
        self.user_permissions = {}
        self._cmd_perm_cache = {}

        # Default system base permission assignments
        self.default_assignments = {
            "root": {PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_NETWORK, PERM_ADMIN},
            "admin": {PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_NETWORK, PERM_ADMIN},
            "devops": {PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_NETWORK, PERM_ADMIN},
            "user": {PERM_READ, PERM_WRITE, PERM_EXECUTE},
            "developer": {PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_NETWORK},
            "auditor": {PERM_READ},
            "guest": {PERM_READ}
        }

        self._load_permissions()
        self._initialized = True

    # --------------------------------------------------------------------------
    # STORAGE & PERSISTENCE
    # --------------------------------------------------------------------------

    def _load_permissions(self):
        try:
            if os.path.exists(self.permissions_file):
                with open(self.permissions_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for user, perms in data.items():
                            if isinstance(perms, list):
                                self.user_permissions[user] = set(perms)
        except Exception as e:
            print(f"[-] User Permissions Load Error: {e}")

    def _save_permissions(self):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.permissions_file)), exist_ok=True)
            serializable = {u: sorted(list(p)) for u, p in self.user_permissions.items()}
            with open(self.permissions_file, 'w', encoding='utf-8') as f:
                json.dump(serializable, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[-] User Permissions Save Error: {e}")

    # --------------------------------------------------------------------------
    # PARSING & HELPER UTILITIES
    # --------------------------------------------------------------------------

    @staticmethod
    def parse_permissions_string(perm_input: str) -> set:
        """
        Parses arbitrary permission input into a clean set of PERM_* flags.
        Supports:
          - Flags: 'r', 'rw', 'rwx', 'rwxn', 'rwxna'
          - Word keywords: 'read', 'write', 'execute', 'network', 'admin', 'all', 'none'
          - Comma/space/pipe/plus-separated: 'read,write,execute'
        """
        if not perm_input:
            return set()

        raw = perm_input.strip().lower()
        if raw in ["all", "full", "*"]:
            return set(ALL_PERMISSIONS)
        if raw in ["none", "restricted", "-", "0"]:
            return set()

        # Word synonyms mapping
        WORD_MAP = {
            "read": PERM_READ, "r": PERM_READ,
            "write": PERM_WRITE, "w": PERM_WRITE,
            "exec": PERM_EXECUTE, "execute": PERM_EXECUTE, "x": PERM_EXECUTE,
            "net": PERM_NETWORK, "network": PERM_NETWORK, "n": PERM_NETWORK,
            "adm": PERM_ADMIN, "admin": PERM_ADMIN, "sudo": PERM_ADMIN, "a": PERM_ADMIN
        }

        # Check single full word
        if raw in WORD_MAP:
            return {WORD_MAP[raw]}

        result = set()
        
        # Check if comma, pipe, plus, or space separated
        if any(sep in raw for sep in [',', '|', ' ', '+']):
            tokens = re.split(r'[,\|\s\+]+', raw)
            for token in tokens:
                t = token.lower()
                if t in WORD_MAP:
                    result.add(WORD_MAP[t])
            return result

        # Check UNIX-style letter flags (only if all characters are valid flags: r, w, x, n, a, -)
        if all(c in PERM_CHAR_MAP or c == '-' for c in raw):
            for char in raw:
                if char in PERM_CHAR_MAP:
                    result.add(PERM_CHAR_MAP[char])
            return result

        # Fallback keyword search
        for word, perm in [("admin", PERM_ADMIN), ("network", PERM_NETWORK), ("execute", PERM_EXECUTE), ("write", PERM_WRITE), ("read", PERM_READ)]:
            if word in raw:
                result.add(perm)

        return result if result else {PERM_READ}

    @staticmethod
    def format_permissions_string(perms: set) -> str:
        """Formats permission set into human-readable compact 'rwxna' and verbose string."""
        if not perms:
            return "--- (NONE)"
        
        flags = [
            'r' if PERM_READ in perms else '-',
            'w' if PERM_WRITE in perms else '-',
            'x' if PERM_EXECUTE in perms else '-',
            'n' if PERM_NETWORK in perms else '-',
            'a' if PERM_ADMIN in perms else '-'
        ]
        short_flag = "".join(flags)
        verbose = ", ".join(sorted(list(perms)))
        return f"{short_flag} ({verbose})"

    # --------------------------------------------------------------------------
    # COMMAND PERMISSION CLASSIFIER
    # --------------------------------------------------------------------------

    def classify_required_permissions(self, command: str) -> set:
        """
        Contextually determines the required permission flags (READ, WRITE, EXECUTE,
        NETWORK, ADMIN) for any given Linux shell command string.
        """
        if not command:
            return set()

        raw = command.strip()
        if raw in self._cmd_perm_cache:
            return self._cmd_perm_cache[raw]

        req = set()
        lower = raw.lower()
        tokens = re.findall(r'\b[\w\.\-/]+\b', lower)
        first_token = tokens[0] if tokens else ""
        base_binary = os.path.basename(first_token)

        # 1. ADMIN Permission Requirements
        if any(w in lower for w in [
            "sudo", "su -", "su root", "useradd", "userdel", "usermod", "groupadd",
            "groupdel", "gpasswd", "visudo", "iptables", "ip6tables", "ufw", "reboot",
            "shutdown", "init 0", "init 6", "systemctl restart", "systemctl stop",
            "systemctl start", "service ", "mount", "umount", "chroot",
            "setfacl", "chattr", "insmod", "modprobe", "rmmod", "auditctl"
        ]) or base_binary in ["sudo", "su", "useradd", "usermod", "userdel", "iptables", "ufw", "visudo", "passwd"]:
            req.add(PERM_ADMIN)

        # 2. NETWORK Permission Requirements
        if any(w in lower for w in [
            "curl", "wget", "nc ", "netcat", "ncat", "socat", "ping", "ssh ", "scp ",
            "sftp ", "rsync", "traceroute", "dig ", "nslookup", "host ", "netstat",
            "ss ", "telnet", "ftp ", "git clone", "git pull", "git push", "git fetch",
            "npm install", "pip install", "apt update", "apt install", "yum install",
            "dnf install", "docker pull", "docker push", "/dev/tcp", "/dev/udp",
            "socket.connect", "urllib", "requests"
        ]) or base_binary in ["curl", "wget", "nc", "netcat", "ncat", "socat", "ping", "ssh", "scp", "sftp", "rsync", "dig", "nslookup", "telnet", "ftp"]:
            req.add(PERM_NETWORK)

        # 3. WRITE Permission Requirements (File / Directory modifications)
        if any(w in lower for w in [
            "touch", "mkdir", "rm ", "rmdir", "cp ", "mv ", "nano", "vim", "vi ",
            "pico", "emacs", "sed -i", "chmod", "chown", "truncate", "tee ",
            "tar -c", "tar -x", "zip", "unzip", "gzip", "gunzip", "dd ",
            ">>", ">"
        ]) or any(sep in raw for sep in [">", ">>", "| tee"]) or base_binary in ["touch", "mkdir", "rm", "rmdir", "cp", "mv", "nano", "vim", "vi", "chmod", "chown"]:
            req.add(PERM_WRITE)

        # 4. EXECUTE Permission Requirements (Scripts, Interpreters, Compilers)
        if any(w in lower for w in [
            "python", "python3", "node", "bash", "sh ", "zsh", "dash", "perl",
            "ruby", "php", "gcc", "g++", "make", "cargo", "docker run", "docker exec",
            "npm start", "npm run", "npm test", "yarn", "pytest", "valgrind", "gdb",
            "./", ".sh", ".py", ".js", ".pl", ".rb"
        ]) or raw.startswith("./") or base_binary in ["python", "python3", "node", "bash", "sh", "zsh", "perl", "ruby", "php", "gcc", "make", "cargo", "docker"]:
            req.add(PERM_EXECUTE)

        # 5. READ Permission Requirements (File / Log / Status viewing)
        if any(w in lower for w in [
            "cat", "less", "more", "tail", "head", "grep", "egrep", "fgrep", "ls",
            "dir", "file", "stat", "diff", "cmp", "find", "wc", "sort", "uniq",
            "uptime", "free", "df", "du", "top", "htop", "ps", "who", "w", "whoami",
            "id", "hostname", "uname", "dmesg", "journalctl", "last", "lastlog",
            "history", "env", "pwd", "echo", "printf"
        ]) or base_binary in ["cat", "less", "more", "tail", "head", "grep", "ls", "file", "stat", "diff", "find", "ps", "top", "htop", "df", "du", "free", "uptime", "whoami", "id", "pwd"]:
            req.add(PERM_READ)

        # Fallback: If no specific requirement was detected, default to READ (safe inspection)
        if not req:
            req.add(PERM_READ)

        if len(self._cmd_perm_cache) > 2000:
            self._cmd_perm_cache.clear()
        self._cmd_perm_cache[raw] = req

        return req

    classify_command_requirements = classify_required_permissions

    # --------------------------------------------------------------------------
    # PERMISSION CHECK & ENFORCEMENT
    # --------------------------------------------------------------------------

    def get_user_permissions(self, username: str) -> set:
        """Returns the active permission set for the given user."""
        if not username:
            return {PERM_READ}

        clean_user = username.strip()
        with self.lock:
            if clean_user in self.user_permissions:
                return set(self.user_permissions[clean_user])
            
            # Check default system assignments
            if clean_user in self.default_assignments:
                return set(self.default_assignments[clean_user])

            # Default safe permissions for unconfigured users
            return {PERM_READ}

    def set_user_permissions(self, username: str, perms_input) -> set:
        """Sets and persists granular permissions for a user."""
        if not username:
            return set()

        if isinstance(perms_input, str):
            perms_set = self.parse_permissions_string(perms_input)
        elif isinstance(perms_input, (set, list, tuple)):
            perms_set = set(perms_input)
        else:
            perms_set = {PERM_READ}

        clean_user = username.strip()
        with self.lock:
            self.user_permissions[clean_user] = perms_set
            self._save_permissions()
            formatted = self.format_permissions_string(perms_set)
            print(f"[+] User '{clean_user}' permissions set to: {formatted}")
            return perms_set

    def check_command_permission(self, username: str, command: str) -> tuple[bool, set, set]:
        """
        Evaluates if the user is authorized to execute the given command.
        Returns: (is_allowed, missing_permissions, required_permissions)
        """
        user_perms = self.get_user_permissions(username)
        req_perms = self.classify_required_permissions(command)

        # If user has ADMIN, grant all permissions
        if PERM_ADMIN in user_perms:
            return True, set(), req_perms

        # Calculate missing permissions: req_perms - user_perms
        missing = req_perms - user_perms
        is_allowed = (len(missing) == 0)

        return is_allowed, missing, req_perms

    def list_all_permissions(self) -> dict:
        """Returns all configured user permissions."""
        with self.lock:
            combined = dict(self.default_assignments)
            combined.update(self.user_permissions)
            return combined

# Global Singleton Instance
permission_manager = PermissionManager()
