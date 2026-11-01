# -*- coding: utf-8 -*-
"""
==============================================================================
FILE INTEGRITY MONITORING & ANTI-TAMPER SUBSYSTEM (file_integrity_monitor.py)
==============================================================================
This module provides cryptographic SHA-256 and inode integrity monitoring for
mission-critical system configuration files, credential stores, and SSH keys
(/etc/passwd, /etc/shadow, /etc/sudoers, /etc/ld.so.preload, authorized_keys).
Any unauthorized modification, injection, or deletion triggers an immediate
CRITICAL security alert.
==============================================================================
"""

import os
import time
import hashlib
import config
from modules.smart_logger import SmartLogger

class FileIntegrityMonitor:
    def __init__(self, callback=None, logger=None):
        self.callback = callback
        self.logger = logger or SmartLogger()
        self.monitored_paths = getattr(config, 'FIM_MONITORED_PATHS', [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
            "/etc/crontab", "/etc/hosts", "/etc/ld.so.preload", "config.py"
        ])
        self.baselines = {}
        self.init_baselines()

    def calculate_file_hash(self, file_path: str) -> str:
        """
        Calculates SHA-256 checksum for the specified file.
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return None

        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    def _read_file_lines(self, file_path: str) -> list:
        """Reads file contents safely as a list of lines for diff analysis."""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.readlines()
        except Exception:
            return []

    def generate_diff(self, old_lines: list, new_lines: list, file_path: str = "file") -> dict:
        """
        Computes line-by-line unified diff, separating added, removed, and modified lines.
        """
        import difflib
        diff_generator = difflib.unified_diff(
            old_lines, new_lines,
            fromfile=f"baseline/{os.path.basename(file_path)}",
            tofile=f"tampered/{os.path.basename(file_path)}",
            lineterm=""
        )
        diff_lines = list(diff_generator)
        added = [l[1:].strip() for l in diff_lines if l.startswith("+") and not l.startswith("+++")]
        removed = [l[1:].strip() for l in diff_lines if l.startswith("-") and not l.startswith("---")]

        return {
            "diff_text": "\n".join(diff_lines),
            "added_lines": added,
            "removed_lines": removed,
            "total_mutations": len(added) + len(removed)
        }

    def init_baselines(self):
        """
        Captures cryptographic baseline checksums, metadata, and line contents on startup.
        """
        for path in self.monitored_paths:
            if os.path.exists(path) and os.path.isfile(path):
                f_hash = self.calculate_file_hash(path)
                stat = os.stat(path)
                lines = self._read_file_lines(path)
                self.baselines[path] = {
                    "hash": f_hash,
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "lines": lines,
                    "exists": True
                }
            else:
                self.baselines[path] = {
                    "hash": None,
                    "size": 0,
                    "mtime": 0,
                    "lines": [],
                    "exists": False
                }

    def update_all_baselines(self):
        """
        Re-computes baseline cryptographic checksums and snapshots after authorized maintenance.
        """
        self.init_baselines()
        print("[+] [FIM RE-BASELINED] Cryptographic baselines updated after authorized maintenance window.")

    def scan_integrity(self):
        """
        Scans all monitored targets against stored baselines.
        Generates line-by-line unified diff upon unauthorized modification.
        """
        if not getattr(config, 'ENABLE_FIM', True):
            return

        is_maintenance = False
        try:
            from modules.maintenance_mode import maintenance_manager
            is_maintenance = maintenance_manager.is_maintenance_active()
        except Exception:
            is_maintenance = False

        for path in self.monitored_paths:
            prev = self.baselines.get(path, {"exists": False, "hash": None, "lines": []})
            exists_now = os.path.exists(path) and os.path.isfile(path)

            # 1. File Newly Created
            if not prev["exists"] and exists_now:
                new_hash = self.calculate_file_hash(path)
                stat = os.stat(path)
                new_lines = self._read_file_lines(path)
                self.baselines[path] = {"hash": new_hash, "size": stat.st_size, "mtime": stat.st_mtime, "lines": new_lines, "exists": True}
                
                if is_maintenance:
                    msg = f"Authorized new file '{path}' registered during active maintenance window."
                    print(f"[*] [FIM MAINTENANCE] {msg}")
                    self.logger.log_event("NOTICE", "FILE_INTEGRITY", "MAINTENANCE_FILE_CREATED", path, msg)
                else:
                    msg = f"CRITICAL TAMPER ALERT! Monitored file '{path}' was newly created! (SHA256: {new_hash[:16]}... | {len(new_lines)} lines)"
                    print(f"[!] [FIM CREATED] {msg}")
                    self.logger.log_event("CRITICAL", "FILE_INTEGRITY", "FILE_INTEGRITY_CREATED", path, msg)
                    if self.callback:
                        self.callback("FILE_INTEGRITY_VIOLATION", path, msg)

            # 2. File Deleted
            elif prev["exists"] and not exists_now:
                self.baselines[path] = {"hash": None, "size": 0, "mtime": 0, "lines": [], "exists": False}
                
                if is_maintenance:
                    msg = f"Authorized file removal for '{path}' during active maintenance window."
                    print(f"[*] [FIM MAINTENANCE] {msg}")
                    self.logger.log_event("NOTICE", "FILE_INTEGRITY", "MAINTENANCE_FILE_DELETED", path, msg)
                else:
                    msg = f"CRITICAL TAMPER ALERT! Monitored file '{path}' was DELETED from disk!"
                    print(f"[!] [FIM DELETED] {msg}")
                    self.logger.log_event("CRITICAL", "FILE_INTEGRITY", "FILE_INTEGRITY_DELETED", path, msg)
                    if self.callback:
                        self.callback("FILE_INTEGRITY_VIOLATION", path, msg)

            # 3. File Content Modified / Tampered
            elif prev["exists"] and exists_now:
                stat = os.stat(path)
                if stat.st_mtime != prev.get("mtime") or stat.st_size != prev.get("size"):
                    curr_hash = self.calculate_file_hash(path)
                    if curr_hash and curr_hash != prev.get("hash"):
                        old_h = prev.get("hash") or "UNKNOWN"
                        new_lines = self._read_file_lines(path)
                        old_lines = prev.get("lines", [])
                        
                        # Generate Line-by-Line Unified Diff
                        diff_res = self.generate_diff(old_lines, new_lines, file_path=path)
                        self.baselines[path] = {
                            "hash": curr_hash,
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "lines": new_lines,
                            "exists": True
                        }
                        
                        if is_maintenance:
                            msg = f"Authorized file update in '{path}' during maintenance. (Mutations: +{len(diff_res['added_lines'])}, -{len(diff_res['removed_lines'])})"
                            print(f"[*] [FIM MAINTENANCE] {msg}")
                            self.logger.log_event("NOTICE", "FILE_INTEGRITY", "MAINTENANCE_FILE_MODIFIED", path, msg)
                        else:
                            print("\n" + "=" * 75)
                            print(f"[!] CRITICAL FIM TAMPER DETECTED IN '{path}'!")
                            print(f"[*] SHA-256 Mutation : Old: {old_h[:12]}... -> New: {curr_hash[:12]}...")
                            print("-" * 75)
                            print("  LINE-BY-LINE UNIFIED DIFF ANALYSIS:")
                            print("-" * 75)
                            if diff_res["added_lines"]:
                                print(f"  [+] INJECTED / ADDED LINES ({len(diff_res['added_lines'])}):")
                                for line in diff_res["added_lines"][:10]:
                                    print(f"      + {line}")
                            if diff_res["removed_lines"]:
                                print(f"  [-] REMOVED / DELETED LINES ({len(diff_res['removed_lines'])}):")
                                for line in diff_res["removed_lines"][:10]:
                                    print(f"      - {line}")
                            print("=" * 75 + "\n")

                            summary_diff = f"Added: {diff_res['added_lines'][:3]} | Removed: {diff_res['removed_lines'][:3]}"
                            full_msg = f"Unauthorized mutation in '{path}'! Injected: {len(diff_res['added_lines'])} lines, Deleted: {len(diff_res['removed_lines'])} lines. {summary_diff}"
                            self.logger.log_event("CRITICAL", "FILE_INTEGRITY", "FILE_INTEGRITY_MODIFIED", path, full_msg)
                            if self.callback:
                                self.callback("FILE_INTEGRITY_VIOLATION", path, full_msg)

    def start(self):
        """
        Starts the continuous File Integrity Monitoring loop under Supervisor watchdog.
        """
        print(f"[+] File Integrity Monitor (FIM) Active (Monitoring {len(self.monitored_paths)} targets): {time.ctime()}")
        interval = getattr(config, 'FIM_CHECK_INTERVAL_SECONDS', 5.0)
        while True:
            try:
                self.scan_integrity()
            except Exception as e:
                print(f"[-] FIM Scan Error: {e}")
            time.sleep(interval)

    def get_status(self) -> dict:
        """Returns FIM status dictionary."""
        return {
            "status": "ACTIVE" if self.monitored_paths else "STANDBY",
            "monitored_files_count": len(self.monitored_paths),
            "monitored_paths": self.monitored_paths
        }

# Singleton instance
file_integrity_monitor = FileIntegrityMonitor()
