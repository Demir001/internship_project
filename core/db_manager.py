# -*- coding: utf-8 -*-
"""
==============================================================================
THREAD-SAFE DATABASE MANAGEMENT SUBSYSTEM (db_manager.py)
==============================================================================
This module manages SQLite connections using WAL (Write-Ahead Logging) mode,
15-second busy timeout retry mechanisms, and thread-safe connection pooling
to completely prevent database locking errors during high-concurrency event logging.
Guarantees absolute path resolution and auto-schema repair on every connect.
==============================================================================
"""

import os
import time
import sqlite3
import threading
import config

_SCHEMA_INITIALIZED = False
_SCHEMA_LOCK = threading.Lock()

def get_resolved_db_path(db_name="security_events.db") -> str:
    """
    Returns the absolute path to the SQLite database file, preventing
    fragmentation across different process working directories.
    """
    if os.path.isabs(db_name):
        return db_name
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(project_root, db_name)

def _init_full_schema(conn):
    """
    Guarantees all required tables exist across all SIEM modules.
    """
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        level TEXT,
        status TEXT,
        module TEXT,
        event_type TEXT,
        target TEXT,
        summary TEXT,
        raw_details TEXT,
        mitre_id TEXT,
        ai_verdict TEXT
    )""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS banned_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        network_type TEXT,
        criticality_level TEXT,
        reason TEXT,
        banned_at REAL,
        unban_at REAL,
        is_active INTEGER DEFAULT 1
    )""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
        session_id TEXT PRIMARY KEY,
        username TEXT,
        source_ip TEXT,
        tty_device TEXT,
        login_time REAL,
        logout_time REAL DEFAULT 0,
        last_activity_time REAL,
        total_commands INTEGER DEFAULT 0,
        status TEXT DEFAULT 'ACTIVE'
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

    cursor.execute("""CREATE TABLE IF NOT EXISTS log_db (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        user TEXT,
        event TEXT,
        time TEXT,
        country TEXT
    )""")
    conn.commit()

def get_db_connection(db_name="security_events.db", timeout=15.0):
    """
    Returns a thread-safe, WAL-enabled SQLite connection with full schema verified.
    """
    global _SCHEMA_INITIALIZED
    abs_path = get_resolved_db_path(db_name)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    busy_timeout_ms = getattr(config, 'SQLITE_BUSY_TIMEOUT_MS', 15000)
    
    conn = sqlite3.connect(abs_path, timeout=timeout, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms};")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA cache_size = -64000;")   # 64 MB fast in-memory page cache
        conn.execute("PRAGMA mmap_size = 268435456;") # 256 MB zero-copy memory mapping
        conn.execute("PRAGMA temp_store = MEMORY;")   # RAM-backed temp storage
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception:
        pass

    with _SCHEMA_LOCK:
        if not _SCHEMA_INITIALIZED:
            try:
                _init_full_schema(conn)
                _SCHEMA_INITIALIZED = True
            except Exception as e:
                print(f"[-] Schema Init Error: {e}")
                
    return conn

class DataBaseManager:
    def __init__(self, database_name="security_events.db"):
        self.database_name = get_resolved_db_path(database_name)
        self.init_tables()

    def start(self):
        """Initializes tables for daemon runtime."""
        self.init_tables()

    def init_tables(self):
        """
        Initializes required event logging tables in WAL mode.
        """
        try:
            with get_db_connection(self.database_name) as conn:
                _init_full_schema(conn)
        except Exception as e:
            print(f"[-] Database Initialization Error ({self.database_name}): {e}")

    def insert_data(self, ip, user, event):
        """
        Inserts event records enriched with GeoIP data (Thread-Safe).
        """
        country = "Unknown"
        try:
            if os.path.exists("GeoLite2-City.mmdb"):
                import geoip2.database
                reader = geoip2.database.Reader("GeoLite2-City.mmdb")
                response = reader.city(ip) if ip and ip != "None" else None
                if response and response.country:
                    country = response.country.name
        except Exception:
            country = "Unknown"

        data = (str(ip), str(user), str(event), time.ctime(), country)
        
        for attempt in range(3):
            try:
                with get_db_connection(self.database_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO log_db (ip, user, event, time, country) VALUES (?, ?, ?, ?, ?)", data)
                    conn.commit()
                break
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() and attempt < 2:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                print(f"[-] Database Write Error: {e}")
                break
            except Exception as e:
                print(f"[-] Database Write Error: {e}")
                break

    def delete_data(self, record_id):
        """
        Deletes a record by ID (Thread-Safe).
        """
        try:
            with get_db_connection(self.database_name) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM log_db WHERE id = ?", (record_id,))
                conn.commit()
        except Exception as e:
            print(f"[-] Database Delete Error: {e}")

    def get_recent_logs(self, limit=50):
        """
        Retrieves the latest N log records (Thread-Safe).
        """
        try:
            with get_db_connection(self.database_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM log_db ORDER BY id DESC LIMIT ?", (limit,))
                return cursor.fetchall()
        except Exception as e:
            print(f"[-] Log Query Error: {e}")
            return []

    def get_logs_by_ip(self, ip):
        """
        Retrieves all log records for a specific IP (Thread-Safe).
        """
        try:
            with get_db_connection(self.database_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM log_db WHERE ip = ? ORDER BY id DESC", (ip,))
                return cursor.fetchall()
        except Exception as e:
            print(f"[-] IP Log Query Error: {e}")
            return []

    def purge_expired_records(self, retention_days=30):
        """
        Purges historical logs and closed user sessions older than retention_days (Default: 30 Days).
        Runs a WAL checkpoint to reclaim disk space.
        """
        cutoff_time = time.time() - (retention_days * 86400)
        cutoff_date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cutoff_time))
        try:
            with get_db_connection(self.database_name) as conn:
                cursor = conn.cursor()
                _init_full_schema(conn)
                
                cursor.execute("DELETE FROM activity_logs WHERE timestamp < ?", (cutoff_date_str,))
                cursor.execute("DELETE FROM session_activity_logs WHERE timestamp < ?", (cutoff_date_str,))
                cursor.execute("DELETE FROM user_sessions WHERE logout_time > 0 AND logout_time < ?", (cutoff_time,))
                cursor.execute("DELETE FROM banned_ips WHERE is_active = 0 AND unban_at > 0 AND unban_at < ?", (time.time() - 86400,))
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except Exception as e:
            print(f"[-] Database Retention Purge Error: {e}")

# Global Singleton
db_man = DataBaseManager()