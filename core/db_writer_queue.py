# -*- coding: utf-8 -*-
"""
==============================================================================
ASYNCHRONOUS BATCH DATABASE WRITER QUEUE (db_writer_queue.py)
==============================================================================
Solves SQLite single-writer lock contention by funneling all concurrent write
operations from Syslog, REST API, eBPF, FIM, and Shell hooks into an in-memory
FIFO queue, batched into atomic transactions by a single dedicated worker thread.
==============================================================================
"""

import os
import time
import queue
import sqlite3
import threading
import atexit
import config

class DBWriterQueue:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DBWriterQueue, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_name="security_events.db", max_queue_size=50000, batch_interval=0.05, batch_size=100):
        if self._initialized:
            return

        self.db_name = db_name
        self.queue = queue.Queue(maxsize=max_queue_size)
        self.batch_interval = batch_interval
        self.batch_size = batch_size
        self.is_running = True
        self.worker_thread = None
        self._lock = threading.RLock()
        self.circuit_breaker_tripped = False
        self.dropped_event_count = 0

        self.start_worker()
        atexit.register(self.shutdown)
        self._initialized = True

    def start_worker(self):
        with self._lock:
            if self.worker_thread is None or not self.worker_thread.is_alive():
                self.is_running = True
                self.worker_thread = threading.Thread(target=self._worker_loop, name="SIEM_DBWriter_Worker", daemon=True)
                self.worker_thread.start()

    def queue_write(self, sql: str, params: tuple = (), priority: bool = False) -> bool:
        """
        Enqueues a single SQL write task. Non-blocking with circuit-breaker protection.
        """
        if not self.is_running:
            self.start_worker()

        try:
            # Circuit breaker: if queue is >95% full, drop low-priority writes
            qsize = self.queue.qsize()
            if qsize > 47500 and not priority:
                self.dropped_event_count += 1
                if self.dropped_event_count % 100 == 1:
                    print(f"[-] [DB CIRCUIT BREAKER] High load detected: Dropped {self.dropped_event_count} low-priority logs.")
                return False

            self.queue.put((sql, params), timeout=0.1)
            return True
        except queue.Full:
            self.dropped_event_count += 1
            return False

    def queue_batch(self, sql: str, params_list: list) -> bool:
        """Enqueues multiple parameter sets for a single SQL statement."""
        for params in params_list:
            if not self.queue_write(sql, params):
                return False
        return True

    def _worker_loop(self):
        from modules.db_manager import get_db_connection, _init_full_schema

        while self.is_running or not self.queue.empty():
            tasks = []
            deadline = time.time() + self.batch_interval

            # Drain batch up to batch_size or until deadline
            while len(tasks) < self.batch_size and time.time() < deadline:
                try:
                    remaining_time = max(0.005, deadline - time.time())
                    item = self.queue.get(timeout=remaining_time)
                    tasks.append(item)
                    self.queue.task_done()
                except queue.Empty:
                    break

            if not tasks:
                time.sleep(0.01)
                continue

            # Execute batch inside single atomic transaction
            self._execute_batch(tasks)

    def _execute_batch(self, tasks):
        from modules.db_manager import get_db_connection

        for attempt in range(5):
            conn = None
            try:
                conn = get_db_connection(self.db_name, timeout=15.0)
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE TRANSACTION;")
                for sql, params in tasks:
                    try:
                        cursor.execute(sql, params)
                    except Exception as ex:
                        # Skip corrupted individual row but continue transaction
                        pass
                conn.commit()
                conn.close()
                return
            except sqlite3.OperationalError as e:
                if conn:
                    try:
                        conn.rollback()
                        conn.close()
                    except Exception:
                        pass
                if "locked" in str(e).lower() and attempt < 4:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                else:
                    print(f"[-] [DB WRITER ERROR] SQLite Batch Write Failed: {e}")
                    break
            except Exception as e:
                if conn:
                    try:
                        conn.rollback()
                        conn.close()
                    except Exception:
                        pass
                print(f"[-] [DB WRITER FATAL] {e}")
                break

    def flush(self):
        """Forces all currently queued writes to commit before proceeding."""
        while not self.queue.empty():
            time.sleep(0.02)
        time.sleep(0.06)

    def shutdown(self):
        """Flushes remaining queue and safely terminates the worker."""
        self.is_running = False
        if self.worker_thread and self.worker_thread.is_alive():
            try:
                self.flush()
                self.worker_thread.join(timeout=1.0)
            except Exception:
                pass

# Global Singleton
db_writer = DBWriterQueue()
