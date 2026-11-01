# -*- coding: utf-8 -*-
"""
==============================================================================
DORMANT / STALE ACCOUNT AWAKENING DETECTOR (modules/dormant_account.py)
==============================================================================
Monitors user accounts for prolonged periods of inactivity (>30 days). Flags
high-priority alerts when a long-dormant account suddenly reactivates.
"""

import time
import os
import json
import threading
from datetime import datetime
import config
from modules.smart_logger import smart_logger

class DormantAccountDetector:
    def __init__(self, db_path="data/dormant_accounts.json", threshold_days=config.DORMANT_ACCOUNT_DAYS_THRESHOLD):
        self.db_path = db_path
        self.threshold_seconds = threshold_days * 86400
        self.lock = threading.Lock()
        
        # User -> {"last_active_ts": float, "last_active_iso": str, "last_ip": str}
        self.account_activity = {}
        self._load_db()

    def _load_db(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self.account_activity = json.load(f)
            except Exception:
                pass

    def _save_db(self):
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.account_activity, f, indent=2)
        except Exception:
            pass

    def evaluate_activity(self, username: str, source_ip: str) -> dict:
        """
        Evaluates user login for dormant account reactivation.
        """
        if not username or username in ["root", "daemon", "nobody"]:
            return None

        current_ts = time.time()
        now_iso = datetime.utcnow().isoformat() + "Z"
        alert = None

        with self.lock:
            record = self.account_activity.get(username)
            if record:
                last_ts = record.get("last_active_ts", current_ts)
                inactive_duration = current_ts - last_ts
                
                if inactive_duration >= self.threshold_seconds:
                    days_inactive = round(inactive_duration / 86400.0, 1)
                    alert = {
                        "type": "DORMANT_ACCOUNT_AWAKENING",
                        "severity": "HIGH",
                        "username": username,
                        "source_ip": source_ip,
                        "days_inactive": days_inactive,
                        "last_active_date": record.get("last_active_iso", "Unknown"),
                        "description": f"Dormant Account Alert: Account '{username}' awakened after {days_inactive} days of zero activity."
                    }
                    smart_logger.log("DORMANT_AWAKEN", alert["description"], level="WARNING")

            # Update activity record
            self.account_activity[username] = {
                "last_active_ts": current_ts,
                "last_active_iso": now_iso,
                "last_ip": source_ip
            }
            self._save_db()

        return alert

# Singleton instance
dormant_account_detector = DormantAccountDetector()
