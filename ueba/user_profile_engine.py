# -*- coding: utf-8 -*-
"""
==============================================================================
UEBA USER & ENTITY BEHAVIOR PROFILER (modules/user_profile_engine.py)
==============================================================================
Constructs dynamic behavioral baselines for each user and entity, identifying
off-hours access anomalies, anomalous source IP clusters, and vocabulary shifts.
"""

import time
import json
import os
import threading
from datetime import datetime
from collections import defaultdict, Counter
import config
from modules.smart_logger import smart_logger

class UserProfileEngine:
    def __init__(self, profiles_db_path="data/user_profiles.json"):
        self.profiles_db_path = profiles_db_path
        self.lock = threading.Lock()
        
        # User -> {"known_ips": set(), "hourly_logins": [0]*24, "common_commands": Counter(), "last_seen": 0}
        self.profiles = defaultdict(lambda: {
            "known_ips": set(),
            "hourly_logins": [0] * 24,
            "day_logins": [0] * 7,
            "common_commands": Counter(),
            "last_seen": 0
        })
        self._load_profiles()

    def _load_profiles(self):
        if os.path.exists(self.profiles_db_path):
            try:
                with open(self.profiles_db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for u, p in data.items():
                        self.profiles[u]["known_ips"] = set(p.get("known_ips", []))
                        self.profiles[u]["hourly_logins"] = p.get("hourly_logins", [0]*24)
                        self.profiles[u]["day_logins"] = p.get("day_logins", [0]*7)
                        self.profiles[u]["common_commands"] = Counter(p.get("common_commands", {}))
                        self.profiles[u]["last_seen"] = p.get("last_seen", 0)
            except Exception as e:
                smart_logger.log("UEBA_LOAD_ERR", f"Failed to load user profiles: {e}", level="WARNING")

    def _save_profiles(self):
        os.makedirs(os.path.dirname(self.profiles_db_path) if os.path.dirname(self.profiles_db_path) else ".", exist_ok=True)
        serializable = {}
        for u, p in self.profiles.items():
            serializable[u] = {
                "known_ips": list(p["known_ips"]),
                "hourly_logins": p["hourly_logins"],
                "day_logins": p["day_logins"],
                "common_commands": dict(p["common_commands"].most_common(50)),
                "last_seen": p["last_seen"]
            }
        try:
            with open(self.profiles_db_path, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2)
        except Exception:
            pass

    def evaluate_login(self, username: str, source_ip: str, timestamp_dt: datetime = None) -> list:
        """
        Evaluates a login event against the user's historical baseline.
        Returns list of behavioral anomaly alerts.
        """
        if not username:
            return []

        if timestamp_dt is None:
            timestamp_dt = datetime.now()

        hour = timestamp_dt.hour
        weekday = timestamp_dt.weekday() # 0 = Monday, 6 = Sunday
        current_ts = time.time()
        anomalies = []

        with self.lock:
            profile = self.profiles[username]
            
            # 1. Off-Hours Anomaly Check (Unusual Access Time)
            is_work_hour = config.UEBA_WORK_HOURS_START <= hour <= config.UEBA_WORK_HOURS_END
            is_work_day = weekday in config.UEBA_WORK_DAYS
            
            # If user has a mature profile (>= 10 historical logins)
            total_logins = sum(profile["hourly_logins"])
            if total_logins >= 10:
                historical_hour_ratio = profile["hourly_logins"][hour] / total_logins
                if (not is_work_hour or not is_work_day) and historical_hour_ratio < 0.05:
                    anomalies.append({
                        "type": "OFF_HOURS_ACCESS_ANOMALY",
                        "severity": "MEDIUM",
                        "username": username,
                        "hour": hour,
                        "weekday": weekday,
                        "description": f"User {username} logged in during uncharacteristic off-hours ({hour:02d}:00, Day {weekday})."
                    })

            # 2. New Source IP Cluster Check
            if profile["known_ips"] and source_ip not in profile["known_ips"] and len(profile["known_ips"]) >= 3:
                anomalies.append({
                    "type": "NEW_SOURCE_IP_CLUSTER",
                    "severity": "LOW",
                    "username": username,
                    "new_ip": source_ip,
                    "known_ips": list(profile["known_ips"])[:5],
                    "description": f"User {username} logged in from a previously unseen IP: {source_ip}"
                })

            # Update Baseline Profile
            profile["known_ips"].add(source_ip)
            profile["hourly_logins"][hour] += 1
            profile["day_logins"][weekday] += 1
            profile["last_seen"] = current_ts

            if total_logins % 20 == 0:
                self._save_profiles()

        return anomalies

# Singleton instance
user_profile_engine = UserProfileEngine()
