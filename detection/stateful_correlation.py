# -*- coding: utf-8 -*-
"""
==============================================================================
STATEFUL COMPLEX EVENT PROCESSING (CEP) CORRELATION ENGINE (modules/stateful_correlation.py)
==============================================================================
Correlates multi-stage attack chains across heterogeneous log sources within
sliding time windows (e.g. Brute Force -> Successful Auth -> PrivEsc -> C2).
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime
import config
from modules.smart_logger import smart_logger

class StatefulCorrelationEngine:
    def __init__(self, window_seconds=config.STATEFUL_CORRELATION_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.lock = threading.Lock()
        
        # State trackers keyed by IP or User
        # Key -> deque of (timestamp, event_type, metadata)
        self.ip_event_history = defaultdict(deque)
        self.user_event_history = defaultdict(deque)
        self._prune_counter = 0

    def _clean_old_events(self, history_deque: deque, current_time: float):
        """Evicts events outside the correlation time window."""
        while history_deque and (current_time - history_deque[0][0]) > self.window_seconds:
            history_deque.popleft()

    def _periodic_memory_prune(self):
        """Periodically cleans empty deque keys to prevent unbounded memory growth."""
        self._prune_counter += 1
        if self._prune_counter % 500 == 0:
            for k in list(self.ip_event_history.keys()):
                if not self.ip_event_history[k]:
                    del self.ip_event_history[k]
            for k in list(self.user_event_history.keys()):
                if not self.user_event_history[k]:
                    del self.user_event_history[k]

    def correlate_event(self, ecs_event: dict, current_time: float = None) -> dict:
        """
        Ingests an ECS event and evaluates stateful multi-stage correlation chains.
        Includes historical backfill protection and monotonic drift immunity.
        """
        if not ecs_event:
            return None

        # 1. Historical Backfill Guard: Ignore replay logs older than threshold
        if current_time is None:
            evt_ts = ecs_event.get("@timestamp")
            if evt_ts:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(evt_ts.replace("Z", "+00:00"))
                    diff = time.time() - dt.timestamp()
                    if diff > getattr(config, 'LOG_BACKFILL_THRESHOLD_SECONDS', 900):
                        return None
                except Exception:
                    pass
            current_time = time.monotonic()

        source_ip = ecs_event.get("source", {}).get("ip")
        user = ecs_event.get("user", {}).get("name")
        action = ecs_event.get("event", {}).get("action", "")
        cmd = ecs_event.get("process", {}).get("command_line", "")
        threat = ecs_event.get("threat", {})

        alerts = []

        with self.lock:
            self._periodic_memory_prune()
            # 1. Record by IP
            if source_ip:
                history = self.ip_event_history[source_ip]
                self._clean_old_events(history, current_time)
                history.append((current_time, action, ecs_event))

                # Check Chain: Brute-Force -> Successful Login
                chain_brute_success = self._check_brute_force_then_success(history)
                if chain_brute_success:
                    alerts.append(chain_brute_success)

            # 2. Record by User
            if user:
                u_history = self.user_event_history[user]
                self._clean_old_events(u_history, current_time)
                u_history.append((current_time, action, ecs_event))

                # Check Chain: Login -> SUID / PrivEsc -> C2 or Malicious Execution
                chain_privesc = self._check_login_then_privesc_c2(u_history)
                if chain_privesc:
                    alerts.append(chain_privesc)

        if alerts:
            for alert in alerts:
                smart_logger.log(
                    "CORRELATION_ALERT",
                    f"Multi-Stage Attack Chain: {alert['chain_name']} | Details: {alert['description']}",
                    level="CRITICAL"
                )
            return alerts[0]
        return None

    def _check_brute_force_then_success(self, history: deque):
        """Detects: Multiple failed logins followed immediately by a successful login."""
        if not history:
            return None

        # Chain triggers ONLY when the latest arriving event is the successful login
        latest_ts, latest_action, latest_evt = history[-1]
        if "success" not in latest_action:
            return None

        fail_count = 0
        for ts, action, evt in list(history)[:-1]:
            if "failed" in action or "fail" in action:
                fail_count += 1

        if fail_count >= 3:
            alert = {
                "chain_name": "Brute-Force Followed by Successful Compromise",
                "severity": "CRITICAL",
                "mitre_tactic": "Initial Access / Credential Access",
                "mitre_technique": "T1110.001",
                "failed_attempts": fail_count,
                "target_user": latest_evt.get("user", {}).get("name"),
                "source_ip": latest_evt.get("source", {}).get("ip"),
                "description": f"{fail_count} failed login attempts followed by successful authentication."
            }
            history.clear()
            return alert
        return None

    def _check_login_then_privesc_c2(self, history: deque):
        """Detects: Login -> Privilege Escalation / SUID -> Reverse Shell / Exfiltration."""
        if len(history) < 3:
            return None

        latest_ts, latest_action, latest_evt = history[-1]
        is_terminal_threat = ("c2" in latest_action or "reverse_shell" in latest_action or latest_evt.get("event", {}).get("risk_score", 0) >= 80)
        if not is_terminal_threat:
            return None

        has_login = False
        has_privesc = False

        for ts, action, evt in list(history)[:-1]:
            if "login" in action or "accepted" in action:
                has_login = True
            if "sudo" in action or "privilege_escalation" in action or "suid" in action:
                has_privesc = True

        if has_login and has_privesc:
            alert = {
                "chain_name": "Full Cyber Kill Chain (Access -> Escalation -> C2/Execution)",
                "severity": "CRITICAL",
                "mitre_tactic": "Lateral Movement / Execution",
                "mitre_technique": "T1059.004 / T1548",
                "description": "User logged in, executed privilege escalation, and initiated high-risk payload/C2 connection."
            }
            history.clear()
            return alert
        return None

    # Backward compatibility alias
    process_event = correlate_event

# Singleton instance
stateful_correlation_engine = StatefulCorrelationEngine()
