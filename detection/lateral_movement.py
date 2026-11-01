# -*- coding: utf-8 -*-
"""
==============================================================================
LATERAL MOVEMENT & INTERNAL RECONNAISSANCE TRACKER (modules/lateral_movement.py)
==============================================================================
Monitors internal LAN/VLAN network traffic to detect lateral traversal, internal
port fan-out scanning, and administrative protocol hopping (SSH, SMB, RDP).
"""

import time
import ipaddress
import threading
from collections import defaultdict, deque
import config
from modules.smart_logger import smart_logger

class LateralMovementTracker:
    def __init__(self, window_seconds=120, fanout_threshold=5):
        self.window_seconds = window_seconds
        self.fanout_threshold = fanout_threshold
        self.lock = threading.Lock()
        
        # Source IP -> deque of (timestamp, dest_ip, dest_port)
        self.internal_hops = defaultdict(deque)
        
        # High-risk administrative lateral movement ports
        self.admin_ports = {22: "SSH", 445: "SMB/RPC", 3389: "RDP", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 23: "Telnet"}

    def _is_internal(self, ip_str: str) -> bool:
        """Returns True if IP belongs to private internal subnet."""
        try:
            ip = ipaddress.ip_address(str(ip_str).strip())
            return ip.is_private and not ip.is_loopback
        except ValueError:
            return False

    def record_connection(self, src_ip: str, dst_ip: str, dst_port: int) -> dict:
        """
        Records an internal connection attempt and checks for lateral movement patterns.
        """
        if not src_ip or not dst_ip or not dst_port:
            return None

        # Only evaluate internal-to-internal lateral connections
        if not (self._is_internal(src_ip) and self._is_internal(dst_ip)):
            return None

        # Ignore self-connections
        if src_ip == dst_ip:
            return None

        current_time = time.time()
        with self.lock:
            history = self.internal_hops[src_ip]
            
            # Evict expired events
            while history and (current_time - history[0][0]) > self.window_seconds:
                history.popleft()

            history.append((current_time, dst_ip, int(dst_port)))

            # Distinct internal destination hosts in window
            distinct_hosts = {item[1] for item in history}
            target_ports = {item[2] for item in history}

            # 1. Check Internal Fan-out Scanning
            if len(distinct_hosts) >= self.fanout_threshold:
                alert = {
                    "type": "INTERNAL_PORT_SCAN_FANOUT",
                    "severity": "HIGH",
                    "source_ip": src_ip,
                    "target_count": len(distinct_hosts),
                    "targets": list(distinct_hosts)[:10],
                    "description": f"Internal host {src_ip} connected to {len(distinct_hosts)} distinct internal targets within {self.window_seconds}s (Lateral Scan)."
                }
                smart_logger.log("LATERAL_FANOUT", alert["description"], level="WARNING")
                return alert

            # 2. Check Rapid Administrative Hopping (SSH/SMB/RDP)
            admin_hits = [p for p in target_ports if p in self.admin_ports]
            if admin_hits and len(distinct_hosts) >= 3:
                proto_names = [self.admin_ports[p] for p in admin_hits]
                alert = {
                    "type": "LATERAL_ADMIN_HOPPING",
                    "severity": "CRITICAL",
                    "source_ip": src_ip,
                    "protocols": proto_names,
                    "target_count": len(distinct_hosts),
                    "description": f"Host {src_ip} performing rapid administrative hopping ({', '.join(proto_names)}) across {len(distinct_hosts)} internal servers."
                }
                smart_logger.log("LATERAL_HOPPING", alert["description"], level="CRITICAL")
                return alert

        return None

# Singleton instance
lateral_movement_tracker = LateralMovementTracker()
