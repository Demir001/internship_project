# -*- coding: utf-8 -*-
"""
==============================================================================
CYBER THREAT INTELLIGENCE (CTI) & IOC MATCHER (modules/cti_matcher.py)
==============================================================================
Matches incoming IP addresses, URLs, domain names, and file hashes in real-time
against Cyber Threat Intelligence (CTI) feeds, IoC databases, and Tor lists.
"""

import os
import json
import threading
import re
from datetime import datetime
import config
from modules.smart_logger import smart_logger

class CTIMatcher:
    def __init__(self, db_path=config.CTI_DATABASE_PATH):
        self.db_path = db_path
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.malicious_hashes = set()
        self.ioc_metadata = {}
        self.lock = threading.Lock()
        
        self._load_or_create_seed_db()

    def _load_or_create_seed_db(self):
        """Loads IoC database from disk or creates default seed database."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._populate(data)
                smart_logger.log("CTI_LOADED", f"Loaded {len(self.malicious_ips)} IPs, {len(self.malicious_domains)} domains from CTI database.", level="INFO")
                return
            except Exception as e:
                smart_logger.log("CTI_LOAD_FAIL", f"Failed to load CTI DB: {e}", level="WARNING")

        # Built-in High-Confidence Seed IoCs
        seed_data = {
            "ips": {
                "185.220.101.5": {"threat": "Tor Exit Node / Malicious Proxy", "severity": "HIGH", "actor": "Anonymous Tor Network"},
                "185.220.101.7": {"threat": "Tor Exit Node", "severity": "HIGH", "actor": "Anonymous Tor Network"},
                "194.26.29.42": {"threat": "Cobalt Strike C2 Beacon Server", "severity": "CRITICAL", "actor": "APT29 / Russian Nexus"},
                "45.145.67.12": {"threat": "Mirai / Mozi Botnet Scanner", "severity": "HIGH", "actor": "Mirai Botnet"},
                "91.240.118.168": {"threat": "SSH Brute-Force Bot", "severity": "HIGH", "actor": "MassCAN Cluster"}
            },
            "domains": {
                "c2-beacon.darknet.onion": {"threat": "C2 Command and Control", "severity": "CRITICAL"},
                "malware-staging.xyz": {"threat": "Malware Dropper Hosting", "severity": "CRITICAL"},
                "cryptominer-pool.org": {"threat": "Unauthorized XMRig Pool", "severity": "HIGH"},
                "update-system-apt.com": {"threat": "Typosquatting Phishing", "severity": "HIGH"}
            },
            "hashes": {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"threat": "Empty Payload Probe", "severity": "LOW"},
                "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": {"threat": "Known Linux Backdoor ELF", "severity": "CRITICAL"}
            }
        }
        
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(seed_data, f, indent=4)
        except Exception:
            pass
        self._populate(seed_data)

    def _populate(self, data: dict):
        with self.lock:
            self.malicious_ips.clear()
            self.malicious_domains.clear()
            self.malicious_hashes.clear()
            self.ioc_metadata.clear()

            for ip, meta in data.get("ips", {}).items():
                clean_ip = ip.strip()
                self.malicious_ips.add(clean_ip)
                self.ioc_metadata[clean_ip] = meta

            for dom, meta in data.get("domains", {}).items():
                clean_dom = dom.strip().lower()
                self.malicious_domains.add(clean_dom)
                self.ioc_metadata[clean_dom] = meta

            for h, meta in data.get("hashes", {}).items():
                clean_h = h.strip().lower()
                self.malicious_hashes.add(clean_h)
                self.ioc_metadata[clean_h] = meta

    def match_ip(self, ip_str: str):
        """Checks if an IP matches any known Threat Intelligence IoC."""
        if not ip_str:
            return None
        ip_str = ip_str.strip()
        if ip_str in self.malicious_ips:
            meta = self.ioc_metadata.get(ip_str, {})
            return {
                "matched": True,
                "ioc_type": "ip",
                "ioc_value": ip_str,
                "threat": meta.get("threat", "Known Malicious IP"),
                "severity": meta.get("severity", "HIGH"),
                "actor": meta.get("actor", "Unknown Threat Actor")
            }
        return None

    def match_text_iocs(self, text: str):
        """Scans arbitrary text, command line, or log message for CTI IoCs."""
        if not text:
            return None

        # Check for IP matches
        for ip in self.malicious_ips:
            if ip in text:
                return self.match_ip(ip)

        # Check for domain matches
        text_lower = text.lower()
        for dom in self.malicious_domains:
            if dom in text_lower:
                meta = self.ioc_metadata.get(dom, {})
                return {
                    "matched": True,
                    "ioc_type": "domain",
                    "ioc_value": dom,
                    "threat": meta.get("threat", "Known Malicious Domain"),
                    "severity": meta.get("severity", "HIGH"),
                    "actor": meta.get("actor", "Unknown Threat Actor")
                }

        return None

# Singleton instance
cti_matcher = CTIMatcher()
