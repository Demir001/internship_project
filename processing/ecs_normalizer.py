# -*- coding: utf-8 -*-
"""
==============================================================================
ELASTIC COMMON SCHEMA (ECS) NORMALIZER (modules/ecs_normalizer.py)
==============================================================================
Converts heterogeneous log sources (Syslog, Auth, Sudo, REST, Systemd, Network)
into standard Elastic Common Schema (ECS v8.11) formatted structured records.
"""

import re
from datetime import datetime

class ECSNormalizer:
    ECS_VERSION = "8.11.0"

    @staticmethod
    def normalize(event: dict) -> dict:
        """Converts raw SIEM event envelope into a standardized ECS 8.11 document."""
        if not isinstance(event, dict):
            return {}

        now_iso = datetime.utcnow().isoformat() + "Z"
        raw_msg = event.get("raw") or event.get("message") or ""
        source_ip = event.get("source_ip") or event.get("ip") or event.get("src_ip")
        user = event.get("user") or event.get("username")
        cmd = event.get("command") or event.get("cmd")

        # Base ECS envelope
        ecs_doc = {
            "@timestamp": event.get("timestamp") or now_iso,
            "ecs": {"version": ECSNormalizer.ECS_VERSION},
            "event": {
                "kind": event.get("event_kind", "event"),
                "category": [event.get("category", "authentication" if "auth" in str(event.get("source_type")) else "host")],
                "type": [event.get("event_type", "info")],
                "action": event.get("action", "activity_recorded"),
                "outcome": event.get("outcome", "unknown"),
                "severity": event.get("severity", 1),
                "risk_score": event.get("risk_score", 0.0)
            },
            "host": {
                "hostname": event.get("hostname") or "localhost",
                "ip": [event.get("host_ip", "127.0.0.1")]
            },
            "source": {},
            "destination": {},
            "user": {},
            "process": {},
            "message": raw_msg,
            "tags": event.get("tags", ["siem", "staj4"])
        }

        # Source & Destination Network
        if source_ip:
            ecs_doc["source"]["ip"] = source_ip
            if event.get("source_port"):
                ecs_doc["source"]["port"] = int(event["source_port"])
        if event.get("dest_ip"):
            ecs_doc["destination"]["ip"] = event["dest_ip"]
            if event.get("dest_port"):
                ecs_doc["destination"]["port"] = int(event["dest_port"])

        # User Info
        if user:
            ecs_doc["user"]["name"] = str(user)

        # Process Info
        if cmd or event.get("pid"):
            if cmd:
                ecs_doc["process"]["command_line"] = str(cmd)
                parts = str(cmd).strip().split()
                if parts:
                    ecs_doc["process"]["name"] = parts[0]
            if event.get("pid"):
                try: ecs_doc["process"]["pid"] = int(event["pid"])
                except Exception: pass
            if event.get("tty"):
                ecs_doc["process"]["tty"] = event["tty"]

        # Parse Common Linux Log Patterns if raw message is provided
        if raw_msg and not user:
            # SSH Accepted: Accepted password for user from 192.168.1.50 port 54321
            m_acc = re.search(r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)", raw_msg)
            if m_acc:
                ecs_doc["user"]["name"] = m_acc.group("user")
                ecs_doc["source"]["ip"] = m_acc.group("ip")
                ecs_doc["event"]["category"] = ["authentication"]
                ecs_doc["event"]["action"] = "ssh_login_success"
                ecs_doc["event"]["outcome"] = "success"

            # SSH Failed: Failed password for invalid user admin from 10.0.0.5
            m_fail = re.search(r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)", raw_msg)
            if m_fail:
                ecs_doc["user"]["name"] = m_fail.group("user")
                ecs_doc["source"]["ip"] = m_fail.group("ip")
                ecs_doc["event"]["category"] = ["authentication"]
                ecs_doc["event"]["action"] = "ssh_login_failed"
                ecs_doc["event"]["outcome"] = "failure"

            # Sudo: sudo: user : TTY=pts/0 ; COMMAND=/bin/cat
            m_sudo = re.search(r"sudo:\s+(?P<user>\S+)\s+:.*?COMMAND=(?P<cmd>.*)$", raw_msg)
            if m_sudo:
                ecs_doc["user"]["name"] = m_sudo.group("user")
                ecs_doc["process"]["command_line"] = m_sudo.group("cmd")
                ecs_doc["event"]["category"] = ["process", "privilege_escalation"]
                ecs_doc["event"]["action"] = "sudo_execution"

        # MITRE ATT&CK Mapping
        if event.get("mitre_technique"):
            ecs_doc["threat"] = {
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id": event["mitre_technique"],
                    "name": event.get("mitre_name", "")
                }
            }

        return ecs_doc

# Singleton
ecs_normalizer = ECSNormalizer()
