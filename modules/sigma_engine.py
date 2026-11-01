# -*- coding: utf-8 -*-
"""
==============================================================================
SIGMA DETECTION RULES EVALUATION ENGINE (modules/sigma_engine.py)
==============================================================================
Parses and evaluates Sigma detection rule definitions against normalized
Elastic Common Schema (ECS) events, mapping matches to MITRE ATT&CK techniques.
"""

import os
import json
import re
import config
from modules.smart_logger import smart_logger

class SigmaEngine:
    def __init__(self, rules_dir=config.SIGMA_RULES_DIR):
        self.rules_dir = rules_dir
        self.rules = []
        self._load_or_create_seed_rules()

    def _load_or_create_seed_rules(self):
        """Loads Sigma rules from disk or generates built-in standard rules."""
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # Built-in High-Value Sigma Rules for Linux SIEM
        default_rules = [
            {
                "id": "sigma-lnx-001",
                "title": "Access to Sensitive Password Hashes (/etc/shadow)",
                "status": "production",
                "level": "high",
                "tags": ["attack.credential_access", "attack.t1003.008"],
                "detection": {
                    "selection": {
                        "process.command_line|contains": ["/etc/shadow", "/etc/gshadow", "/etc/security/opasswd"]
                    },
                    "condition": "selection"
                }
            },
            {
                "id": "sigma-lnx-002",
                "title": "Interactive Reverse Shell Execution via Netcat or Socat",
                "status": "production",
                "level": "critical",
                "tags": ["attack.execution", "attack.t1059.004"],
                "detection": {
                    "selection": {
                        "process.command_line|contains": ["nc -e", "ncat --ssl", "socat TCP", "mkfifo /tmp/f"]
                    },
                    "condition": "selection"
                }
            },
            {
                "id": "sigma-lnx-003",
                "title": "SUID / SGID Root Privilege Escalation Probe",
                "status": "production",
                "level": "medium",
                "tags": ["attack.discovery", "attack.t1083"],
                "detection": {
                    "selection": {
                        "process.command_line|contains": ["-perm -4000", "-perm -u=s", "chmod 4755", "chmod u+s"]
                    },
                    "condition": "selection"
                }
            },
            {
                "id": "sigma-lnx-004",
                "title": "Defense Evasion via Environment Variable or Base64 Pipe",
                "status": "production",
                "level": "high",
                "tags": ["attack.defense_evasion", "attack.t1027"],
                "detection": {
                    "selection": {
                        "process.command_line|contains": ["base64 -d | bash", "base64 -d | sh", "$IFS", "rev <<<"]
                    },
                    "condition": "selection"
                }
            },
            {
                "id": "sigma-lnx-005",
                "title": "Persistence via Cron Table Hijacking",
                "status": "production",
                "level": "high",
                "tags": ["attack.persistence", "attack.t1053.003"],
                "detection": {
                    "selection": {
                        "process.command_line|contains": ["/etc/crontab", "/etc/cron.d", "crontab -e", "crontab -l"]
                    },
                    "condition": "selection"
                }
            }
        ]

        # Save default rules if directory is empty
        for r in default_rules:
            rule_file = os.path.join(self.rules_dir, f"{r['id']}.json")
            if not os.path.exists(rule_file):
                try:
                    with open(rule_file, "w", encoding="utf-8") as f:
                        json.dump(r, f, indent=4)
                except Exception:
                    pass

        # Load all JSON rules in directory
        loaded_count = 0
        for f_name in os.listdir(self.rules_dir):
            if f_name.endswith(".json"):
                f_path = os.path.join(self.rules_dir, f_name)
                try:
                    with open(f_path, "r", encoding="utf-8") as f:
                        rule = json.load(f)
                        if "detection" in rule:
                            self.rules.append(rule)
                            loaded_count += 1
                except Exception:
                    pass
                    
        smart_logger.log("SIGMA_INIT", f"Loaded {len(self.rules)} Sigma detection rules.", level="INFO")

    def _get_nested_field(self, doc: dict, field_path: str):
        """Retrieves a nested field using dot notation (e.g. process.command_line)."""
        keys = field_path.split(".")
        val = doc
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return None
        return val

    def evaluate(self, ecs_event: dict):
        """
        Evaluates all loaded Sigma rules against an ECS document.
        Returns list of matched Sigma detection alerts.
        """
        matches = []
        if not isinstance(ecs_event, dict):
            return matches

        for rule in self.rules:
            try:
                detection = rule.get("detection", {})
                selection = detection.get("selection", {})
                
                is_match = True
                for key, expected_vals in selection.items():
                    # Parse modifiers (e.g. process.command_line|contains)
                    field_name = key
                    modifier = "exact"
                    if "|" in key:
                        field_name, modifier = key.split("|", 1)

                    actual_val = self._get_nested_field(ecs_event, field_name)
                    if actual_val is None:
                        is_match = False
                        break

                    actual_str = str(actual_val)
                    if not isinstance(expected_vals, list):
                        expected_vals = [expected_vals]

                    # Modifier matching
                    field_match = False
                    for exp in expected_vals:
                        exp_str = str(exp)
                        if modifier == "contains" and exp_str in actual_str:
                            field_match = True
                            break
                        elif modifier == "startswith" and actual_str.startswith(exp_str):
                            field_match = True
                            break
                        elif modifier == "endswith" and actual_str.endswith(exp_str):
                            field_match = True
                            break
                        elif modifier == "exact" and actual_str == exp_str:
                            field_match = True
                            break

                    if not field_match:
                        is_match = False
                        break

                if is_match:
                    matches.append({
                        "rule_id": rule.get("id"),
                        "title": rule.get("title"),
                        "level": rule.get("level", "medium").upper(),
                        "tags": rule.get("tags", []),
                        "event": ecs_event
                    })
            except Exception:
                continue

        return matches

# Singleton instance
sigma_engine = SigmaEngine()
