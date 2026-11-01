# -*- coding: utf-8 -*-
"""
==============================================================================
SMART FALSE-POSITIVE WHITELIST SHIELD (whitelist_shield.py)
==============================================================================
This module recognizes authentic system daemon operations, observability sweeps,
OpenSSH routine preauth/session logs, and DevOps automation routines (Systemd,
Certbot, Logrotate, Prometheus, Dpkg, PostgreSQL checkpoints, Docker daemon,
SIEM firewall & pkill operations) to eliminate false alarms and prevent
premature SSH bans.
==============================================================================
"""

import re

# Pre-compiled high-performance benign signatures
KNOWN_BENIGN_PATTERNS = [
    # 1. SIEM Self-Operations & Firewall Maintenance Commands (Prevents Logging Loops)
    re.compile(r"COMMAND=.*(?:(?:/usr/sbin/|/usr/bin/|/sbin/|/bin/)?(?:ufw|iptables|ip6tables|pkill|ss|conntrack|journalctl)|python3?\s+(?:main\.py|manage\.py))"),
    re.compile(r"sudo:.*COMMAND=.*(?:ufw|iptables|ip6tables|pkill|ss\s+-K|conntrack\s+-D|journalctl)"),

    # 2. OpenSSH Routine Side-Logs & Successful Authentications (All Ciphers & Key Types)
    re.compile(r"sshd(?:\[\d+\])?: Accepted (?:password|publickey|keyboard-interactive|hostbased|gssapi-with-mic|certificate) for "),
    re.compile(r"sshd(?:\[\d+\])?: (?:Connection from|Connection closed|Connection reset|Received disconnect|Disconnected|Disconnected from).*"),
    re.compile(r"(?:Connection (?:from|closed|reset) by?|Received disconnect from|Disconnected from) \S+ port \d+"),
    re.compile(r"sshd(?:\[\d+\])?: pam_unix\(sshd:[^)]+\): session (?:opened|closed) for user"),
    re.compile(r"pam_unix\((?:sudo|systemd-user|login|su|sshd):[^)]+\): session (?:opened|closed) for user"),
    re.compile(r"sshd(?:\[\d+\])?: (?:Postponed|Found matching|Starting session|User child|Transferred|subsystem request|session_open|Authenticated to|userauth|kex_|banner exchange|dispatch_protocol_error|Authorized|Certificate|Close session|Failed none).*"),

    # 3. Remote IDE & Developer SSH Agent Handshakes (VS Code Remote, Cursor, JetBrains)
    re.compile(r"sshd\[\d+\]: subsystem request for sftp by user"),
    re.compile(r"COMMAND=.*(?:\.vscode-server|\.cursor-server|\.windsurf-server|vscode-remote|\.jb-server|\.idea-server|sftp-server|scp -t|rsync --server)"),

    # 4. Systemd, Auditd, MOTD & Kernel Login Events
    re.compile(r"type=(?:USER_LOGIN|CRED_ACQ|USER_START|USER_END|CRED_DISP|LOGIN|SERVICE_START|SERVICE_STOP)\s+msg=audit\(.*"),
    re.compile(r"systemd(?:-logind|-resolved|-timesyncd)?(?:\[\d+\])?: (?:Started Session|Starting Daily Cleanup|Reached target|Clock synchronized|Created slice|Starting Rotate log files|New session \d+ of user|Started User Manager|Stopping User Manager)"),
    re.compile(r"kernel: (?:\[\s*\d+\.\d+\] )?(?:usb|EXT4-fs|TCP: cubic|eth0: Link is Up|Memory:|thermal|audit:)"),
    re.compile(r"(?:landscape-sysinfo|update-notifier|50-motd-news|motd\.ubuntu\.com|apt-check)"),
    re.compile(r"NetworkManager(?:\[\d+\])?: <info>.*dhcp4.*state changed bound"),

    # 5. Package Management & Updates (Apt, Dpkg, Snap, PackageKit)
    re.compile(r"dpkg(?:\[\d+\])?: status installed \S+"),
    re.compile(r"systemd(?:\[\d+\])?: Started Daily apt download activities"),
    re.compile(r"packagekitd(?:\[\d+\])?: (?:Request process transaction completed|Transaction active)"),
    re.compile(r"freshclam(?:\[\d+\])?: daily\.cvd updated"),

    # 6. Certificate Renewal & Scheduled Maintenance (Certbot, Logrotate, Cron Daily)
    re.compile(r"certbot(?:\[\d+\])?: Renewal configuration file.*is valid"),
    re.compile(r"CRON(?:\[\d+\])?: \(root\) CMD \(.*certbot.*renew.*\)"),
    re.compile(r"CRON(?:\[\d+\])?: \(root\) CMD \(.*run-parts --report /etc/cron\.daily.*\)"),
    re.compile(r"logrotate(?:\[\d+\])?: ALERT syslog's size has reached"),

    # 7. Observability, Healthchecks & Metrics (Prometheus, KubeProbe)
    re.compile(r"prometheus(?:\[\d+\])?: level=info.*(?:Scrape loop completed|WAL segment loaded|Head GC completed)"),
    re.compile(r"GET /(?:metrics|healthz|livez|health|favicon\.ico|robots\.txt|sitemap\.xml) HTTP/1\.[01]\" 200"),
    re.compile(r"User-Agent: (?:Prometheus|KubeProbe|OpenTelemetry|Datadog Agent|Googlebot)"),

    # 8. Database Maintenance Checkpoints (PostgreSQL, MySQL, Redis)
    re.compile(r"postgres(?:\[\d+\])?:.*LOG: (?:checkpoint starting|checkpoint complete|autovacuum:|automatic analyze)"),
    re.compile(r"mysqld(?:\[\d+\])?:.*\[Note\] InnoDB: Buffer pool.*load completed"),
    re.compile(r"redis(?:\[\d+\])?:.*DB saved on disk; RDB snapshot created"),

    # 9. Safe Sudo Administration Commands
    re.compile(r"COMMAND=.*(?:/usr/bin/openssl x509 -in|/usr/sbin/nginx -t|/usr/bin/journalctl --vacuum-time|/usr/bin/git pull|/usr/bin/htop|/usr/bin/uptime|/usr/bin/free -h|/usr/bin/dmesg -T)")
]

from functools import lru_cache

class WhitelistShield:
    @classmethod
    @lru_cache(maxsize=4096)
    def is_known_benign(cls, log_line: str) -> bool:
        """
        Fast lookup to check if a log line represents a known legitimate system activity.
        LRU-cached for sub-microsecond evaluation of recurring benign daemon events.
        """
        if not log_line:
            return False

        for pattern in KNOWN_BENIGN_PATTERNS:
            if pattern.search(log_line):
                return True

        return False

