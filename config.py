# -*- coding: utf-8 -*-
"""
==============================================================================
SYSTEM AND SECURITY CONFIGURATION (config.py)
==============================================================================
"""

# 0. Operational Mode (Dry-Run / Warning-Only vs. Active Blocking)
DRY_RUN_MODE = False                     # Set True to evaluate threats and generate alerts without banning or kicking

# 1. System Resource Thresholds
CPU_USAGE_THRESHOLD = 85.0              # Overall CPU usage alert threshold (%)
CPU_USAGE_BY_CORE_THRESHOLD = 95.0      # Per-core CPU overload threshold (%)
CPU_IOWAIT_THRESHOLD = 20.0             # CPU Disk I/O wait bottleneck threshold (%)

RAM_USAGE_THRESHOLD = 85.0              # RAM usage alert threshold (%)
DISK_USAGE_READ_THRESHOLD = 100         # Disk read speed alert threshold (MB/s)
DISK_USAGE_WRITE_THRESHOLD = 100        # Disk write speed alert threshold (MB/s)
INTERNET_BANDWITH_USAGE_THRESHOLD = 100 # Network bandwidth alert threshold (MB/s)
GPU_USAGE_THRESHOLD = 85.0              # GPU/TPU resource alert threshold (%)

# 2. File and Archive Settings
FILE_SIZE_THRESHOLD = 5                 # Maximum log file size before rotation (MB)
CHECK_INTERVAL_SECONDS = 2              # Hardware metric sampling interval (Seconds)
LINUX_APP_LOG_PATH = "app.log"          # Application log path

# 3. Monitored System Log Files (Multi-File Real-Time Tailing)
SYSTEM_LOG_PATHS = [
    "/var/log/auth.log",      # Debian/Ubuntu SSH & Authentication Logs
    "/var/log/syslog",        # Debian/Ubuntu System, Network & Kernel Logs
    "/var/log/secure",        # RHEL/CentOS/Rocky Linux Security Logs
    "/var/log/messages",      # RHEL/CentOS System Logs
    "/var/log/ufw.log",       # UFW Firewall Packet Drop Logs
    "/var/log/kern.log",      # Kernel & Hardware Logs
    "/var/log/audit/audit.log",# Linux Kernel Audit (Auditd) Syscall Logs
    "logs/auth.log",          # Local Test Auth Log
    "logs/syslog"             # Local Test Syslog Log
]

# 4. Session Inactivity Timeout (Auto-Kick)
IDLE_SESSION_TIMEOUT_SECONDS = 900      # 15 Minutes (900 seconds) idle session timeout

# 5. Cumulative Security Risk & Sliding Time Window
RISK_SCORE_THRESHOLD = 50               # Cumulative risk threshold required to trigger an automatic ban
TIME_WINDOW = 600                       # Sliding time window for risk calculation (10 Minutes / 600s)

# 6. Network Segmentation (Internal LAN vs. External WAN)
INTERNAL_SUBNETS = [
    "127.0.0.0/8",       # Localhost loopback
    "10.0.0.0/8",        # Class A Private Network
    "172.16.0.0/12",     # Class B Private Network
    "192.168.0.0/16",    # Class C Private Network
    "169.254.0.0/16",    # Link-Local Subnet
    "fc00::/7",          # IPv6 Unique Local Address (ULA)
    "fe80::/10"          # IPv6 Link-Local Subnet
]

PROTECTED_IPS = [
    "127.0.0.1", "::1", "localhost", "192.168.1.1", "10.0.0.1", "LOCAL_SYSTEM"
]

PROTECTED_USERS = [
    "root", "admin", "ubuntu", "debian", "user", "devops", "administrator"
]

# 7. Password Typo & SSH Ban Settings (SSH Banning Completely Disabled)
ENABLE_SSH_BAN = False                  # Completely disable IP bans for SSH authentication / connections
EXTERNAL_MAX_TYPOS = 999                # Unlimited tolerated attempts for external WAN IPs
INTERNAL_MAX_TYPOS = 999                # Unlimited tolerated attempts for internal LAN users
TYPO_TIME_INTERVAL_SECONDS = 1.0        # Rapid burst threshold
AUTH_FAIL_BAN_DURATION_SECONDS = 0      # 0 Seconds (No ban for failed SSH login attempts)

# 8. Tiered Ban Durations by Threat Level (Seconds)
BAN_DURATIONS_EXTERNAL = {
    "CRITICAL": 3600,                   # 60 Minutes (Reverse shell, C2, memory injection, rootkit)
    "HIGH": 1800,                       # 30 Minutes (Zero-day anomaly, SQLi, RCE, network probe)
    "MEDIUM": 300,                      # 5 Minutes (Password brute-force, protocol abuse - Max 5 mins)
    "LOW": 0                            # 0 Minutes (Tolerated typo, minor warning - No ban)
}

BAN_DURATIONS_INTERNAL = {
    "CRITICAL": 900,                    # 15 Minutes (Session termination & SSH port isolation)
    "HIGH": 300,                        # 5 Minutes (Temporary service rate-limiting)
    "MEDIUM": 300,                      # 5 Minutes (Temporary rate-limiting - Max 5 mins)
    "LOW": 0                            # 0 Minutes (Tolerated typo - No ban)
}

# 9. Email Alert Settings (Disabled by Default)
ENABLE_EMAIL_ALERTS = False              # Email alerts active/inactive
SMTP_ENABLED = False                     # Master SMTP switch
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your_email@gmail.com"
RECEIVER_EMAIL = "admin@example.com"
EMAIL_PASSWORD = "your_app_password"

# Backward compatibility aliases
SMTP_HOST = SMTP_SERVER
SMTP_MAIL_ADRESS = SENDER_EMAIL
SMTP_ALERT_MAIL = RECEIVER_EMAIL
SMTP_PASSWORD = EMAIL_PASSWORD

# 10. Advanced Multi-Backend Firewall & Kernel Enforcement
ENABLE_IPTABLES_FALLBACK = True           # Direct kernel-level IPTables drop (-I INPUT 1 -j DROP)
ENABLE_SESSION_KILL = True               # Terminate active TCP/SSH socket connections on ban
ENABLE_FIREWALL_SYNC_ON_STARTUP = True   # Re-synchronize active database bans into OS firewall on boot
SQLITE_BUSY_TIMEOUT_MS = 15000           # SQLite WAL busy timeout (15 seconds)
LOGROTATE_CHECK_INTERVAL_SECONDS = 2.0   # Inode and logrotate check frequency

# 11. Distributed Botnet & Subnet / CIDR Defense
ENABLE_SUBNET_SHIELD = True              # Enable /24 & /64 CIDR botnet aggregation
SUBNET_DISTINCT_IPS_THRESHOLD = 3        # Distinct IPs attacking from same /24 or /64 subnet
SUBNET_RISK_THRESHOLD = 75.0             # Cumulative risk score across subnet to trigger CIDR ban
SUBNET_BAN_DURATION_SECONDS = 7200       # 2 Hours ban for distributed botnet CIDR blocks

# 12. File Integrity Monitoring (FIM)
ENABLE_FIM = True                        # Enable real-time file integrity monitoring
FIM_CHECK_INTERVAL_SECONDS = 5.0         # Frequency of file checksum verification
FIM_MONITORED_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/ld.so.preload",
    "/root/.ssh/authorized_keys",
    "config.py"                          # Core configuration integrity watch
]

# 13. Honeypot Decoy Port Traps
ENABLE_HONEYPOT_TRAPS = True             # Enable decoy TCP port traps
HONEYPOT_PORTS = [23, 2323, 5555, 6379, 4444, 31337] # Decoy TCP ports to trap scanners (Avoids web dev ports 8080/8888)
HONEYPOT_BAN_DURATION_SECONDS = 86400    # 24 Hours ban for honeypot probe offenders

# 14. Cryptographic HMAC-SHA256 Log Integrity Chain
ENABLE_LOG_INTEGRITY_SEAL = True         # Cryptographically seal log lines with HMAC-SHA256
LOG_SECRET_KEY_PATH = ".log_secret.key"  # Secret HMAC key storage path

# 15. Outbound C2 & Reverse Shell Beaconing Guard
ENABLE_C2_DETECTION = True               # Enable active outbound socket inspection
C2_CHECK_INTERVAL_SECONDS = 3.0          # Sampling frequency for outbound sockets

# 16. Linux Kernel-Space eBPF Telemetry Sensor (Zero-Latency Syscall Hooks)
ENABLE_EBPF_TELEMETRY = True             # Hook execve, connect, openat directly in Linux kernel via eBPF

# 17. Live Process Memory & YARA Injection Hunter (Fileless Threat Guard)
ENABLE_MEMORY_HUNTER = True              # Scan /proc/<pid>/maps and mem for RWX/YARA shellcode stagers

# ==============================================================================
# SECTION 1: LOG TOPLAMA VE ENTEGRASYON (INGESTION)
# ==============================================================================
ENABLE_SYSLOG_SERVER = True              # Enable UDP/TCP Syslog listener
SYSLOG_BIND_HOST = "0.0.0.0"
SYSLOG_PORT = 5514                       # Default port (5514 avoids root binding, 514 on production)
SYSLOG_PROTOCOL = "BOTH"                 # "UDP", "TCP", or "BOTH"

ENABLE_REST_INGEST = True                # Enable RESTful Webhook log ingest API
REST_INGEST_HOST = "0.0.0.0"
REST_INGEST_PORT = 8088                  # HTTP port for /api/v1/ingest
REST_INGEST_API_KEY = ""                 # Optional Bearer Token for log ingestion authentication

# ==============================================================================
# SECTION 2: DATA PROCESSING, PARSING & ENRICHMENT
# ==============================================================================
ENABLE_ECS_NORMALIZER = True             # Convert all incoming events to Elastic Common Schema (ECS)
ENABLE_GEOIP_ENRICHMENT = True           # Enrich source/destination IPs with Geo coordinates, Country, ASN
ENABLE_CTI_MATCHER = True                # Enable Cyber Threat Intelligence (CTI/IoC) real-time matching
CTI_DATABASE_PATH = "data/cti_database.json" # Threat intelligence database path
ENABLE_PII_MASKING = True                # Mask Credit Cards, TCKN, Passwords and API Keys in log streams
ENABLE_REVERSE_DNS = True                # Enable non-blocking asynchronous reverse DNS resolver

# ==============================================================================
# SECTION 3: THREAT DETECTION & CORRELATION ENGINES
# ==============================================================================
ENABLE_STATEFUL_CORRELATION = True       # Complex Event Processing (CEP) attack chain tracker
STATEFUL_CORRELATION_WINDOW_SECONDS = 300# 5 Minutes time window to correlate multi-stage attack chains
ENABLE_SIGMA_ENGINE = True               # Enable open-source Sigma detection rules evaluator
SIGMA_RULES_DIR = "rules/sigma"          # Directory containing YAML/JSON Sigma detection rules
ENABLE_DGA_DETECTION = True              # Detect Domain Generation Algorithm malware queries
DGA_ENTROPY_THRESHOLD = 3.75             # Shannon entropy threshold for DGA detection
ENABLE_LATERAL_MOVEMENT = True           # Track internal network hops (SSH, SMB, RDP) across subnets

# ==============================================================================
# SECTION 4: UEBA & BEHAVIORAL ANALYTICS
# ==============================================================================
ENABLE_UEBA = True                       # Master switch for User & Entity Behavior Analytics
UEBA_WORK_HOURS_START = 8                # Work hours start (08:00)
UEBA_WORK_HOURS_END = 19                 # Work hours end (19:00)
UEBA_WORK_DAYS = [0, 1, 2, 3, 4]         # Work days (0=Monday ... 4=Friday)
IMPOSSIBLE_TRAVEL_SPEED_KMH = 800.0      # Maximum physical travel velocity threshold (km/h)
DORMANT_ACCOUNT_DAYS_THRESHOLD = 30      # Inactive days before flagging account reactivation
USER_RISK_DECAY_HOURS = 24.0             # Half-life for user/entity risk score decay

# ==============================================================================
# SECTION 5: ENTERPRISE MAINTENANCE DEFENSE, RBAC & PORT 22 HONEYPOT
# ==============================================================================

# 1. Maintenance Mode & Defense Authorization
ENABLE_MAINTENANCE_MODE = False          # When True, only authorized users/roles can execute commands
MAINTENANCE_ALLOWED_USERS = ["root", "admin", "devops"] # Whitelisted maintenance usernames
MAINTENANCE_ALLOWED_ROLES = ["ADMIN", "DEVOPS"]         # Whitelisted maintenance access roles
MAINTENANCE_REASON = "Routine Maintenance"              # Maintenance banner description
MAINTENANCE_STATE_FILE = "data/maintenance_state.json"  # Persistent maintenance configuration file
MAINTENANCE_AUTO_KILL_UNAUTHORIZED = True               # Instantly terminate unapproved terminal sessions

# 2. Real SSH Custom Port & Port 22 Decoy Honeypot Trap
REAL_SSH_PORT = 2222                     # Production SSH server port
ENABLE_PORT_22_HONEYPOT = True           # Turn Port 22 into an active deceptive honeypot trap
PORT_22_BAN_DURATION_SECONDS = 86400     # 24-Hour Zero-Tolerance firewall ban for Port 22 probes
HONEYPOT_PORTS = [22, 23, 2323, 5555, 6379, 4444, 31337] # Decoy listener ports
HONEYPOT_BAN_DURATION_SECONDS = 86400    # Default decoy ban duration
HONEYPOT_SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n" # Mimic real OpenSSH daemon

# 3. Role-Based Access Control (RBAC)
RBAC_DATABASE_FILE = "data/rbac_roles.json" # Granular user-to-role assignment storage
DEFAULT_USER_ROLES = {
    "root": "ADMIN",
    "admin": "ADMIN",
    "devops": "DEVOPS",
    "user": "OPERATOR",
    "auditor": "AUDITOR"
}

# ==============================================================================
# SECTION 6: ENTERPRISE MACRO RESILIENCE & PRODUCTION HARDENING
# ==============================================================================

# 1. Infrastructure Scanner & Monitoring Whitelists (Zabbix, Prometheus, Nessus)
INFRASTRUCTURE_SCANNER_IPS = [
    "10.0.0.50", "192.168.1.50", "127.0.0.1", "localhost"
]

# 2. Corporate Egress NAT & VPN Gateways (Guaranteed Network-Wide Protection)
TRUSTED_CORPORATE_EGRESS_IPS = [
    "198.51.100.1", "203.0.113.1"
]

# 3. Decoy Honeypot Tolerance & Informative Banner
PORT_22_TOLERANCE_ATTEMPTS = 2          # Grace attempts for IDE auto-reconnects (VS Code, PyCharm)
PORT_22_INFO_BANNER = "SSH-2.0-OpenSSH_8.9p1 NOTICE: Production SSH runs on Port 2222. Please update your client configuration.\r\n"

# 4. Historical Log Backfill & Replay Guard
LOG_BACKFILL_THRESHOLD_SECONDS = 900    # Logs older than 15 mins processed in audit-only mode (no live bans)

# 5. Non-Interactive System Daemon Accounts (Immune from Maintenance Lockouts)
SYSTEM_DAEMON_ACCOUNTS = [
    "cron", "systemd", "backup", "postgres", "mysql", "www-data", "nobody", "daemon"
]

# ==============================================================================
# SECTION 7: EMERGENCY HOST NETWORK CONTAINMENT & QUARANTINE
# ==============================================================================
ENABLE_HOST_CONTAINMENT = False              # Persistent state indicator
CONTAINMENT_STATE_FILE = "data/containment_state.json"
SOC_MANAGEMENT_IPS = [
    "127.0.0.1", "10.0.0.100", "192.168.1.100", "localhost"
]
CONTAINMENT_DEFAULT_REASON = "Emergency Active Threat Quarantine"

# ==============================================================================
# SECTION 8: ADVANCED RESOURCE ABUSE & CRYPTOMINER GUARD
# ==============================================================================
RESOURCE_GUARD_ENABLED = True
RESOURCE_CPU_THRESHOLD_PERCENT = 85.0        # Sustained CPU threshold (%)
RESOURCE_RAM_THRESHOLD_PERCENT = 90.0        # Sustained Memory threshold (%)
RESOURCE_DISK_MB_PER_SEC = 50.0              # Sustained Disk Write threshold (MB/s)
RESOURCE_NET_MB_PER_SEC = 20.0               # Sustained Network TX/RX rate (MB/s)
RESOURCE_SUSTAINED_WINDOW_SECONDS = 10       # Sustained duration before enforcement
RESOURCE_EXEMPT_ROLES = ["ADMIN", "DEVOPS"]
RESOURCE_EXEMPT_ACCOUNTS = [
    "root", "postgres", "mysql", "backup", "systemd", "redis", "nginx", "docker", "daemon"
]
RESOURCE_EXEMPT_BINARIES = [
    "mysqld", "postgres", "redis-server", "nginx", "dockerd", "containerd",
    "python", "python3", "gcc", "g++", "rustc", "cargo", "npm", "rsync", "tar", "gzip"
]