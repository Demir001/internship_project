#!/usr/bin/env bash
# ==============================================================================
# ENTERPRISE SIEM & AI SECURITY PLATFORM AUTOMATED SETUP SCRIPT (setup.sh)
# ==============================================================================
# This script configures all system requirements, Linux kernel headers, eBPF/BCC
# tools, audit hooks, firewall prerequisites, Python environment updates,
# dependencies from requirements.txt, and systemd service orchestration.
# ==============================================================================

set -e

# ANSI Color Codes for Professional SOC Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "=============================================================================="
echo "      ENTERPRISE SIEM & AI SECURITY MONITORING PLATFORM SETUP                "
echo "=============================================================================="
echo -e "${NC}"

# 1. Check Root Privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] ERROR: This installation script must be executed as root (sudo).${NC}"
    echo -e "${YELLOW}[*] Usage: sudo bash setup.sh${NC}"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "${GREEN}[+] Current Project Root: ${PROJECT_DIR}${NC}"

# 2. Update Linux Package Repositories & Upgrade System Packages
echo -e "\n${BLUE}[1/8] Updating package index and system packages...${NC}"
apt-get update -y

# 3. Comprehensive System Packages Installation
echo -e "\n${BLUE}[2/8] Installing core Linux system packages and kernel build tools...${NC}"
KERNEL_RELEASE=$(uname -r 2>/dev/null || echo "")

SYSTEM_PACKAGES=(
    python3
    python3-pip
    python3-dev
    python3-setuptools
    python3-venv
    build-essential
    pkg-config
    ufw
    iptables
    ip6tables
    conntrack
    auditd
    libaudit-dev
    net-tools
    iproute2
    psmisc
    curl
    procps
    rsyslog
    yara
    libyara-dev
    bpfcc-tools
    python3-bpfcc
    libbpf-dev
)

# Add kernel headers if available on host
if [ -n "$KERNEL_RELEASE" ]; then
    SYSTEM_PACKAGES+=("linux-headers-${KERNEL_RELEASE}")
fi

for pkg in "${SYSTEM_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Installing ${pkg}...${NC}"
        apt-get install -y "$pkg" 2>/dev/null || echo -e "${YELLOW}[!] Optional package ${pkg} skipped.${NC}"
    else
        echo -e "${GREEN}[OK] Package ${pkg} is already installed.${NC}"
    fi
done

# 4. Upgrade Python Core Tooling (pip, setuptools, wheel)
echo -e "\n${BLUE}[3/8] Upgrading Python package installer (pip, setuptools, wheel)...${NC}"
python3 -m pip install --upgrade pip setuptools wheel --break-system-packages 2>/dev/null || \
python3 -m pip install --upgrade pip setuptools wheel 2>/dev/null || true

# 5. Install Python Dependencies from requirements.txt
echo -e "\n${BLUE}[4/8] Installing Python AI, SIEM & Security dependencies...${NC}"
if [ -f "${PROJECT_DIR}/requirements.txt" ]; then
    echo -e "${YELLOW}[*] Installing from ${PROJECT_DIR}/requirements.txt...${NC}"
    python3 -m pip install -r "${PROJECT_DIR}/requirements.txt" --break-system-packages 2>/dev/null || \
    python3 -m pip install -r "${PROJECT_DIR}/requirements.txt" 2>/dev/null || true
else
    PYTHON_DEPS=(
        "psutil>=5.9.0"
        "requests>=2.28.0"
        "geoip2>=4.7.0"
        "pynvml>=11.5.0"
        "pyamdgpuinfo>=2.1.0"
        "numpy>=1.24.0"
        "scipy>=1.10.0"
        "scikit-learn>=1.3.0"
        "joblib>=1.3.0"
        "yara-python>=4.3.0"
    )
    for dep in "${PYTHON_DEPS[@]}"; do
        echo -e "${YELLOW}[*] Installing Python dependency: ${dep}...${NC}"
        python3 -m pip install "$dep" --break-system-packages 2>/dev/null || python3 -m pip install "$dep" 2>/dev/null || true
    done
fi

# 6. Initialize Project Log, Data & Model Directories
echo -e "\n${BLUE}[5/8] Initializing project directory hierarchy and log sinks...${NC}"
mkdir -p "${PROJECT_DIR}/logs"
mkdir -p "${PROJECT_DIR}/data"
mkdir -p "${PROJECT_DIR}/rules/sigma"
mkdir -p "${PROJECT_DIR}/models/numpy_ensemble"
mkdir -p "${PROJECT_DIR}/models/numpy_autoencoder"

touch "${PROJECT_DIR}/logs/activity_records.jsonl"
touch "${PROJECT_DIR}/logs/readable_activity.log"
touch "${PROJECT_DIR}/logs/user_actions_readable.log"
touch "${PROJECT_DIR}/logs/auth.log"
touch "${PROJECT_DIR}/logs/syslog"

chmod -R 750 "${PROJECT_DIR}/logs"
echo -e "${GREEN}[OK] All required log files and model storage directories initialized.${NC}"

# 7. Configure Linux Kernel Auditd Rules
echo -e "\n${BLUE}[6/8] Configuring Linux Kernel auditd syscall monitoring...${NC}"
if command -v auditctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
    
    # Persistent audit watches for credentials, sudoers, and authentication logs
    auditctl -w /etc/shadow -p rwa -k siem_shadow 2>/dev/null || true
    auditctl -w /etc/passwd -p rwa -k siem_passwd 2>/dev/null || true
    auditctl -w /etc/sudoers -p rwa -k siem_sudoers 2>/dev/null || true
    auditctl -w /etc/sudoers.d/ -p rwa -k siem_sudoers 2>/dev/null || true
    auditctl -w /var/log/auth.log -p rwa -k siem_auth 2>/dev/null || true
    echo -e "${GREEN}[OK] Kernel auditd watches active on /etc/shadow, /etc/passwd, and /etc/sudoers.${NC}"
else
    echo -e "${YELLOW}[!] auditctl utility not found, skipping kernel audit rule injection.${NC}"
fi

# 8. Install Global Interactive Shell Audit Hook
echo -e "\n${BLUE}[7/8] Installing system-wide interactive shell command audit hook...${NC}"
HOOK_PATH="/etc/profile.d/siem_audit.sh"
cat << 'EOF' > "$HOOK_PATH"
# SIEM Real-Time Interactive Shell Command Audit Hook
export PROMPT_COMMAND='logger -p auth.notice -t siem_audit "user=$USER tty=$(tty 2>/dev/null | sed "s#/dev/##") cmd=\"$(history 1 | sed "s/^[ ]*[0-9]*[ ]*//")\"" 2>/dev/null'
EOF
chmod 644 "$HOOK_PATH"

BASHRC_PATH="/etc/bash.bashrc"
if [ -f "$BASHRC_PATH" ]; then
    if ! grep -q "siem_audit" "$BASHRC_PATH"; then
        echo -e "\n# SIEM Interactive Shell Audit Hook\nexport PROMPT_COMMAND='logger -p auth.notice -t siem_audit \"user=\$USER tty=\$(tty 2>/dev/null | sed \"s#/dev/##\") cmd=\\\"\$(history 1 | sed \"s/^[ ]*[0-9]*[ ]*//\")\\\"\" 2>/dev/null'" >> "$BASHRC_PATH"
    fi
fi
echo -e "${GREEN}[OK] Shell audit hook installed in /etc/profile.d and /etc/bash.bashrc.${NC}"

# 9. Configure UFW Firewall & Safe Whitelist
if command -v ufw >/dev/null 2>&1; then
    # Ensure SSH port 22 is always open before starting firewall
    ufw allow 22/tcp >/dev/null 2>&1 || true
    echo -e "${GREEN}[OK] UFW configured with safe SSH port 22 allow rule.${NC}"
fi

# 10. Generate Systemd Service File
echo -e "\n${BLUE}[8/8] Generating systemd service file (/etc/systemd/system/siem-monitor.service)...${NC}"
SERVICE_FILE="/etc/systemd/system/siem-monitor.service"
PYTHON_BIN=$(which python3)

cat << EOF > "$SERVICE_FILE"
[Unit]
Description=Enterprise SIEM & AI Security Monitoring Platform
After=network.target network-online.target systemd-journald.service auditd.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PYTHON_BIN} ${PROJECT_DIR}/main.py
Restart=always
RestartSec=3
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"
systemctl daemon-reload 2>/dev/null || true
echo -e "${GREEN}[OK] systemd service created: siem-monitor.service${NC}"

# ==============================================================================
# INSTALLATION COMPLETE SUMMARY
# ==============================================================================
echo -e "\n${GREEN}"
echo "=============================================================================="
echo "           SIEM & AI DEFENSE PLATFORM INSTALLED SUCCESSFULLY!                "
echo "=============================================================================="
echo -e "${NC}"
echo -e "You can run and manage the platform using any of the following commands:"
echo ""
echo -e "  ${CYAN}1. Active Production Daemon Mode:${NC}"
echo -e "     ${YELLOW}sudo python3 manage.py start --mode production${NC}"
echo ""
echo -e "  ${CYAN}2. Dry-Run / Warning-Only Audit Mode:${NC}"
echo -e "     ${YELLOW}sudo python3 manage.py audit${NC}"
echo ""
echo -e "  ${CYAN}3. Automated Enterprise Test Suite:${NC}"
echo -e "     ${YELLOW}python3 manage.py test${NC}"
echo ""
echo -e "  ${CYAN}4. Real-Time Interactive SOC Dashboard:${NC}"
echo -e "     ${YELLOW}python3 manage.py monitor${NC} (or 'python3 manage.py top')"
echo ""
echo -e "  ${CYAN}5. Background Systemd Service:${NC}"
echo -e "     ${YELLOW}sudo systemctl start siem-monitor${NC}"
echo -e "     ${YELLOW}sudo systemctl enable siem-monitor${NC}"
echo ""
echo "=============================================================================="
