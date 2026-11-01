#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
ENTERPRISE SIEM & DEFENSE PLATFORM - WARNING & AUDIT ONLY MODE
(main_warning_only.py)
==============================================================================
This executable runs the ENTIRE SIEM platform (all 12 engines, live journald,
live process monitoring, AI security inference, FIM, Honeypot, C2 Detector)
in PASSIVE AUDIT / WARNING-ONLY MODE.

- Real-Time Live Monitoring: ACTIVE
- Multi-Model AI Threat Detection: ACTIVE
- Terminal Threat Warning & Logs: ACTIVE
- Active Firewall IP Bans (UFW/IPTables): SUPPRESSED (Warning Only)
- Active Session Termination (pkill): SUPPRESSED (Warning Only)
==============================================================================
Usage:
  sudo python3 main_warning_only.py
==============================================================================
"""

import os
import sys
import time
import threading

# Force Dry-Run / Warning-Only Mode
import config
config.DRY_RUN_MODE = True

# Optimize Linux file descriptor limits
if os.name != 'nt':
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = min(65536, hard)
        if soft < target_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard))
    except Exception:
        pass

# Subsystem Imports
from modules.smart_logger import SmartLogger
from modules.ban_manager import BanManager
from modules.ai_security_engine import AISecurityEngine
from modules.user_session_tracker import UserSessionTracker
from modules.log_monitor import LogMonitor
from modules.file_integrity_monitor import FileIntegrityMonitor
from modules.honeypot_trap import HoneypotTrap
from modules.c2_detector import C2Detector
from modules.cpu_info import CPU_Manager
from modules.ram_monitor import RamMonitor
from modules.disk_monitor import DiskMonitor
from modules.network_monitor import NetworkMonitor
from modules.gpu_control import Gpu_Controller
from modules.file_control_zip import FileManager
from modules.db_manager import DataBaseManager
from modules.alert import Alert
from modules.watchdog import ThreadSupervisor

# Enterprise Sections 1, 2, 3, 4 Subsystems
from modules.syslog_server import syslog_server
from modules.rest_ingest_api import rest_ingest_server
from modules.ecs_normalizer import ecs_normalizer
from modules.geoip_enricher import geoip_enricher
from modules.cti_matcher import cti_matcher
from modules.pii_masker import pii_masker
from modules.stateful_correlation import stateful_correlation_engine
from modules.sigma_engine import sigma_engine
from modules.dga_detector import dga_detector
from modules.lateral_movement import lateral_movement_tracker
from modules.user_profile_engine import user_profile_engine
from modules.impossible_travel import impossible_travel_detector
from modules.dormant_account import dormant_account_detector
from modules.risk_scorer import risk_scorer
from modules.ebpf_kernel_telemetry import ebpf_telemetry_engine
from modules.memory_threat_hunter import memory_threat_hunter

# Global Core Instances (Dry-Run Mode Enabled)
logger = SmartLogger()
ban_man = BanManager(logger=logger)
ban_man.dry_run = True

ai_engine = AISecurityEngine()
session_tracker = UserSessionTracker(logger=logger, ai_engine=ai_engine, ban_manager=ban_man)
session_tracker.dry_run = True

db_man = DataBaseManager(database_name="security_events.db")
alert_service = Alert()
supervisor = ThreadSupervisor(logger=logger)

def unified_pipeline_handler(raw_event: dict):
    """
    Unified Processing Pipeline in Warning-Only Mode.
    """
    if not isinstance(raw_event, dict):
        return

    # 1. PII Masking
    if config.ENABLE_PII_MASKING:
        for k in ["raw", "message", "command"]:
            if k in raw_event and isinstance(raw_event[k], str):
                raw_event[k] = pii_masker.mask(raw_event[k])

    # 2. ECS Normalization
    ecs_doc = ecs_normalizer.normalize(raw_event) if config.ENABLE_ECS_NORMALIZER else raw_event

    # 3. GeoIP & ASN Enrichment
    if config.ENABLE_GEOIP_ENRICHMENT:
        ecs_doc = geoip_enricher.enrich_ecs_event(ecs_doc)

    src_ip = ecs_doc.get("source", {}).get("ip")
    username = ecs_doc.get("user", {}).get("name")
    cmd_line = ecs_doc.get("process", {}).get("command_line", "")
    msg = ecs_doc.get("message", "")

    # 4. CTI IoC Matching
    if config.ENABLE_CTI_MATCHER:
        cti_match = cti_matcher.match_ip(src_ip) or cti_matcher.match_text_iocs(cmd_line) or cti_matcher.match_text_iocs(msg)
        if cti_match:
            alert_handler("CTI_THREAT_IOC_MATCH", src_ip or "UNKNOWN", f"[AUDIT] CTI Match: {cti_match['threat']} (Actor: {cti_match['actor']})")
            risk_scorer.add_risk(src_ip, 80.0, f"CTI IoC Hit: {cti_match['threat']}", is_user=False)

    # 5. DGA Detection
    if config.ENABLE_DGA_DETECTION and ("http" in cmd_line or "http" in msg or "dns" in msg):
        for token in (cmd_line + " " + msg).split():
            if "." in token and len(token) >= 8:
                dga_res = dga_detector.analyze(token)
                if dga_res.get("is_dga"):
                    alert_handler("DGA_MALWARE_DOMAIN", token, f"[AUDIT] DGA C2 Domain: {token} (Score: {dga_res['score']})")

    # 6. Stateful Correlation
    if config.ENABLE_STATEFUL_CORRELATION:
        chain_alert = stateful_correlation_engine.process_event(ecs_doc)
        if chain_alert:
            alert_handler("CORRELATION_ATTACK_CHAIN", chain_alert.get("source_ip") or username or "UNKNOWN", f"[AUDIT] {chain_alert['description']}")

    # 7. Sigma Rules
    if config.ENABLE_SIGMA_ENGINE:
        sigma_matches = sigma_engine.evaluate(ecs_doc)
        for sm in sigma_matches:
            alert_handler(f"SIGMA_{sm['rule_id']}", src_ip or username or "HOST", f"[AUDIT] Sigma Rule Match: {sm['title']}")

    # 8. UEBA Checks
    if config.ENABLE_UEBA:
        if username and src_ip:
            imp_travel = impossible_travel_detector.evaluate(username, src_ip)
            if imp_travel:
                alert_handler("IMPOSSIBLE_TRAVEL_ANOMALY", username, f"[AUDIT] {imp_travel['description']}")

            dormant_alert = dormant_account_detector.evaluate_activity(username, src_ip)
            if dormant_alert:
                alert_handler("DORMANT_ACCOUNT_AWAKEN", username, f"[AUDIT] {dormant_alert['description']}")

            ueba_anomalies = user_profile_engine.evaluate_login(username, src_ip)
            for u_anom in ueba_anomalies:
                alert_handler(u_anom["type"], username, f"[AUDIT] {u_anom['description']}")

def alert_handler(event_type, target, message):
    """
    Central Alert Handler in Warning-Only Mode.
    """
    level = "INFO"
    if any(k in event_type for k in ["ADVANCED_THREAT", "AI_ATTACK", "AI_ZERO_DAY", "ROOT", "SPOOFING", "BAN", "KICKED", "FILE_INTEGRITY", "HONEYPOT", "C2_", "CTI_", "IMPOSSIBLE_TRAVEL", "CORRELATION_"]):
        level = "CRITICAL"
    elif any(k in event_type for k in ["HIGH_", "OVERLOAD", "IDLE", "DGA_", "SIGMA_", "DORMANT_"]):
        level = "WARNING"
    elif any(k in event_type for k in ["ATTEMPT", "BLOCK", "OFF_HOURS"]):
        level = "ALERT"

    logger.log_event(level=level, module="SIEM_AUDIT", event_type=event_type, target=target, details=message)
    status_tag = logger.determine_operation_status(level, event_type)
    print(f"[{level}] [{status_tag}] [{event_type}] Target: {target} | {message}")

    if level in ["ALERT", "CRITICAL"] and alert_service.is_enabled():
        try:
            alert_service.send_alert(f"Subject: SIEM WARNING [{level}] - {event_type}\n\n{message}")
        except Exception:
            pass

if __name__ == "__main__":
    print("=================================================================")
    print("  ENTERPRISE SIEM & DEFENSE PLATFORM - WARNING-ONLY AUDIT MODE   ")
    print("=================================================================")
    print("[*] STATUS: Passive Audit Mode Active (Zero Active Bans / Zero Session Kills).")
    print("[*] ALL 24 Engines will analyze real-time live events and log full warnings.")
    print("=================================================================\n")

    # A. Initialize Log Directory, Database and Smart Logger
    os.makedirs("logs", exist_ok=True)
    db_man.start()
    logger.log_event("INFO", "SYSTEM", "SYSTEM_START_AUDIT_MODE", "LOCAL", "SIEM Platform Initialized in Warning-Only Mode.")

    # B. Load Multi-Layer AI Security Models into Memory
    ai_engine.load_all_models()

    # C. Bind Unified Pipeline to Syslog, REST and eBPF Ingestion
    syslog_server.event_callback = unified_pipeline_handler
    rest_ingest_server.event_callback = unified_pipeline_handler
    ebpf_telemetry_engine.callback = unified_pipeline_handler
    memory_threat_hunter.callback = alert_handler
    memory_threat_hunter.ban_manager = ban_man

    # D. Instantiate All Monitoring & Defense Subsystems
    log_mon = LogMonitor(callback=alert_handler, ban_manager=ban_man, session_tracker=session_tracker, ai_engine=ai_engine)
    fim_mon = FileIntegrityMonitor(callback=alert_handler, logger=logger)
    honeypot = HoneypotTrap(ban_manager=ban_man, callback=alert_handler, logger=logger)
    c2_guard = C2Detector(ban_manager=ban_man, callback=alert_handler, logger=logger)
    cpu_mon = CPU_Manager(callback=alert_handler)
    ram_mon = RamMonitor(callback=alert_handler)
    disk_mon = DiskMonitor(callback=alert_handler)
    net_mon = NetworkMonitor(callback=alert_handler)
    gpu_mon = Gpu_Controller(callback=alert_handler)
    file_man = FileManager(file_path=config.LINUX_APP_LOG_PATH)

    # E. Register All Subsystems Under Self-Healing Watchdog
    supervisor.register_service("SessionTracker", session_tracker.start)
    supervisor.register_service("BanManager", ban_man.start)
    supervisor.register_service("LogMonitor", log_mon.start)
    supervisor.register_service("FileIntegrityMonitor", fim_mon.start)
    supervisor.register_service("HoneypotTrap", honeypot.start)
    supervisor.register_service("C2Detector", c2_guard.start)
    supervisor.register_service("CpuMonitor", cpu_mon.start)
    supervisor.register_service("RamMonitor", ram_mon.start)
    supervisor.register_service("DiskMonitor", disk_mon.start)
    supervisor.register_service("NetworkMonitor", net_mon.start)
    supervisor.register_service("GpuMonitor", gpu_mon.start)
    supervisor.register_service("FileManager", file_man.start)
    
    if config.ENABLE_SYSLOG_SERVER:
        supervisor.register_service("SyslogServer", syslog_server.start)
    if config.ENABLE_REST_INGEST:
        supervisor.register_service("RestIngestApi", rest_ingest_server.start)
    if getattr(config, 'ENABLE_EBPF_TELEMETRY', True):
        supervisor.register_service("EBPFKernelTelemetry", ebpf_telemetry_engine.start)
    if getattr(config, 'ENABLE_MEMORY_HUNTER', True):
        supervisor.register_service("MemoryThreatHunter", memory_threat_hunter.start)

    # Launch Watchdog Supervisor Loop in Background
    threading.Thread(target=supervisor.supervise_loop, daemon=True).start()

    print("\n[+] All 24 Defense & Monitoring Engines, AI Core, and Watchdog Active in WARNING-ONLY Mode!")
    print(f"[+] Syslog Listener : UDP/TCP Port {config.SYSLOG_PORT}")
    print(f"[+] REST Ingest API : http://{config.REST_INGEST_HOST}:{config.REST_INGEST_PORT}/api/v1/ingest")
    print("[+] Activity logs cryptographically sealed to 'logs/activity_records.jsonl'.")
    print("[+] Press Ctrl+C to terminate the monitoring engine...\n")

    # F. Keep Main Thread Alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.log_event("INFO", "SYSTEM", "SYSTEM_STOP_AUDIT_MODE", "LOCAL", "SIEM Warning-Only Service Terminated by User.")
        print("\n[*] Monitoring Service Terminated by User Request.")

