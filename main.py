# -*- coding: utf-8 -*-
"""
==============================================================================
ENTERPRISE SECURITY & SYSTEM MONITORING ENGINE (main.py)
==============================================================================
This module orchestrates all 12 monitoring & defense subsystems:
1. Multi-Layer Dual-AI Threat & Zero-Day Anomaly Detection Engine
2. Multi-Backend Tiered Ban Manager (UFW + IPTables Kernel Drop)
3. 15-Minute Multi-Session & Hostile TTY Auto-Kick Tracker
4. 106-Rule High-Speed Log Parser & Logrotate Inode Watcher
5. Distributed Botnet Subnet / CIDR Defense Shield
6. File Integrity Monitoring (FIM - SHA256 Anti-Tamper Baseline)
7. Honeypot Decoy Port Traps (Telnet 23, ADB 5555, Redis 6379, etc.)
8. Outbound C2 & Reverse Shell Beaconing Guard
9. Hardware Telemetry Monitors (CPU, RAM, Disk, Network, GPU)
10. Automated Log Size Watcher & ZIP Compressor
11. Cryptographic HMAC-SHA256 Log Blockchain Sealer
12. Self-Healing Watchdog & Thread Supervisor (Auto-Resurrection)
==============================================================================
"""

import os
import time
import threading
import config

# Optimize Linux file descriptor limits (prevents EMFILE / 'Too many open files' error)
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

# Global Core Instances
logger = SmartLogger()
ban_man = BanManager(logger=logger)
ai_engine = AISecurityEngine()
session_tracker = UserSessionTracker(logger=logger, ai_engine=ai_engine, ban_manager=ban_man)
db_man = DataBaseManager(database_name="security_events.db")
alert_service = Alert()
supervisor = ThreadSupervisor(logger=logger)

def unified_pipeline_handler(raw_event: dict):
    """
    Central Enterprise Processing Pipeline for all ingested events (Syslog, REST, Local).
    Executes Normalization, Enrichment, Correlation, Sigma Rules, and UEBA Analytics.
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

    # 4. Cyber Threat Intelligence (CTI) IoC Matching
    if config.ENABLE_CTI_MATCHER:
        cti_match = cti_matcher.match_ip(src_ip) or cti_matcher.match_text_iocs(cmd_line) or cti_matcher.match_text_iocs(msg)
        if cti_match:
            alert_handler("CTI_THREAT_IOC_MATCH", src_ip or "UNKNOWN", f"CTI Match: {cti_match['threat']} (Actor: {cti_match['actor']})")
            risk_scorer.add_risk(src_ip, 80.0, f"CTI IoC Hit: {cti_match['threat']}", is_user=False)
            if src_ip and not config.DRY_RUN_MODE and not geoip_enricher.is_private_ip(src_ip):
                ban_man.ban_ip(src_ip, criticality="CRITICAL", reason=f"CTI IoC Match: {cti_match['threat']}")

    # 5. DGA Domain Detection
    if config.ENABLE_DGA_DETECTION and ("http" in cmd_line or "http" in msg or "dns" in msg):
        for token in (cmd_line + " " + msg).split():
            if "." in token and len(token) >= 8:
                dga_res = dga_detector.analyze(token)
                if dga_res.get("is_dga"):
                    alert_handler("DGA_MALWARE_DOMAIN", token, f"DGA C2 Domain Detected: {token} (Entropy: {dga_res['entropy']}, Score: {dga_res['score']})")
                    if src_ip:
                        risk_scorer.add_risk(src_ip, 65.0, f"DGA C2 Query: {token}", is_user=False)

    # 6. Stateful Complex Event Processing (CEP) Attack Chains
    if config.ENABLE_STATEFUL_CORRELATION:
        chain_alert = stateful_correlation_engine.process_event(ecs_doc)
        if chain_alert:
            alert_handler("CORRELATION_ATTACK_CHAIN", chain_alert.get("source_ip") or username or "UNKNOWN", chain_alert["description"])
            if src_ip:
                risk_scorer.add_risk(src_ip, 90.0, chain_alert["chain_name"], is_user=False)

    # 7. Sigma Detection Rules Evaluation
    if config.ENABLE_SIGMA_ENGINE:
        sigma_matches = sigma_engine.evaluate(ecs_doc)
        for sm in sigma_matches:
            alert_handler(f"SIGMA_{sm['rule_id']}", src_ip or username or "HOST", f"Sigma Rule Match: {sm['title']} (Level: {sm['level']})")
            if username:
                risk_scorer.add_risk(username, 70.0, f"Sigma Match: {sm['title']}", is_user=True)

    # 8. UEBA Behavioral Checks
    if config.ENABLE_UEBA:
        if username and src_ip:
            # A. Impossible Travel Detection
            imp_travel = impossible_travel_detector.evaluate(username, src_ip)
            if imp_travel:
                alert_handler("IMPOSSIBLE_TRAVEL_ANOMALY", username, imp_travel["description"])
                risk_scorer.add_risk(username, 85.0, "Impossible Travel Anomaly", is_user=True)

            # B. Dormant Account Awakening
            dormant_alert = dormant_account_detector.evaluate_activity(username, src_ip)
            if dormant_alert:
                alert_handler("DORMANT_ACCOUNT_AWAKEN", username, dormant_alert["description"])
                risk_scorer.add_risk(username, 60.0, "Dormant Account Awakening", is_user=True)

            # C. Off-Hours Access Profile
            ueba_anomalies = user_profile_engine.evaluate_login(username, src_ip)
            for u_anom in ueba_anomalies:
                alert_handler(u_anom["type"], username, u_anom["description"])
                risk_scorer.add_risk(username, 35.0, u_anom["type"], is_user=True)

def alert_handler(event_type, target, message):
    """
    Central Alert Handler for SIEM events.
    """
    level = "INFO"
    if any(k in event_type for k in ["ADVANCED_THREAT", "AI_ATTACK", "AI_ZERO_DAY", "ROOT", "SPOOFING", "BAN", "KICKED", "FILE_INTEGRITY", "HONEYPOT", "C2_", "CTI_", "IMPOSSIBLE_TRAVEL", "CORRELATION_"]):
        level = "CRITICAL"
    elif any(k in event_type for k in ["HIGH_", "OVERLOAD", "IDLE", "DGA_", "SIGMA_", "DORMANT_"]):
        level = "WARNING"
    elif any(k in event_type for k in ["ATTEMPT", "BLOCK", "OFF_HOURS"]):
        level = "ALERT"

    logger.log_event(level=level, module="SIEM_MONITOR", event_type=event_type, target=target, details=message)
    status_tag = logger.determine_operation_status(level, event_type)
    print(f"[{level}] [{status_tag}] [{event_type}] Target: {target} | {message}")

    if level in ["ALERT", "CRITICAL"] and alert_service.is_enabled():
        try:
            alert_service.send_alert(f"Subject: SIEM ALERT [{level}] - {event_type}\n\n{message}")
        except Exception:
            pass

if __name__ == "__main__":
    print("=================================================================")
    print("  ENTERPRISE SIEM & DEFENSE PLATFORM INITIALIZING (24 ENGINES)   ")
    print("=================================================================")

    # A. Initialize Log Directory, Database and Smart Logger
    os.makedirs("logs", exist_ok=True)
    db_man.start()
    logger.log_event("INFO", "SYSTEM", "SYSTEM_START", "LOCAL", "SIEM Monitoring & Defense Platform Initialized.")

    # B. Load Multi-Layer AI Security Models into Memory
    ai_engine.load_all_models()

    # C. Bind Unified Pipeline to Syslog, REST and eBPF Kernel Ingestion
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
    
    # Ingestion, Kernel & Memory Subsystems
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

    print("\n[+] All Ingestion, Processing, Correlation, UEBA and Defense Engines Active!")
    print(f"[+] Syslog Listener : UDP/TCP Port {config.SYSLOG_PORT}")
    print(f"[+] REST Ingest API : http://{config.REST_INGEST_HOST}:{config.REST_INGEST_PORT}/api/v1/ingest")
    print("[+] Activity logs cryptographically sealed to 'logs/activity_records.jsonl'.")
    print("[+] Press Ctrl+C to terminate the monitoring engine...\n")

    # F. Keep Main Thread Alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.log_event("INFO", "SYSTEM", "SYSTEM_STOP", "LOCAL", "SIEM Monitoring Service Terminated by User.")
        print("\n[*] Monitoring Service Terminated by User Request.")