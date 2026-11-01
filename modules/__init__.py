# -*- coding: utf-8 -*-
"""
==============================================================================
MODULES COMPATIBILITY & RE-EXPORT LAYER (__init__.py)
==============================================================================
This module provides 100% transparent backwards compatibility by re-exporting
all classes and singletons from the new modular package architecture:
- core/
- ingestion/
- processing/
- detection/
- ueba/
- defense/
- system_monitors/
==============================================================================
"""

# Core Subsystems
from modules.ai_security_engine import AISecurityEngine, ai_security_engine
from modules.db_manager import get_db_connection
from modules.smart_logger import SmartLogger, smart_logger
from modules.integrity_guard import LogIntegrityGuard
from modules.canonicalizer import PayloadCanonicalizer
from modules.watchdog import ThreadSupervisor, ThreadSupervisor as Watchdog

# Ingestion Subsystems
from modules.syslog_server import SyslogServer, syslog_server
from modules.rest_ingest_api import RestIngestAPI, rest_ingest_api
from modules.ebpf_kernel_telemetry import EBPFKernelTelemetry, ebpf_kernel_telemetry
from modules.journal_reader import JournalReader
from modules.log_monitor import LogMonitor

# Processing Subsystems
from modules.ecs_normalizer import ECSNormalizer, ecs_normalizer
from modules.geoip_enricher import GeoIPEnricher, geoip_enricher
from modules.cti_matcher import CTIMatcher, cti_matcher
from modules.pii_masker import PIIMasker, pii_masker
from modules.log_parser_utils import LogParserUtils, PIDAttributionCache

# Detection Subsystems
from modules.stateful_correlation import StatefulCorrelationEngine, stateful_correlation_engine
from modules.sigma_engine import SigmaEngine, sigma_engine
from modules.dga_detector import DGADetector, dga_detector
from modules.c2_detector import C2Detector
from modules.memory_threat_hunter import MemoryThreatHunter, memory_threat_hunter
from modules.honeypot_trap import HoneypotTrap
from modules.file_integrity_monitor import FileIntegrityMonitor
from modules.lateral_movement import LateralMovementTracker, lateral_movement_tracker

# UEBA Subsystems
from modules.user_profile_engine import UserProfileEngine, user_profile_engine
from modules.user_session_tracker import UserSessionTracker
from modules.user_action_inspector import UserActionInspector, user_action_inspector
from modules.impossible_travel import ImpossibleTravelDetector, impossible_travel_detector
from modules.dormant_account import DormantAccountDetector, dormant_account_detector
from modules.risk_scorer import DynamicRiskScorer, risk_scorer

# Defense Subsystems
from modules.ban_manager import BanManager
from modules.subnet_shield import SubnetShield
from modules.whitelist_shield import WhitelistShield
from modules.alert import Alert

# System Observability Subsystems
from modules.cpu_info import CPU_Manager, CPU_Manager as CPU_Info
from modules.ram_monitor import RamMonitor
from modules.disk_monitor import DiskMonitor
from modules.network_monitor import NetworkMonitor
from modules.gpu_control import Gpu_Controller, Gpu_Controller as GPU_Control
from modules.file_control_zip import FileManager, FileManager as File_Control_Zip
