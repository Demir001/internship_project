# -*- coding: utf-8 -*-
"""
==============================================================================
DETECTION & CORRELATION PACKAGE (__init__.py)
==============================================================================
Provides threat detection and correlation engines: Stateful CEP attack chains,
Sigma detection rules, DGA detector, C2 reverse shell hunter, live memory YARA
hunter, honeypot traps, and lateral movement tracker.
==============================================================================
"""

from detection.stateful_correlation import StatefulCorrelationEngine, stateful_correlation_engine
from detection.sigma_engine import SigmaEngine, sigma_engine
from detection.dga_detector import DGADetector, dga_detector
from detection.c2_detector import C2Detector
from detection.memory_threat_hunter import MemoryThreatHunter, memory_threat_hunter
from detection.honeypot_trap import HoneypotTrap
from detection.file_integrity_monitor import FileIntegrityMonitor
from detection.lateral_movement import LateralMovementTracker, lateral_movement_tracker
