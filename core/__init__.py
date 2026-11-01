# -*- coding: utf-8 -*-
"""
==============================================================================
CORE PACKAGE (__init__.py)
==============================================================================
Provides core infrastructure: AI security engine, SQLite WAL database,
multi-sink smart logger, HMAC-SHA256 log blockchain sealer, canonicalizer,
and self-healing process supervisor.
==============================================================================
"""

from core.ai_security_engine import AISecurityEngine, ai_security_engine
from core.db_manager import get_db_connection
from core.smart_logger import SmartLogger, smart_logger
from core.integrity_guard import LogIntegrityGuard
from core.canonicalizer import PayloadCanonicalizer
from core.watchdog import ThreadSupervisor, ThreadSupervisor as Watchdog
