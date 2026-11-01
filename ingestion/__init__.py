# -*- coding: utf-8 -*-
"""
==============================================================================
INGESTION PACKAGE (__init__.py)
==============================================================================
Provides log ingestion and telemetry collectors: RFC 3164/5424 Syslog,
RESTful webhook endpoint, eBPF kernel sensor, systemd-journald streaming,
and local log tailing.
==============================================================================
"""

from ingestion.syslog_server import SyslogServer, syslog_server
from ingestion.rest_ingest_api import RestIngestAPI, rest_ingest_api
from ingestion.ebpf_kernel_telemetry import EBPFKernelTelemetry, ebpf_kernel_telemetry
from ingestion.journal_reader import JournalReader
from ingestion.log_monitor import LogMonitor
