# -*- coding: utf-8 -*-
"""
==============================================================================
RFC 3164 / RFC 5424 ASYNCHRONOUS SYSLOG SERVER (modules/syslog_server.py)
==============================================================================
Listens for remote and local Syslog events over UDP and TCP sockets, parses
PRI, facility, severity, timestamps, hostname, application, and message.
Pushes normalized events directly into the SIEM processing pipeline.
"""

import socket
import threading
import time
import re
from datetime import datetime
import config
from modules.smart_logger import smart_logger

class SyslogServer:
    def __init__(self, host=config.SYSLOG_BIND_HOST, port=config.SYSLOG_PORT, event_callback=None):
        self.host = host
        self.port = port
        self.event_callback = event_callback
        self.running = False
        self.udp_sock = None
        self.tcp_sock = None
        self.threads = []
        
        # RFC 3164: <PRI>MMM DD HH:MM:SS HOSTNAME TAG[PID]: MESSAGE
        self.rfc3164_pattern = re.compile(
            r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+(?P<tag>[^:\s\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
        )
        # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        self.rfc5424_pattern = re.compile(
            r"^<(?P<pri>\d{1,3})>1\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<proc_id>\S+)\s+(?P<msg_id>\S+)\s+(?P<structured_data>\[.*?\]|-)\s*(?P<message>.*)$"
        )

    def parse_syslog(self, raw_text: str, source_ip: str) -> dict:
        """Parses RFC 3164 or RFC 5424 formatted syslog string into a structured dict."""
        raw_text = raw_text.strip()
        parsed = {
            "source_type": "syslog",
            "source_ip": source_ip,
            "raw": raw_text,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "facility": 1,
            "severity": 6,
            "hostname": source_ip,
            "app_name": "syslog",
            "pid": None,
            "message": raw_text
        }
        
        # Try RFC 5424 first
        m5424 = self.rfc5424_pattern.match(raw_text)
        if m5424:
            pri = int(m5424.group("pri"))
            parsed["facility"] = pri >> 3
            parsed["severity"] = pri & 7
            parsed["hostname"] = m5424.group("hostname")
            parsed["app_name"] = m5424.group("app_name")
            pid_str = m5424.group("proc_id")
            parsed["pid"] = int(pid_str) if pid_str.isdigit() else None
            parsed["message"] = m5424.group("message")
            return parsed

        # Try RFC 3164
        m3164 = self.rfc3164_pattern.match(raw_text)
        if m3164:
            pri = int(m3164.group("pri"))
            parsed["facility"] = pri >> 3
            parsed["severity"] = pri & 7
            parsed["hostname"] = m3164.group("hostname")
            parsed["app_name"] = m3164.group("tag")
            pid_str = m3164.group("pid")
            parsed["pid"] = int(pid_str) if pid_str and pid_str.isdigit() else None
            parsed["message"] = m3164.group("message")
            return parsed

        # Fallback for plain messages without PRI header
        return parsed

    def _handle_client_event(self, raw_data: bytes, client_ip: str):
        try:
            raw_text = raw_data.decode("utf-8", errors="ignore").strip()
            if not raw_text:
                return
            
            for line in raw_text.splitlines():
                if not line.strip():
                    continue
                event = self.parse_syslog(line, client_ip)
                if self.event_callback:
                    self.event_callback(event)
        except Exception as e:
            smart_logger.log("SYSLOG_ERROR", f"Syslog parse error from {client_ip}: {e}", level="WARNING")

    def _udp_worker(self):
        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(65535)
                self._handle_client_event(data, addr[0])
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    smart_logger.log("SYSLOG_UDP_ERR", f"UDP receive error: {e}", level="WARNING")

    def _tcp_client_handler(self, client_sock, client_ip):
        client_sock.settimeout(10.0)
        buffer = ""
        try:
            while self.running:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk.decode("utf-8", errors="ignore")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        self._handle_client_event(line.encode("utf-8"), client_ip)
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _tcp_worker(self):
        while self.running:
            try:
                client_sock, addr = self.tcp_sock.accept()
                t = threading.Thread(target=self._tcp_client_handler, args=(client_sock, addr[0]), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    smart_logger.log("SYSLOG_TCP_ERR", f"TCP accept error: {e}", level="WARNING")

    def start(self):
        """Starts the Syslog server listeners."""
        if self.running:
            return
        self.running = True
        
        # Start UDP
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((self.host, self.port))
            self.udp_sock.settimeout(1.0)
            t_udp = threading.Thread(target=self._udp_worker, name="Syslog-UDP-Server", daemon=True)
            t_udp.start()
            self.threads.append(t_udp)
            smart_logger.log("SYSLOG_START", f"Syslog UDP Listener active on {self.host}:{self.port}", level="INFO")
        except Exception as e:
            smart_logger.log("SYSLOG_BIND_FAIL", f"Failed to bind Syslog UDP {self.host}:{self.port}: {e}", level="ERROR")

        # Start TCP
        try:
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind((self.host, self.port))
            self.tcp_sock.listen(128)
            self.tcp_sock.settimeout(1.0)
            t_tcp = threading.Thread(target=self._tcp_worker, name="Syslog-TCP-Server", daemon=True)
            t_tcp.start()
            self.threads.append(t_tcp)
            smart_logger.log("SYSLOG_START", f"Syslog TCP Listener active on {self.host}:{self.port}", level="INFO")
        except Exception as e:
            smart_logger.log("SYSLOG_BIND_FAIL", f"Failed to bind Syslog TCP {self.host}:{self.port}: {e}", level="ERROR")

        # Keep calling thread alive for supervisor
        while self.running:
            time.sleep(1.0)

    def stop(self):
        """Stops the Syslog server."""
        self.running = False
        if self.udp_sock:
            try: self.udp_sock.close()
            except Exception: pass
        if self.tcp_sock:
            try: self.tcp_sock.close()
            except Exception: pass
        smart_logger.log("SYSLOG_STOP", "Syslog server stopped gracefully.", level="INFO")

# Singleton instance
syslog_server = SyslogServer()
