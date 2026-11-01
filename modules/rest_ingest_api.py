# -*- coding: utf-8 -*-
"""
==============================================================================
RESTFUL WEBHOOK / API LOG INGESTION SERVICE (modules/rest_ingest_api.py)
==============================================================================
Provides high-throughput HTTP REST API endpoints for SaaS, Cloud, and remote
agents to push logs directly into the SIEM pipeline over JSON.
Endpoints:
- POST /api/v1/ingest : Single or batch JSON log ingestion
- GET  /api/v1/health : Health check and queue status
"""

import os
import time
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import config
from modules.smart_logger import smart_logger

class RestIngestHandler(BaseHTTPRequestHandler):
    server_instance = None

    def _send_response_json(self, status_code: int, data: dict):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        if self.path in ["/api/v1/health", "/health"]:
            self._send_response_json(200, {
                "status": "healthy",
                "service": "SIEM REST Ingest Engine",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        else:
            self._send_response_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        if self.path != "/api/v1/ingest":
            self._send_response_json(404, {"error": "Invalid ingestion endpoint. Use /api/v1/ingest"})
            return

        # Optional API Key Authentication
        if config.REST_INGEST_API_KEY:
            auth_header = self.headers.get("Authorization", "")
            expected = f"Bearer {config.REST_INGEST_API_KEY}"
            if auth_header != expected:
                self._send_response_json(401, {"error": "Unauthorized: Invalid or missing API Bearer token"})
                return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0 or content_length > 10 * 1024 * 1024:  # Max 10MB payload
                self._send_response_json(400, {"error": "Invalid content length (Max 10MB)"})
                return

            body = self.rfile.read(content_length).decode("utf-8")
            payload = json.loads(body)
            
            client_ip = self.client_address[0]
            ingested_count = 0
            
            # Support both single dict and batch list of events
            events = payload if isinstance(payload, list) else [payload]
            
            for item in events:
                if not isinstance(item, dict):
                    continue
                
                # Standardize incoming envelope
                event = {
                    "source_type": "rest_api",
                    "source_ip": client_ip,
                    "timestamp": item.get("@timestamp") or item.get("timestamp") or datetime.utcnow().isoformat() + "Z",
                    "raw": json.dumps(item),
                    "data": item
                }
                
                if self.server_instance and self.server_instance.event_callback:
                    self.server_instance.event_callback(event)
                ingested_count += 1

            self._send_response_json(200, {
                "status": "success",
                "ingested_events": ingested_count,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        except json.JSONDecodeError:
            self._send_response_json(400, {"error": "Malformed JSON payload"})
        except Exception as e:
            self._send_response_json(500, {"error": f"Ingestion server error: {str(e)}"})

    def log_message(self, format, *args):
        # Suppress default stdout logging to avoid cluttering SIEM console
        pass


class RestIngestServer:
    def __init__(self, host=config.REST_INGEST_HOST, port=config.REST_INGEST_PORT, event_callback=None):
        self.host = host
        self.port = port
        self.event_callback = event_callback
        self.httpd = None
        self.thread = None
        self.running = False

    def start(self):
        """Starts the REST Ingest API HTTP Server."""
        if self.running:
            return
        self.running = True
        
        try:
            RestIngestHandler.server_instance = self
            self.httpd = HTTPServer((self.host, self.port), RestIngestHandler)
            self.thread = threading.Thread(target=self.httpd.serve_forever, name="REST-Ingest-API", daemon=True)
            self.thread.start()
            smart_logger.log("REST_INGEST_START", f"REST Ingestion API active on http://{self.host}:{self.port}/api/v1/ingest", level="INFO")
        except Exception as e:
            smart_logger.log("REST_INGEST_FAIL", f"Failed to start REST Ingest API on {self.host}:{self.port}: {e}", level="ERROR")

        # Keep calling thread alive for supervisor
        while self.running:
            time.sleep(1.0)

    def stop(self):
        """Stops the REST Ingestion server."""
        self.running = False
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
        smart_logger.log("REST_INGEST_STOP", "REST Ingest API server stopped gracefully.", level="INFO")

# Singleton instance
rest_ingest_server = RestIngestServer()

# Aliases for backwards compatibility
RestIngestAPI = RestIngestServer
rest_ingest_api = rest_ingest_server
