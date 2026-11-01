# -*- coding: utf-8 -*-
"""
==============================================================================
IMPOSSIBLE TRAVEL GEOGRAPHIC SPEED DETECTOR (modules/impossible_travel.py)
==============================================================================
Calculates physical travel velocity between consecutive logins across different
geographic locations using the spherical Haversine formula to detect account takeover.
"""

import math
import time
import threading
from datetime import datetime
import config
from modules.smart_logger import smart_logger
from modules.geoip_enricher import geoip_enricher

class ImpossibleTravelDetector:
    def __init__(self, max_speed_kmh=config.IMPOSSIBLE_TRAVEL_SPEED_KMH):
        self.max_speed_kmh = max_speed_kmh
        self.lock = threading.Lock()
        
        # User -> {"last_ip": str, "last_lat": float, "last_lon": float, "last_time": float, "country": str, "city": str}
        self.user_last_locations = {}

    @staticmethod
    def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculates Great-Circle distance between two points on a sphere in Kilometers.
        """
        R = 6371.0  # Earth's mean radius in km
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dlon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def evaluate(self, username: str, source_ip: str, current_time: float = None) -> dict:
        """
        Evaluates physical travel feasibility for consecutive logins.
        Returns Impossible Travel alert dict if velocity exceeds physical threshold.
        """
        if not username or not source_ip:
            return None

        if current_time is None:
            current_time = time.time()

        geo = geoip_enricher.lookup(source_ip)
        
        # Ignore private LAN addresses with no geographic delta
        if geo.get("is_private") and geo.get("latitude") == 0 and geo.get("longitude") == 0:
            return None

        lat = geo.get("latitude", 0.0)
        lon = geo.get("longitude", 0.0)
        country = geo.get("country_name", "Unknown")
        city = geo.get("city", "Unknown")

        if lat == 0.0 and lon == 0.0:
            return None

        with self.lock:
            last = self.user_last_locations.get(username)
            self.user_last_locations[username] = {
                "last_ip": source_ip,
                "last_lat": lat,
                "last_lon": lon,
                "last_time": current_time,
                "country": country,
                "city": city
            }

            if not last:
                return None

            # Ignore if consecutive login comes from the exact same IP
            if last["last_ip"] == source_ip:
                return None

            # Calculate elapsed time in hours (minimum 1 second to avoid zero division)
            time_diff_hours = max(1.0 / 3600.0, (current_time - last["last_time"]) / 3600.0)

            # Calculate distance in km
            dist_km = self.haversine_distance(last["last_lat"], last["last_lon"], lat, lon)
            
            # Ignore micro-movements within the same city (< 50km)
            if dist_km < 50.0:
                return None

            velocity_kmh = dist_km / time_diff_hours

            if velocity_kmh > self.max_speed_kmh:
                alert = {
                    "type": "IMPOSSIBLE_TRAVEL_ANOMALY",
                    "severity": "CRITICAL",
                    "username": username,
                    "previous_location": f"{last['city']}, {last['country']} ({last['last_ip']})",
                    "current_location": f"{city}, {country} ({source_ip})",
                    "distance_km": round(dist_km, 1),
                    "time_diff_minutes": round(time_diff_hours * 60, 1),
                    "calculated_velocity_kmh": round(velocity_kmh, 1),
                    "description": (f"Impossible Travel: User {username} logged in from {city}, {country} "
                                    f"only {time_diff_hours*60:.1f} minutes after {last['city']}, {last['country']} "
                                    f"({dist_km:.1f} km at {velocity_kmh:.1f} km/h).")
                }
                smart_logger.log("IMPOSSIBLE_TRAVEL", alert["description"], level="CRITICAL")
                return alert

        return None

# Singleton instance
impossible_travel_detector = ImpossibleTravelDetector()
