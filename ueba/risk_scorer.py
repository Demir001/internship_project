# -*- coding: utf-8 -*-
"""
==============================================================================
DYNAMIC USER & HOST RISK SCORING ENGINE (modules/risk_scorer.py)
==============================================================================
Maintains dynamic cumulative risk scores (0 to 100) for users and hosts with
exponential half-life decay, categorizing risk tiers and driving auto-response.
"""

import time
import math
import threading
from collections import defaultdict
import config
from modules.smart_logger import smart_logger

class RiskScorer:
    def __init__(self, half_life_hours=config.USER_RISK_DECAY_HOURS):
        self.half_life_seconds = half_life_hours * 3600.0
        self.lock = threading.Lock()
        
        # entity_id -> {"score": float, "last_updated": float, "history": list}
        self.user_risk_map = defaultdict(lambda: {"score": 0.0, "last_updated": time.time(), "history": []})
        self.host_risk_map = defaultdict(lambda: {"score": 0.0, "last_updated": time.time(), "history": []})

    def _decay_score(self, entry: dict, current_time: float) -> float:
        """Applies exponential time decay to an existing risk score."""
        elapsed = current_time - entry["last_updated"]
        if elapsed <= 0:
            return entry["score"]
        decay_factor = math.pow(0.5, elapsed / self.half_life_seconds)
        decayed = entry["score"] * decay_factor
        return round(max(0.0, decayed), 2)

    def add_risk(self, entity_id: str, points: float, reason: str, is_user: bool = True) -> dict:
        """
        Adds risk points to a user or host entity and returns the updated score & tier.
        """
        if not entity_id:
            return {"score": 0.0, "tier": "LOW"}

        current_time = time.time()
        target_map = self.user_risk_map if is_user else self.host_risk_map

        with self.lock:
            entry = target_map[entity_id]
            current_score = self._decay_score(entry, current_time)
            new_score = min(100.0, round(current_score + float(points), 2))
            
            entry["score"] = new_score
            entry["last_updated"] = current_time
            entry["history"].append({
                "ts": current_time,
                "added_points": points,
                "reason": reason,
                "resulting_score": new_score
            })
            # Keep last 20 history items
            if len(entry["history"]) > 20:
                entry["history"] = entry["history"][-20:]

            tier = self.get_tier(new_score)

            if new_score >= 75.0:
                entity_type = "User" if is_user else "Host"
                smart_logger.log(
                    "HIGH_RISK_ENTITY",
                    f"{entity_type} '{entity_id}' reached {tier} Risk Score: {new_score:.1f}/100 (Trigger: {reason})",
                    level="CRITICAL" if new_score >= 85 else "WARNING"
                )

            return {"entity_id": entity_id, "score": new_score, "tier": tier, "is_user": is_user}

    def get_risk(self, entity_id: str, is_user: bool = True) -> float:
        """Gets current decayed risk score for an entity."""
        target_map = self.user_risk_map if is_user else self.host_risk_map
        current_time = time.time()
        with self.lock:
            if entity_id not in target_map:
                return 0.0
            entry = target_map[entity_id]
            decayed = self._decay_score(entry, current_time)
            entry["score"] = decayed
            entry["last_updated"] = current_time
            return decayed

    @staticmethod
    def get_tier(score: float) -> str:
        """Maps numeric risk score to qualitative security tier."""
        if score >= 80.0:
            return "CRITICAL"
        elif score >= 60.0:
            return "HIGH"
        elif score >= 30.0:
            return "MEDIUM"
        return "LOW"

    def get_top_riskiest(self, top_n: int = 10, is_user: bool = True) -> list:
        """Returns the top N riskiest users or hosts."""
        target_map = self.user_risk_map if is_user else self.host_risk_map
        current_time = time.time()
        results = []
        with self.lock:
            for eid, entry in target_map.items():
                score = self._decay_score(entry, current_time)
                if score > 0:
                    results.append({"entity_id": eid, "score": score, "tier": self.get_tier(score)})
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_n]

# Singleton instance
risk_scorer = RiskScorer()

# Alias for backwards compatibility
DynamicRiskScorer = RiskScorer
