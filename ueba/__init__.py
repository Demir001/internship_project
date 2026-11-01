# -*- coding: utf-8 -*-
"""
==============================================================================
UEBA & BEHAVIORAL ANALYTICS PACKAGE (__init__.py)
==============================================================================
Provides User and Entity Behavior Analytics: 24x7 off-hours profiler, TTY
session tracker, human-readable user action auditor, impossible travel detector,
dormant account detector, and dynamic risk decay scorer.
==============================================================================
"""

from ueba.user_profile_engine import UserProfileEngine, user_profile_engine
from ueba.user_session_tracker import UserSessionTracker
from ueba.user_action_inspector import UserActionInspector, user_action_inspector
from ueba.impossible_travel import ImpossibleTravelDetector, impossible_travel_detector
from ueba.dormant_account import DormantAccountDetector, dormant_account_detector
from ueba.risk_scorer import DynamicRiskScorer, risk_scorer
