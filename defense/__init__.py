# -*- coding: utf-8 -*-
"""
==============================================================================
DEFENSE & RESPONSE PACKAGE (__init__.py)
==============================================================================
Provides active defense and automated response: Kernel firewall orchestrator,
CIDR botnet defense shield, benign noise whitelist shield, and SMTP alerts.
==============================================================================
"""

from defense.ban_manager import BanManager
from defense.subnet_shield import SubnetShield
from defense.whitelist_shield import WhitelistShield
from defense.alert import Alert
