# -*- coding: utf-8 -*-
"""
==============================================================================
VIRTUAL MULTI-NODE MESH SIMULATION UNIT TEST (tests/test_virtual_mesh_simulation.py)
==============================================================================
"""

import unittest
from modules.virtual_mesh_simulator import virtual_mesh_orchestrator

class TestVirtualMeshSimulation(unittest.TestCase):
    def test_run_simulation(self):
        res = virtual_mesh_orchestrator.run_automated_simulation(speed_delay=0.0)
        metrics = res["metrics"]
        self.assertEqual(metrics["authorized_passed"], 5)
        self.assertEqual(metrics["policy_blocked"], 4)
        self.assertGreaterEqual(metrics["threats_neutralized"], 2)
        self.assertEqual(metrics["firewall_bans"], 1)

if __name__ == "__main__":
    unittest.main()
