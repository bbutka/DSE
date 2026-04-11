"""
Full regression test suite for the DSE security analysis tool.

Covers:
  - Data model construction (Component, Asset, NetworkModel)
  - Factory models (TC9, RefSoC-16)
  - ASP fact generation (ASPGenerator)
  - Topology validation
  - Solution parser (Phase1Result, Phase2Result, ScenarioResult, SolutionResult)
  - Solution ranker (scoring, CIA weighting)
  - Comparison engine and report generation
  - Executive summary analyser
  - Phase 3 scenario generation
  - End-to-end Clingo solver integration (Phase 1, 2, 3)
  - Orchestrator full pipeline
"""
from __future__ import annotations

import os
import queue
import sys
import unittest
from dataclasses import asdict
from typing import List

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLINGO_DIR = os.path.join(PROJECT_ROOT, "Clingo")
TESTCASE_LP = os.path.join(CLINGO_DIR, "tgt_system_tc9_inst.lp")

sys.path.insert(0, PROJECT_ROOT)

from dse_tool.core.asp_generator import (
    Component, Asset, RedundancyGroup, Service, AccessNeed,
    MissionCapability, FunctionSupport, NetworkModel, ASPGenerator,
    make_opentitan_network, make_pixhawk6x_platform, make_pixhawk6x_uav_network,
    make_pixhawk6x_dual_ps_network, make_pixhawk6x_uav_dual_ps_network,
    make_tc9_network, make_reference_soc,
)
from dse_tool.core.solution_parser import (
    Phase1Result, Phase2Result, ScenarioResult, SolutionResult,
    SolutionParser, AMP_DENOM,
)
from dse_tool.core.architecture_delta import compare_network_models
from dse_tool.core.architecture_repair import apply_architecture_repair_intents
from dse_tool.core.architecture_comparison_report import (
    build_architecture_comparison_summary,
    format_architecture_comparison,
)
from dse_tool.core.solution_ranker import SolutionRanker, CIA_WEIGHTS
from dse_tool.core.comparison import ComparisonEngine, generate_report_text
from dse_tool.core.executive_summary import (
    ExecutiveSummaryAnalyser, ExecutiveSummary, BottleneckFinding,
    format_executive_summary,
)
from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent
from dse_tool.agents.phase3_agent import generate_scenarios, _valid_asp_components


# ═══════════════════════════════════════════════════════════════════════════
# 1. Data Model Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestComponent(unittest.TestCase):
    """Test Component dataclass defaults and creation."""

    def test_defaults(self):
        c = Component("test", "ip_core", "normal", 3, 3, 10, 10)
        self.assertEqual(c.name, "test")
        self.assertEqual(c.impact_avail, 0)
        self.assertEqual(c.exploitability, 3)
        self.assertFalse(c.has_rot)
        self.assertFalse(c.has_sboot)
        self.assertFalse(c.has_attest)
        self.assertFalse(c.is_master)
        self.assertTrue(c.is_receiver)
        self.assertFalse(c.is_critical)
        self.assertFalse(c.is_safety_critical)
        self.assertEqual(c.direction, "bidirectional")

    def test_master_component(self):
        c = Component("cpu", "processor", "low", 1, 1, 1000, 1000,
                       is_master=True, is_receiver=False)
        self.assertTrue(c.is_master)
        self.assertFalse(c.is_receiver)


class TestAsset(unittest.TestCase):
    def test_defaults(self):
        a = Asset("reg1", "comp_a")
        self.assertEqual(a.direction, "bidirectional")
        self.assertEqual(a.impact_read, 3)
        self.assertEqual(a.impact_write, 3)
        self.assertEqual(a.impact_avail, 0)

    def test_input_asset(self):
        a = Asset("sensor_data", "sensor", direction="input",
                  impact_read=4, impact_write=0, impact_avail=3)
        self.assertEqual(a.direction, "input")
        self.assertEqual(a.impact_avail, 3)


class TestNetworkModel(unittest.TestCase):
    def test_empty_model(self):
        m = NetworkModel()
        self.assertEqual(m.name, "custom_network")
        self.assertIsInstance(m.components, list)
        self.assertIsInstance(m.system_caps, dict)
        self.assertIn("max_luts", m.system_caps)

    def test_model_serialization(self):
        m = NetworkModel(name="test_net")
        d = asdict(m)
        self.assertEqual(d["name"], "test_net")


# ═══════════════════════════════════════════════════════════════════════════
# 2. Factory Model Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestTC9Factory(unittest.TestCase):
    """Validate the TC9 factory model structure."""

    @classmethod
    def setUpClass(cls):
        cls.model = make_tc9_network()

    def test_name(self):
        self.assertEqual(self.model.name, "testCase9")

    def test_component_count(self):
        # 2 masters + 8 IPs + 2 PSes = 12
        self.assertEqual(len(self.model.components), 12)

    def test_masters(self):
        masters = [c for c in self.model.components if c.is_master]
        self.assertEqual(len(masters), 2)
        names = {m.name for m in masters}
        self.assertEqual(names, {"sys_cpu", "dma"})

    def test_buses(self):
        self.assertEqual(set(self.model.buses), {"noc0", "noc1"})

    def test_links_nonempty(self):
        self.assertGreater(len(self.model.links), 0)

    def test_redundancy_groups(self):
        self.assertEqual(len(self.model.redundancy_groups), 1)
        grp = self.model.redundancy_groups[0]
        self.assertEqual(set(grp.members), {"c1", "c2", "c3", "c4", "c5"})

    def test_services(self):
        self.assertEqual(len(self.model.services), 3)
        svc_names = {s.name for s in self.model.services}
        self.assertIn("compute_svc", svc_names)

    def test_access_needs(self):
        self.assertGreater(len(self.model.access_needs), 0)

    def test_candidate_firewalls(self):
        self.assertEqual(set(self.model.cand_fws), {"pep_group", "pep_standalone"})

    def test_candidate_ps(self):
        self.assertEqual(set(self.model.cand_ps), {"ps0", "ps1"})

    def test_on_paths(self):
        self.assertGreater(len(self.model.on_paths), 0)

    def test_ip_locs(self):
        self.assertGreater(len(self.model.ip_locs), 0)

    def test_fw_governs(self):
        self.assertGreater(len(self.model.fw_governs), 0)

    def test_capabilities(self):
        self.assertGreater(len(self.model.capabilities), 0)
        cap_names = {c.name for c in self.model.capabilities}
        self.assertIn("compute", cap_names)
        self.assertIn("policy_management", cap_names)

    def test_trust_anchors(self):
        self.assertIn("ps0", self.model.trust_anchors)
        self.assertIn("signed_policy", self.model.trust_anchors["ps0"])

    def test_safety_critical(self):
        sc = [c for c in self.model.components if c.is_safety_critical]
        self.assertGreater(len(sc), 0)

    def test_roles(self):
        self.assertGreater(len(self.model.roles), 0)

    def test_policy_exceptions(self):
        self.assertGreater(len(self.model.policy_exceptions), 0)


class TestRefSoCFactory(unittest.TestCase):
    """Validate the Reference SoC-16 factory model."""

    @classmethod
    def setUpClass(cls):
        cls.model = make_reference_soc()

    def test_name(self):
        self.assertEqual(self.model.name, "SecureSoC-16")

    def test_component_count(self):
        # 3 masters + 10 IPs + 2 PSes = 15
        self.assertEqual(len(self.model.components), 15)

    def test_masters(self):
        masters = [c for c in self.model.components if c.is_master]
        self.assertEqual(len(masters), 3)

    def test_all_domain_levels(self):
        domains = {c.domain for c in self.model.components}
        # Should cover at least untrusted, normal, privileged, root
        self.assertIn("untrusted", domains)
        self.assertIn("normal", domains)
        self.assertIn("privileged", domains)
        self.assertIn("root", domains)

    def test_exploitability_range(self):
        exploits = {c.exploitability for c in self.model.components
                    if c.comp_type not in ("policy_server",)}
        self.assertIn(1, exploits)  # hardened
        self.assertIn(5, exploits)  # trivial

    def test_direction_types(self):
        dirs = {c.direction for c in self.model.components}
        self.assertIn("input", dirs)
        self.assertIn("output", dirs)
        self.assertIn("bidirectional", dirs)

    def test_capabilities_count(self):
        self.assertEqual(len(self.model.capabilities), 8)

    def test_essential_capabilities(self):
        essential = [c for c in self.model.capabilities
                     if c.criticality == "essential"]
        self.assertGreater(len(essential), 0)

    def test_candidate_firewalls(self):
        self.assertEqual(len(self.model.cand_fws), 3)

    def test_buses(self):
        self.assertEqual(len(self.model.buses), 3)

    def test_redundancy(self):
        self.assertEqual(len(self.model.redundancy_groups), 1)
        self.assertEqual(len(self.model.redundancy_groups[0].members), 3)


class TestOpenTitanFactory(unittest.TestCase):
    """Validate the OpenTitan-derived ICCAD factory model."""

    @classmethod
    def setUpClass(cls):
        cls.ot_a = make_opentitan_network("OT-A")
        cls.ot_b = make_opentitan_network("OT-B")
        cls.ot_c = make_opentitan_network("OT-C")

    def test_name(self):
        self.assertEqual(self.ot_a.name, "OpenTitan (OT-A)")

    def test_profile_caps(self):
        self.assertEqual(self.ot_a.system_caps["max_luts"], 254200)
        self.assertEqual(self.ot_b.system_caps["max_luts"], 25000)
        self.assertEqual(self.ot_c.system_caps["max_power"], 800)

    def test_explicit_asset_count(self):
        self.assertEqual(len(self.ot_a.assets), 20)

    def test_core_component_names(self):
        names = {c.name for c in self.ot_a.components}
        self.assertIn("cpu", names)
        self.assertIn("dma", names)
        self.assertIn("keymgr", names)
        self.assertIn("entropy", names)
        self.assertIn("pep_ot", names)
        self.assertIn("ps_ot", names)

    def test_redundancy_groups(self):
        groups = {g.group_id: set(g.members) for g in self.ot_a.redundancy_groups}
        self.assertEqual(groups["crypto_cover"], {"aes", "hmac", "kmac"})
        self.assertEqual(groups["uart_cover"], {"uart0", "uart1"})

    def test_candidate_control_plane(self):
        self.assertEqual(self.ot_a.cand_fws, ["pep_ot"])
        self.assertEqual(self.ot_a.cand_ps, ["ps_ot"])

    def test_capabilities_present(self):
        caps = {c.name for c in self.ot_a.capabilities}
        self.assertIn("secure_boot", caps)
        self.assertIn("crypto_ops", caps)
        self.assertIn("serial_io", caps)


class TestPixhawk6XFactory(unittest.TestCase):
    """Validate the Pixhawk 6X platform and UAV overlay models."""

    @classmethod
    def setUpClass(cls):
        cls.platform = make_pixhawk6x_platform()
        cls.uav = make_pixhawk6x_uav_network()
        cls.uav_dual_ps = make_pixhawk6x_uav_dual_ps_network()

    def test_platform_name(self):
        self.assertEqual(self.platform.name, "Pixhawk 6X Platform")

    def test_platform_contains_documented_components(self):
        names = {c.name for c in self.platform.components}
        for name in ("fmu_h753", "io_mcu", "imu_1", "imu_2", "imu_3", "baro_1", "baro_2", "mag", "se050", "ps_fmu"):
            self.assertIn(name, names)

    def test_platform_redundancy_groups(self):
        groups = {g.group_id: set(g.members) for g in self.platform.redundancy_groups}
        self.assertEqual(groups["imu_group"], {"imu_1", "imu_2", "imu_3"})
        self.assertEqual(groups["baro_group"], {"baro_1", "baro_2"})

    def test_platform_port_buses(self):
        buses = set(self.platform.buses)
        for bus in ("gps1_port", "gps2_port", "telem1_port", "uart4_i2c_port", "eth_port", "spi5_ext", "can1", "can2", "px4io_link"):
            self.assertIn(bus, buses)

    def test_platform_capabilities(self):
        caps = {c.name for c in self.platform.capabilities}
        self.assertEqual(caps, {"flight_stabilization_base", "failsafe_io", "crypto_anchor"})

    def test_uav_name(self):
        self.assertEqual(self.uav.name, "Pixhawk 6X UAV")

    def test_uav_overlay_components(self):
        names = {c.name for c in self.uav.components}
        for name in ("gps_1", "gps_2", "telem_radio", "ground_station", "rc_receiver", "esc_bus_1", "esc_bus_2", "companion", "camera", "flash_fram"):
            self.assertIn(name, names)

    def test_uav_overlay_redundancy(self):
        groups = {g.group_id: set(g.members) for g in self.uav.redundancy_groups}
        self.assertEqual(groups["gps_group"], {"gps_1", "gps_2"})
        self.assertEqual(groups["motor_bus_group"], {"esc_bus_1", "esc_bus_2"})

    def test_uav_overlay_capabilities(self):
        caps = {c.name for c in self.uav.capabilities}
        for cap in ("flight_control", "navigation", "ground_comms", "rc_override", "surveillance", "crypto_ops", "logging"):
            self.assertIn(cap, caps)

    def test_uav_pep_candidates(self):
        self.assertIn("pep_telem1", self.uav.cand_fws)
        self.assertIn("pep_eth", self.uav.cand_fws)
        self.assertIn("pep_can1", self.uav.cand_fws)
        self.assertIn("pep_gps2", self.uav.cand_fws)

    def test_dual_ps_overlay_contains_ps_io(self):
        names = {c.name for c in self.uav_dual_ps.components}
        self.assertIn("ps_io", names)
        self.assertEqual(set(self.uav_dual_ps.cand_ps), {"ps_fmu", "ps_io"})

    def test_dual_ps_alias_matches_uav_dual_ps_factory(self):
        alias_model = make_pixhawk6x_dual_ps_network()
        self.assertEqual(alias_model.name, self.uav_dual_ps.name)
        self.assertEqual(set(alias_model.cand_ps), set(self.uav_dual_ps.cand_ps))
        self.assertEqual(set(alias_model.fw_governs), set(self.uav_dual_ps.fw_governs))

    def test_platform_to_uav_architecture_delta(self):
        delta = compare_network_models(self.platform, self.uav)
        self.assertTrue(delta.has_changes())
        self.assertIn("gps_1", delta.added_components)
        self.assertIn("gps_2", delta.added_components)
        self.assertIn("telem_radio", delta.added_components)
        self.assertIn("ground_station", delta.added_components)
        self.assertIn("flash_fram", delta.added_components)
        self.assertIn("gps_group", delta.added_redundancy_groups)
        self.assertIn("motor_bus_group", delta.added_redundancy_groups)
        self.assertIn("navigation", delta.added_capabilities)
        self.assertIn("comms_svc", delta.added_services)

    def test_uav_to_dual_ps_architecture_delta(self):
        delta = compare_network_models(self.uav, self.uav_dual_ps)
        self.assertEqual(delta.added_components, ["ps_io"])
        self.assertEqual(delta.added_ps_candidates, ["ps_io"])


# ═══════════════════════════════════════════════════════════════════════════
# 3. ASP Generator Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestASPGenerator(unittest.TestCase):
    """Test ASP fact generation from NetworkModel."""

    @classmethod
    def setUpClass(cls):
        cls.tc9 = make_tc9_network()
        cls.refsoc = make_reference_soc()
        cls.ot = make_opentitan_network("OT-A")
        cls.pixhawk_platform = make_pixhawk6x_platform()
        cls.pixhawk_uav = make_pixhawk6x_uav_network()
        cls.tc9_facts = ASPGenerator(cls.tc9).generate()
        cls.refsoc_facts = ASPGenerator(cls.refsoc).generate()
        cls.ot_facts = ASPGenerator(cls.ot).generate()
        cls.pixhawk_platform_facts = ASPGenerator(cls.pixhawk_platform).generate()
        cls.pixhawk_uav_facts = ASPGenerator(cls.pixhawk_uav).generate()

    def test_tc9_nonempty(self):
        self.assertGreater(len(self.tc9_facts), 100)

    def test_refsoc_nonempty(self):
        self.assertGreater(len(self.refsoc_facts), 100)

    def test_tc9_contains_components(self):
        self.assertIn("component(c1).", self.tc9_facts)
        self.assertIn("component(c8).", self.tc9_facts)

    def test_tc9_contains_masters(self):
        self.assertIn("master(sys_cpu).", self.tc9_facts)
        self.assertIn("master(dma).", self.tc9_facts)

    def test_tc9_precomputed_phase2_reachability(self):
        self.assertIn("reachable(sys_cpu, c1).", self.tc9_facts)
        self.assertIn("reachable(dma, c8).", self.tc9_facts)
        self.assertNotIn("reachable(c1, sys_cpu).", self.tc9_facts)
        self.assertNotIn("reachable(sys_cpu, noc0).", self.tc9_facts)

    def test_tc9_contains_receivers(self):
        self.assertIn("receiver(c1).", self.tc9_facts)

    def test_tc9_contains_assets(self):
        self.assertIn("asset(c1, c1r1, read).", self.tc9_facts)

    def test_tc9_contains_links(self):
        self.assertIn("link(sys_cpu, noc0).", self.tc9_facts)

    def test_tc9_contains_domains(self):
        self.assertIn("domain(sys_cpu, low).", self.tc9_facts)
        self.assertIn("domain(c1, high).", self.tc9_facts)

    def test_tc9_contains_services(self):
        self.assertIn("service_component(compute_svc, c1).", self.tc9_facts)
        self.assertIn("service_quorum(compute_svc, 3).", self.tc9_facts)

    def test_tc9_contains_access_needs(self):
        self.assertIn("access_need(sys_cpu, c1, read).", self.tc9_facts)

    def test_tc9_contains_capabilities(self):
        self.assertIn("capability(compute).", self.tc9_facts)

    def test_tc9_contains_trust_anchors(self):
        self.assertIn("signed_policy(ps0).", self.tc9_facts)
        self.assertIn("hardware_rot(c1).", self.tc9_facts)

    def test_tc9_contains_risk_weights(self):
        self.assertIn("risk_weight(", self.tc9_facts)

    def test_pixhawk_master_without_asset_does_not_emit_dead_risk_weight(self):
        self.assertNotIn("risk_weight(fmu_h753r1,", self.pixhawk_platform_facts)
        self.assertNotIn("risk_weight(fmu_h753r1,", self.pixhawk_uav_facts)

    def test_pixhawk_platform_capability_preserves_service_quorum_semantics(self):
        self.assertNotIn(
            "capability_requires_access(flight_stabilization_base, fmu_h753, imu_1, read).",
            self.pixhawk_platform_facts,
        )
        self.assertNotIn(
            "capability_requires_access(flight_stabilization_base, fmu_h753, baro_1, read).",
            self.pixhawk_platform_facts,
        )

    def test_pixhawk_uav_capabilities_do_not_pin_redundant_members(self):
        self.assertNotIn(
            "capability_requires_access(flight_control, fmu_h753, imu_1, read).",
            self.pixhawk_uav_facts,
        )
        self.assertNotIn(
            "capability_requires_access(flight_control, fmu_h753, esc_bus_1, write).",
            self.pixhawk_uav_facts,
        )
        self.assertNotIn(
            "capability_requires_access(navigation, fmu_h753, gps_1, read).",
            self.pixhawk_uav_facts,
        )
        self.assertNotIn(
            "capability_requires_access(navigation, fmu_h753, baro_1, read).",
            self.pixhawk_uav_facts,
        )

    def test_tc9_contains_redundancy(self):
        # Group g1 → integer 1
        self.assertIn("redundant_group(1, c1).", self.tc9_facts)

    def test_refsoc_contains_safety_critical(self):
        self.assertIn("safety_critical(crypto_eng).", self.refsoc_facts)
        self.assertIn("safety_critical(actuator).", self.refsoc_facts)

    def test_refsoc_contains_buses(self):
        self.assertIn("bus(axi_main).", self.refsoc_facts)

    def test_refsoc_contains_exploitability(self):
        # comm_eth has exploitability 5 (non-default)
        self.assertIn("exploitability(comm_eth, 5).", self.refsoc_facts)

    def test_refsoc_direction_filtering(self):
        # sensor_a is input-only: should have read but NOT write
        self.assertIn("asset(sensor_a, sensor_ar1, read).", self.refsoc_facts)
        self.assertNotIn("asset(sensor_a, sensor_ar1, write).", self.refsoc_facts)

    def test_refsoc_output_direction(self):
        # actuator is output-only: should have write but NOT read
        self.assertIn("asset(actuator, actuatorr1, write).", self.refsoc_facts)
        self.assertNotIn("asset(actuator, actuatorr1, read).", self.refsoc_facts)

    def test_refsoc_avail_assets(self):
        # Components with impact_avail > 0 should have avail assets
        self.assertIn("asset(sensor_a, sensor_ar1, avail).", self.refsoc_facts)

    def test_opentitan_contains_components(self):
        self.assertIn("master(cpu).", self.ot_facts)
        self.assertIn("master(dma).", self.ot_facts)
        self.assertIn("component(keymgr).", self.ot_facts)
        self.assertIn("component(entropy).", self.ot_facts)

    def test_opentitan_contains_assets(self):
        self.assertIn("asset(cpu, cpu_a0, read).", self.ot_facts)
        self.assertIn("asset(entropy, entropy_a0, write).", self.ot_facts)

    def test_opentitan_contains_redundancy(self):
        self.assertIn("redundant_group(crypto_cover, aes).", self.ot_facts)
        self.assertIn("redundant_group(uart_cover, uart0).", self.ot_facts)

    def test_opentitan_contains_capabilities(self):
        self.assertIn("capability(secure_boot).", self.ot_facts)
        self.assertIn("capability(crypto_ops).", self.ot_facts)

    def test_opentitan_contains_profile_caps(self):
        self.assertIn("system_capability(max_luts, 254200).", self.ot_facts)
        self.assertIn("system_capability(max_power, 15000).", self.ot_facts)

    def test_no_bus_as_component(self):
        # Buses should not appear as component() or receiver()
        self.assertNotIn("component(noc0).", self.tc9_facts)
        self.assertNotIn("receiver(noc0).", self.tc9_facts)

    def test_ps_not_receiver(self):
        self.assertNotIn("receiver(ps0).", self.tc9_facts)
        self.assertNotIn("component(ps0).", self.tc9_facts)

    def test_mission_phases(self):
        self.assertIn("mission_phase(operational).", self.tc9_facts)

    def test_pep_guards(self):
        self.assertIn("pep_guards(pep_group, c1).", self.tc9_facts)


class TestTopologyValidation(unittest.TestCase):
    """Test validate_topology() detects structural issues."""

    def test_tc9_clean(self):
        model = make_tc9_network()
        warnings = ASPGenerator(model).validate_topology()
        self.assertEqual(len(warnings), 0, f"Unexpected warnings: {warnings}")

    def test_refsoc_clean(self):
        model = make_reference_soc()
        warnings = ASPGenerator(model).validate_topology()
        self.assertEqual(len(warnings), 0, f"Unexpected warnings: {warnings}")

    def test_missing_fw_coverage(self):
        """A critical IP reachable from low-trust master with no on-path FW."""
        model = NetworkModel(name="test_bad")
        model.components = [
            Component("cpu", "processor", "low", 1, 1, 1000, 1000,
                       is_master=True, is_receiver=False),
            Component("secret", "ip_core", "high", 5, 5, 10, 10,
                       is_critical=True),
        ]
        model.links = [("cpu", "secret")]
        model.cand_fws = ["fw1"]
        # No on_paths → should warn
        warnings = ASPGenerator(model).validate_topology()
        self.assertGreater(len(warnings), 0)
        self.assertTrue(any("UNSAT risk" in w for w in warnings))

    def test_ungoverned_fw(self):
        """A candidate FW with no governing PS."""
        model = NetworkModel(name="test_ungov")
        model.components = [
            Component("cpu", "processor", "low", 1, 1, 1000, 1000,
                       is_master=True, is_receiver=False),
            Component("ip1", "ip_core", "high", 3, 3, 10, 10, is_critical=True),
        ]
        model.links = [("cpu", "ip1")]
        model.cand_fws = ["fw1"]
        model.on_paths = [("fw1", "cpu", "ip1")]
        model.fw_governs = []  # No governance → should warn
        warnings = ASPGenerator(model).validate_topology()
        self.assertTrue(any("governing PS" in w for w in warnings))

    def test_bad_ip_loc(self):
        """ip_loc references a non-candidate FW."""
        model = NetworkModel(name="test_badloc")
        model.ip_locs = [("ip1", "nonexistent_fw")]
        model.cand_fws = ["real_fw"]
        warnings = ASPGenerator(model).validate_topology()
        self.assertTrue(any("non-candidate firewall" in w for w in warnings))

    def test_safety_critical_bus(self):
        """Safety-critical on a bus type should warn."""
        model = NetworkModel(name="test_sc_bus")
        model.components = [
            Component("mybus", "bus", "normal", 1, 1, 1000, 1000,
                       is_safety_critical=True),
        ]
        warnings = ASPGenerator(model).validate_topology()
        self.assertTrue(any("Safety-critical" in w for w in warnings))


# ═══════════════════════════════════════════════════════════════════════════
# 4. Solution Parser Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPhase1Result(unittest.TestCase):
    def _make_p1(self) -> Phase1Result:
        p1 = Phase1Result(strategy="max_security", satisfiable=True, optimal=True)
        p1.security = {"c1": "zero_trust", "c2": "dynamic_mac", "c3": "mac"}
        p1.realtime = {"c1": "runtime_attestation", "c2": "watchdog", "c3": "no_realtime"}
        p1.new_risk = [
            ("c1", "c1r1", "read", 2),
            ("c1", "c1r1", "write", 3),
            ("c2", "c2r1", "read", 5),
            ("c2", "c2r1", "write", 4),
            ("c3", "c3r1", "read", 7),
        ]
        p1.total_luts = 5000
        p1.total_ffs = 2000
        p1.total_power = 800
        return p1

    def test_max_risk_per_asset(self):
        p1 = self._make_p1()
        per_asset = p1.max_risk_per_asset()
        self.assertEqual(per_asset["c1r1"], 3)
        self.assertEqual(per_asset["c2r1"], 5)
        self.assertEqual(per_asset["c3r1"], 7)

    def test_total_risk(self):
        p1 = self._make_p1()
        self.assertEqual(p1.total_risk(), 2 + 3 + 5 + 4 + 7)

    def test_summary_total_risk(self):
        p1 = self._make_p1()
        self.assertEqual(p1.summary_total_risk(), 3 + 5 + 7)

    def test_risk_by_component(self):
        p1 = self._make_p1()
        by_comp = p1.risk_by_component()
        # risk_by_component uses max-per-asset-then-sum (same as summary_total_risk)
        # c1: max(c1r1 read=2, c1r1 write=3) = 3
        # c2: max(c2r1 read=5, c2r1 write=4) = 5
        # c3: c3r1 read=7
        self.assertEqual(by_comp["c1"], 3)
        self.assertEqual(by_comp["c2"], 5)
        self.assertEqual(by_comp["c3"], 7)

    def test_risk_per_asset_action(self):
        p1 = self._make_p1()
        per_aa = p1.risk_per_asset_action()
        self.assertEqual(per_aa[("c1r1", "read")], 2)
        self.assertEqual(per_aa[("c1r1", "write")], 3)

    def test_as_p1_facts(self):
        p1 = self._make_p1()
        facts = p1.as_p1_facts()
        self.assertIn("p1_security(c1, zero_trust).", facts)
        self.assertIn("p1_realtime(c1, runtime_attestation).", facts)
        self.assertIn("p1_risk(c1r1, read, 2).", facts)
        self.assertIn("p1_risk(c1r1, 3).", facts)  # max over actions

    def test_security_overhead_summary(self):
        p1 = self._make_p1()
        summary = p1.security_overhead_summary()
        self.assertEqual(summary["luts"], 5000)
        self.assertEqual(summary["ffs"], 2000)
        self.assertEqual(summary["power_mw"], 800)


class TestPhase2Result(unittest.TestCase):
    def test_as_phase3_facts(self):
        p2 = Phase2Result(satisfiable=True)
        p2.placed_fws = ["fw1", "fw2"]
        p2.placed_ps = ["ps0"]
        p2.final_allows = [("cpu", "ip1", "read")]
        p2.trust_levels = {"ip1": "low"}
        p2.excess_privileges = [("cpu", "ip1", "write")]
        p2.transition_triggers = [("compromise_detected", "normal", "attack_suspected")]
        facts = p2.as_phase3_facts()
        self.assertIn("deployed_pep(fw1).", facts)
        self.assertIn("deployed_ps(ps0).", facts)
        self.assertIn("p2_mode_allow(cpu, ip1, read).", facts)
        self.assertNotIn("p2_trust_level", facts)
        self.assertNotIn("p2_excess_privilege", facts)
        self.assertNotIn("transition_trigger", facts)

    def test_avg_policy_tightness(self):
        p2 = Phase2Result(satisfiable=True)
        p2.policy_tightness = {"cpu": 80, "dma": 60}
        self.assertAlmostEqual(p2.avg_policy_tightness(), 70.0)

    def test_avg_policy_tightness_empty(self):
        p2 = Phase2Result(satisfiable=True)
        self.assertEqual(p2.avg_policy_tightness(), 0.0)

    def test_avg_effective_policy_tightness(self):
        p2 = Phase2Result(satisfiable=True)
        p2.effective_policy_tightness = {
            ("cpu", "normal"): 80,
            ("dma", "normal"): 60,
            ("cpu", "attack_confirmed"): 0,
        }
        self.assertAlmostEqual(p2.avg_effective_policy_tightness(), 70.0)

    def test_avg_effective_policy_tightness_fallback_all_modes(self):
        p2 = Phase2Result(satisfiable=True)
        p2.effective_policy_tightness = {
            ("cpu", "attack_confirmed"): 10,
            ("dma", "attack_confirmed"): 30,
        }
        self.assertAlmostEqual(p2.avg_effective_policy_tightness(), 20.0)

    def test_zta_overhead_cost(self):
        p2 = Phase2Result(satisfiable=True, total_cost=275)
        self.assertEqual(p2.zta_overhead_cost(), 275)

    def test_resilience_objective_penalty(self):
        p2 = Phase2Result(
            satisfiable=True,
            unplaced_safety_fw_penalty=750,
            control_plane_concentration_penalty=400,
        )
        self.assertEqual(p2.resilience_objective_penalty(), 1150)

    def test_phase2_objective_facts_control_plane(self):
        from dse_tool.agents.phase2_agent import Phase2Agent

        agent = Phase2Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=Phase1Result(strategy="max_security", satisfiable=True),
            solver_config={
                "phase2_objective": "control_plane",
                "phase2_safety_fw_penalty_weight": 500,
                "phase2_concentration_penalty_weight": 300,
            },
        )
        facts = agent._phase2_objective_facts()
        self.assertIn("phase2_resilience_mode(control_plane).", facts)
        self.assertIn("phase2_safety_fw_penalty_weight(500).", facts)
        self.assertIn("phase2_concentration_penalty_weight(300).", facts)


class TestScenarioResult(unittest.TestCase):
    def test_total_risk_property(self):
        sc = ScenarioResult(name="test", compromised=[], failed=[])
        sc.total_risk_scaled = 35
        self.assertAlmostEqual(sc.total_risk, 3.5)

    def test_max_blast_radius(self):
        sc = ScenarioResult(name="test", compromised=[], failed=[])
        sc.blast_radii = {"a": 3, "b": 7, "c": 2}
        self.assertEqual(sc.max_blast_radius, 7)

    def test_max_blast_radius_empty(self):
        sc = ScenarioResult(name="test", compromised=[], failed=[])
        self.assertEqual(sc.max_blast_radius, 0)


class TestSolutionResult(unittest.TestCase):
    def _make_sol(self) -> SolutionResult:
        p1 = Phase1Result(strategy="max_security", satisfiable=True)
        p1.new_risk = [("c1", "c1r1", "read", 5)]
        sc1 = ScenarioResult(name="baseline", compromised=[], failed=[],
                              satisfiable=True)
        sc1.blast_radii = {"a": 3, "b": 5}
        sc1.total_risk_scaled = 20
        sc2 = ScenarioResult(name="worst", compromised=["cpu"], failed=[],
                              satisfiable=True)
        sc2.blast_radii = {"a": 8, "b": 2}
        sc2.total_risk_scaled = 50
        return SolutionResult(strategy="max_security", phase1=p1,
                              scenarios=[sc1, sc2])

    def test_avg_blast_radius(self):
        sol = self._make_sol()
        # avg of max(3,5)=5 and max(8,2)=8 → 6.5
        self.assertAlmostEqual(sol.avg_blast_radius(), 6.5)

    def test_worst_scenario(self):
        sol = self._make_sol()
        worst = sol.worst_scenario()
        self.assertIsNotNone(worst)
        self.assertEqual(worst.name, "worst")

    def test_latency_violations(self):
        sol = self._make_sol()
        self.assertEqual(sol.latency_violations(), 0)

    def test_phase2_mode_label(self):
        sol = self._make_sol()
        sol.phase2 = Phase2Result(satisfiable=True)
        self.assertEqual(sol.phase2_mode_label(), "cost-only heuristic")
        sol.phase2.unplaced_safety_fw_penalty = 1
        self.assertEqual(sol.phase2_mode_label(), "heuristic control-plane proxy")
        sol.phase2.closed_loop_score = (1, 2, 3)
        self.assertEqual(sol.phase2_mode_label(), "exact closed-loop")

    def test_analysis_notes_include_core_limitations(self):
        sol = self._make_sol()
        sol.phase2 = Phase2Result(satisfiable=True)
        notes = sol.analysis_notes()
        self.assertTrue(any("ordinal residual-risk scores" in note for note in notes))
        self.assertTrue(any("enumerated scenario set" in note for note in notes))
        self.assertTrue(any("exact closed-loop Phase 2 mode" in note for note in notes))


# ═══════════════════════════════════════════════════════════════════════════
# 5. Solution Ranker Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestSolutionRanker(unittest.TestCase):
    def _make_solutions(self) -> List[SolutionResult]:
        sols = []
        for strat, risk_val, luts, power in [
            ("max_security", 5, 8000, 2000),
            ("min_resources", 15, 3000, 1000),
            ("balanced", 10, 5000, 1500),
        ]:
            p1 = Phase1Result(strategy=strat, satisfiable=True, optimal=True)
            p1.new_risk = [("c1", "c1r1", "read", risk_val)]
            p1.total_luts = luts
            p1.total_power = power
            p2 = Phase2Result(satisfiable=True)
            p2.placed_fws = ["fw1"]
            sc = ScenarioResult(name="baseline", compromised=[], failed=[],
                                satisfiable=True)
            sc.blast_radii = {"c1": 3}
            sol = SolutionResult(strategy=strat, phase1=p1, phase2=p2,
                                 scenarios=[sc])
            sols.append(sol)
        return sols

    def test_rank_populates_scores(self):
        sols = self._make_solutions()
        ranker = SolutionRanker(sols)
        ranker.rank()
        for sol in sols:
            self.assertGreater(sol.security_score, 0)
            self.assertGreater(sol.resource_score, 0)
            self.assertGreater(sol.power_score, 0)
            self.assertEqual(sol.latency_score, 100.0)

    def test_security_ordering(self):
        sols = self._make_solutions()
        ranker = SolutionRanker(sols)
        ranker.rank()
        # max_security (risk=5) should have highest security score
        self.assertGreater(sols[0].security_score, sols[1].security_score)

    def test_resource_ordering(self):
        sols = self._make_solutions()
        ranker = SolutionRanker(sols)
        ranker.rank()
        # min_resources (luts=3000) should have highest resource score
        self.assertGreater(sols[1].resource_score, sols[0].resource_score)

    def test_custom_caps(self):
        sols = self._make_solutions()
        ranker = SolutionRanker(sols, max_luts=10000, max_power=5000)
        ranker.rank()
        # With lower caps, resource percentages should be higher
        # min_resources: 3000/10000 = 30% → score = 70
        self.assertAlmostEqual(sols[1].resource_score, 70.0)

    def test_relative_ranks(self):
        sols = self._make_solutions()
        ranker = SolutionRanker(sols)
        ranker.rank()
        ranks = ranker.relative_ranks()
        # max_security should be rank 0 for security_score
        self.assertEqual(ranks[(0, "security_score")], 0)
        # min_resources should be rank 0 for resource_score
        self.assertEqual(ranks[(1, "resource_score")], 0)

    def test_get_scores(self):
        sols = self._make_solutions()
        ranker = SolutionRanker(sols)
        ranker.rank()
        scores = SolutionRanker.get_scores(sols[0])
        self.assertIn("Security", scores)
        self.assertIn("Resources", scores)
        self.assertIn("Resilience", scores)

    def test_cia_weights(self):
        self.assertEqual(CIA_WEIGHTS["read"], 1.0)
        self.assertEqual(CIA_WEIGHTS["write"], 1.5)
        self.assertEqual(CIA_WEIGHTS["avail"], 2.0)

    def test_policy_score_prefers_effective_tightness(self):
        p1 = Phase1Result(strategy="test", satisfiable=True)
        p1.new_risk = [("c1", "c1r1", "read", 5)]
        p2 = Phase2Result(satisfiable=True)
        p2.policy_tightness = {"cpu": 100}
        p2.effective_policy_tightness = {
            ("cpu", "normal"): 40,
            ("dma", "normal"): 60,
        }
        sol = SolutionResult(strategy="test", phase1=p1, phase2=p2)
        SolutionRanker([sol]).rank()
        self.assertEqual(sol.policy_score, 50.0)

    def test_unsatisfiable_scores_zero(self):
        p1 = Phase1Result(strategy="test", satisfiable=False)
        sol = SolutionResult(strategy="test", phase1=p1)
        ranker = SolutionRanker([sol])
        ranker.rank()
        self.assertEqual(sol.security_score, 0.0)
        self.assertEqual(sol.resource_score, 0.0)

    def test_resilience_with_capabilities(self):
        """Resilience score incorporates capability retention."""
        p1 = Phase1Result(strategy="test", satisfiable=True)
        p1.new_risk = [("c1", "c1r1", "read", 5)]
        sc = ScenarioResult(name="test", compromised=[], failed=[],
                            satisfiable=True)
        sc.blast_radii = {"c1": 2}
        sc.capabilities_ok = ["cap1", "cap2"]
        sc.capabilities_degraded = ["cap3"]
        sc.capabilities_lost = []
        sol = SolutionResult(strategy="test", phase1=p1, scenarios=[sc])
        ranker = SolutionRanker([sol])
        ranker.rank()
        self.assertGreater(sol.resilience_score, 0)

    def test_essential_cap_lost_penalizes(self):
        """Essential capability loss reduces resilience score."""
        p1 = Phase1Result(strategy="test", satisfiable=True)
        p1.new_risk = [("c1", "c1r1", "read", 5)]
        sc_good = ScenarioResult(name="good", compromised=[], failed=[],
                                  satisfiable=True)
        sc_good.blast_radii = {"c1": 2}
        sc_good.capabilities_ok = ["cap1"]
        sc_good.capabilities_lost = []

        sc_bad = ScenarioResult(name="bad", compromised=["c1"], failed=[],
                                 satisfiable=True)
        sc_bad.blast_radii = {"c1": 2}
        sc_bad.capabilities_ok = []
        sc_bad.capabilities_lost = ["cap1"]
        sc_bad.essential_caps_lost = ["cap1"]

        sol1 = SolutionResult(strategy="good", phase1=p1, scenarios=[sc_good])
        sol2 = SolutionResult(strategy="bad", phase1=p1, scenarios=[sc_bad])
        SolutionRanker([sol1]).rank()
        SolutionRanker([sol2]).rank()
        self.assertGreater(sol1.resilience_score, sol2.resilience_score)


# ═══════════════════════════════════════════════════════════════════════════
# 6. Comparison Engine Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestComparisonEngine(unittest.TestCase):
    def _make_sols(self):
        sols = []
        for strat, risk_val, luts in [
            ("max_security", 5, 8000),
            ("min_resources", 15, 3000),
            ("balanced", 10, 5000),
        ]:
            p1 = Phase1Result(strategy=strat, satisfiable=True)
            p1.new_risk = [("c1", "c1r1", "read", risk_val)]
            p1.security = {"c1": "zero_trust" if strat == "max_security" else "mac"}
            p1.realtime = {"c1": "runtime_attestation" if strat == "max_security" else "no_realtime"}
            p1.total_luts = luts
            p1.total_power = 1000
            p2 = Phase2Result(satisfiable=True)
            p2.placed_fws = ["fw1"]
            sol = SolutionResult(strategy=strat, label=f"Sol {strat}",
                                 phase1=p1, phase2=p2)
            sols.append(sol)
        SolutionRanker(sols).rank()
        return sols

    def test_generate_all(self):
        sols = self._make_sols()
        engine = ComparisonEngine(sols)
        results = engine.generate_all()
        self.assertEqual(len(results), 3)
        for pros, cons in results:
            self.assertIsInstance(pros, list)
            self.assertIsInstance(cons, list)
            self.assertGreater(len(pros), 0)
            self.assertGreater(len(cons), 0)

    def test_custom_caps(self):
        sols = self._make_sols()
        engine = ComparisonEngine(sols, max_luts=10000, max_power=5000)
        self.assertEqual(engine._max_luts, 10000)
        self.assertEqual(engine._max_power, 5000)

    def test_report_generation(self):
        sols = self._make_sols()
        sols[0].scenarios = [
            ScenarioResult(
                name="sensor_bus_failure",
                compromised=[],
                failed=["sensor_bus"],
                failed_buses=["sensor_bus"],
                satisfiable=True,
                function_scores={"state_estimation": 0},
                function_statuses={"state_estimation": "lost"},
                functions_lost=["state_estimation"],
                function_findings=["state_estimation_lost_under_bus_failure"],
            )
        ]
        sols[0].phase2.closed_loop_repair_intents = [
            {
                "stage": "architecture_generation",
                "status": "pending_architecture_revision",
                "function": "state_estimation",
                "repair": "split_function_support_buses",
                "required_diversity_axis": "bus",
                "minimum_independent_domains": 2,
            }
        ]
        report = generate_report_text(sols, network_name="test_net")
        self.assertIn("DSE SECURITY ANALYSIS REPORT", report)
        self.assertIn("test_net", report)
        self.assertIn("COMPARISON TABLE", report)
        self.assertIn("FUNCTION SUPPORT FINDINGS", report)
        self.assertIn("ARCHITECTURE REPAIR INTENTS", report)
        self.assertIn("Function Deficiencies", report)
        self.assertIn("Repair Intents", report)
        self.assertIn("split_function_support_buses", report)
        self.assertIn("state_estimation", report)
        self.assertIn("lost_under_domain_failure", report)
        self.assertIn("RECOMMENDATIONS", report)


class TestOrchestratorDefaults(unittest.TestCase):
    def test_phase3_backend_defaults_to_asp(self):
        from dse_tool.agents.orchestrator import DEFAULT_SOLVER_CONFIG

        self.assertEqual(DEFAULT_SOLVER_CONFIG["phase3_backend"], "asp")


class TestArchitectureComparisonReport(unittest.TestCase):
    def test_build_summary_without_solutions(self):
        baseline = make_pixhawk6x_platform()
        candidate = make_pixhawk6x_uav_network()
        summary = build_architecture_comparison_summary(baseline, candidate)

        self.assertEqual(summary.baseline_name, "Pixhawk 6X Platform")
        self.assertEqual(summary.candidate_name, "Pixhawk 6X UAV")
        self.assertIn("gps_1", summary.delta.added_components)
        self.assertIn("motor_bus_group", summary.delta.added_redundancy_groups)
        self.assertEqual(summary.baseline_ledger.phase2_zta_cost, 0)
        self.assertEqual(summary.candidate_ledger.phase2_zta_cost, 0)

    def test_format_summary_with_solution_ledgers(self):
        baseline = make_pixhawk6x_platform()
        candidate = make_pixhawk6x_uav_network()

        p1 = Phase1Result(strategy="max_security", satisfiable=True)
        p1.total_luts = 25180
        p1.total_ffs = 19230
        p1.total_power = 507
        p1.new_risk = [("telem_radio", "telem_radio_data", "read", 243)]
        p2 = Phase2Result(satisfiable=True, total_cost=1)
        baseline_sc = ScenarioResult(name="baseline", compromised=[], failed=[], satisfiable=True)
        baseline_sc.total_risk_scaled = 2430
        worst_sc = ScenarioResult(name="group_gps_group_compromise", compromised=["gps_1"], failed=[], satisfiable=True)
        worst_sc.total_risk_scaled = 3469
        sol = SolutionResult(
            strategy="max_security",
            phase1=p1,
            phase2=p2,
            scenarios=[baseline_sc, worst_sc],
        )
        sol.security_score = 73.13
        sol.resource_score = 52.67
        sol.power_score = 49.3
        sol.resilience_score = 44.8

        summary = build_architecture_comparison_summary(
            baseline,
            candidate,
            baseline_solution=sol,
            candidate_solution=sol,
        )
        text = format_architecture_comparison(summary)

        self.assertIn("ARCHITECTURE COMPARISON", text)
        self.assertIn("Added components: camera", text)
        self.assertIn("Phase 1 security overhead: LUTs=25,180", text)
        self.assertIn("Phase 2 ZTA cost: 1", text)
        self.assertIn("Worst scenario: group_gps_group_compromise", text)


class TestArchitectureRepair(unittest.TestCase):
    def _make_shared_bus_state_estimation_model(self) -> NetworkModel:
        return NetworkModel(
            name="Shared Bus State Estimation",
            components=[
                Component("fmu", "processor", "privileged", 1, 1, 1000, 1000, is_master=True, is_receiver=False),
                Component("sensor_bus", "bus", "normal", 1, 1, 1000, 1000, is_receiver=False),
                Component("gps_1", "ip_core", "low", 1, 1, 1000, 1000, direction="input"),
                Component("imu_1", "ip_core", "high", 1, 1, 1000, 1000, direction="input"),
                Component("baro_1", "ip_core", "normal", 1, 1, 1000, 1000, direction="input"),
            ],
            links=[
                ("fmu", "sensor_bus"),
                ("sensor_bus", "gps_1"),
                ("sensor_bus", "imu_1"),
                ("sensor_bus", "baro_1"),
            ],
            buses=["sensor_bus"],
            function_supports=[
                FunctionSupport("state_estimation", "gps_1", "satellite", 90, bus="sensor_bus"),
                FunctionSupport("state_estimation", "imu_1", "inertial", 70, bus="sensor_bus"),
                FunctionSupport("state_estimation", "baro_1", "pressure", 40, bus="sensor_bus"),
            ],
            function_thresholds={"state_estimation": {"ok": 80, "degraded": 50}},
        )

    def test_split_function_support_buses_creates_revised_architecture(self):
        model = self._make_shared_bus_state_estimation_model()
        intent = {
            "stage": "architecture_generation",
            "status": "pending_architecture_revision",
            "function": "state_estimation",
            "repair": "split_function_support_buses",
            "required_diversity_axis": "bus",
            "minimum_independent_domains": 2,
        }

        candidate = apply_architecture_repair_intents(model, [intent])
        candidate_support_buses = {
            support.component: support.bus
            for support in candidate.function_supports
            if support.function == "state_estimation"
        }

        self.assertEqual(model.buses, ["sensor_bus"])
        self.assertEqual(candidate.name, "Shared Bus State Estimation (repaired)")
        self.assertGreaterEqual(len(set(candidate_support_buses.values())), 2)
        self.assertEqual(candidate_support_buses["gps_1"], "sensor_bus")
        self.assertEqual(candidate_support_buses["imu_1"], "imu_1_repair_bus")
        self.assertEqual(candidate_support_buses["baro_1"], "baro_1_repair_bus")
        self.assertIn(("fmu", "imu_1_repair_bus"), candidate.links)
        self.assertIn(("imu_1_repair_bus", "imu_1"), candidate.links)
        self.assertIn(("fmu", "baro_1_repair_bus"), candidate.links)
        self.assertIn(("baro_1_repair_bus", "baro_1"), candidate.links)
        self.assertNotIn(("sensor_bus", "imu_1"), candidate.links)
        self.assertNotIn(("sensor_bus", "baro_1"), candidate.links)

        delta = compare_network_models(model, candidate)
        self.assertIn("imu_1_repair_bus", delta.added_buses)
        self.assertIn("baro_1_repair_bus", delta.added_buses)
        self.assertIn(("imu_1_repair_bus", "imu_1"), delta.added_links)
        self.assertIn(("sensor_bus", "imu_1"), delta.removed_links)

    def test_split_function_support_buses_noops_when_already_diverse(self):
        model = self._make_shared_bus_state_estimation_model()
        model.buses = ["gps_bus", "imu_bus"]
        model.links = [
            ("fmu", "gps_bus"),
            ("gps_bus", "gps_1"),
            ("fmu", "imu_bus"),
            ("imu_bus", "imu_1"),
        ]
        model.function_supports = [
            FunctionSupport("state_estimation", "gps_1", "satellite", 90, bus="gps_bus"),
            FunctionSupport("state_estimation", "imu_1", "inertial", 70, bus="imu_bus"),
        ]
        intent = {
            "function": "state_estimation",
            "repair": "split_function_support_buses",
            "minimum_independent_domains": 2,
        }

        candidate = apply_architecture_repair_intents(model, [intent])
        delta = compare_network_models(model, candidate)

        self.assertEqual(candidate.name, "Shared Bus State Estimation")
        self.assertFalse(delta.has_changes())

    def test_orchestrator_builds_repair_candidate_from_intents(self):
        from dse_tool.agents.orchestrator import DSEOrchestrator

        model = self._make_shared_bus_state_estimation_model()
        intent = {
            "stage": "architecture_generation",
            "status": "pending_architecture_revision",
            "function": "state_estimation",
            "repair": "split_function_support_buses",
            "required_diversity_axis": "bus",
            "minimum_independent_domains": 2,
        }
        p2 = Phase2Result(satisfiable=True)
        p2.closed_loop_repair_intents = [intent]
        sol = SolutionResult(
            strategy="max_security",
            label="Solution 1: Maximum Security",
            phase2=p2,
        )
        orch = DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp="",
            progress_queue=queue.Queue(),
            solver_config={"generate_architecture_repair_candidates": True},
        )
        orch.solutions = [sol]

        candidates = orch._build_architecture_repair_candidates()

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["source_strategy"], "max_security")
        self.assertEqual(candidates[0]["source_label"], "Solution 1: Maximum Security")
        self.assertEqual(candidates[0]["repair_intents"], [intent])
        self.assertIn("imu_1_repair_bus", candidates[0]["model"].buses)
        self.assertIn("baro_1_repair_bus", candidates[0]["delta"].added_buses)
        self.assertIn(("imu_1_repair_bus", "imu_1"), candidates[0]["delta"].added_links)


# ═══════════════════════════════════════════════════════════════════════════
# 7. Executive Summary Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestExecutiveSummary(unittest.TestCase):
    def _make_sols(self):
        sols = []
        for strat, risk_val in [("max_security", 5), ("min_resources", 15), ("balanced", 10)]:
            p1 = Phase1Result(strategy=strat, satisfiable=True)
            p1.new_risk = [("c1", "c1r1", "read", risk_val)]
            p1.total_luts = 5000
            p1.security = {"c1": "zero_trust"}
            p1.realtime = {"c1": "runtime_attestation"}
            p2 = Phase2Result(satisfiable=True)
            p2.placed_fws = ["fw1"]
            p2.policy_servers_active = ["ps0"]
            sc = ScenarioResult(name="baseline", compromised=[], failed=[],
                                satisfiable=True)
            sc.blast_radii = {"c1": 3}
            sol = SolutionResult(strategy=strat, label=f"Sol {strat}",
                                 phase1=p1, phase2=p2, scenarios=[sc])
            sol.security_score = 100 - risk_val
            sol.resilience_score = 70.0
            sols.append(sol)
        return sols

    def test_analyse_returns_summary(self):
        sols = self._make_sols()
        analyser = ExecutiveSummaryAnalyser(sols)
        summary = analyser.analyse()
        self.assertIsInstance(summary, ExecutiveSummary)
        self.assertTrue(len(summary.verdict) > 0)

    def test_adequate_architecture(self):
        sols = self._make_sols()
        analyser = ExecutiveSummaryAnalyser(sols)
        summary = analyser.analyse()
        self.assertTrue(summary.architecture_adequate)

    def test_all_unsat_architecture_inadequate(self):
        sols = []
        for strat in ["max_security", "min_resources", "balanced"]:
            p1 = Phase1Result(strategy=strat, satisfiable=False)
            sol = SolutionResult(strategy=strat, phase1=p1)
            sols.append(sol)
        analyser = ExecutiveSummaryAnalyser(sols)
        summary = analyser.analyse()
        self.assertFalse(summary.architecture_adequate)

    def test_format_produces_text(self):
        sols = self._make_sols()
        analyser = ExecutiveSummaryAnalyser(sols)
        summary = analyser.analyse()
        text = format_executive_summary(summary)
        self.assertIn("EXECUTIVE SECURITY", text)
        self.assertIn("VERDICT", text)

    def test_bottleneck_sorting(self):
        b1 = BottleneckFinding("FEATURE", "MEDIUM", "c1", "d", "r", "i")
        b2 = BottleneckFinding("TOPOLOGY", "CRITICAL", "sys", "d", "r", "i")
        b3 = BottleneckFinding("TRUST", "HIGH", "c2", "d", "r", "i")
        # Simulate the sorting logic
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        category_order = {"TOPOLOGY": 0, "CAPABILITY": 1, "TRUST": 2, "POLICY": 3, "FEATURE": 4}
        items = [b1, b2, b3]
        items.sort(key=lambda b: (severity_order.get(b.severity, 9),
                                   category_order.get(b.category, 9)))
        self.assertEqual(items[0].severity, "CRITICAL")
        self.assertEqual(items[1].severity, "HIGH")


# ═══════════════════════════════════════════════════════════════════════════
# 8. Phase 3 Scenario Generation Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestScenarioGeneration(unittest.TestCase):
    def test_tc9_core_scenarios(self):
        model = make_tc9_network()
        scenarios = generate_scenarios(model, full=False)
        names = {s["name"] for s in scenarios}
        self.assertIn("baseline", names)
        # Should have master compromises
        self.assertIn("sys_cpu_compromise", names)
        self.assertIn("dma_compromise", names)
        # Bus failures
        self.assertIn("noc0_failure", names)
        self.assertIn("noc1_failure", names)
        # PS compromises
        self.assertIn("ps0_compromise", names)
        self.assertIn("ps1_compromise", names)

    def test_tc9_full_scenarios(self):
        model = make_tc9_network()
        scenarios = generate_scenarios(model, full=True)
        names = {s["name"] for s in scenarios}
        # Should have PEP bypass scenarios
        self.assertIn("pep_group_bypass", names)
        self.assertIn("pep_standalone_bypass", names)
        # Should have more scenarios than core
        core = generate_scenarios(model, full=False)
        self.assertGreater(len(scenarios), len(core))

    def test_refsoc_scenarios(self):
        model = make_reference_soc()
        scenarios = generate_scenarios(model, full=False)
        names = {s["name"] for s in scenarios}
        self.assertIn("baseline", names)
        self.assertIn("arm_a53_compromise", names)
        self.assertIn("arm_m4_compromise", names)
        self.assertIn("dma0_compromise", names)
        self.assertIn("ps_main_compromise", names)

    def test_scenario_names_valid(self):
        """All generated scenarios should reference valid ASP components."""
        model = make_tc9_network()
        valid = _valid_asp_components(model)
        scenarios = generate_scenarios(model, full=True)
        for sc in scenarios:
            for c in sc["compromised"]:
                self.assertIn(c, valid, f"Invalid compromised: {c} in {sc['name']}")
            for f in sc["failed"]:
                self.assertIn(f, valid, f"Invalid failed: {f} in {sc['name']}")

    def test_valid_asp_components(self):
        model = make_tc9_network()
        valid = _valid_asp_components(model)
        # Masters
        self.assertIn("sys_cpu", valid)
        self.assertIn("dma", valid)
        # Receivers
        self.assertIn("c1", valid)
        # Buses
        self.assertIn("noc0", valid)
        # PSes
        self.assertIn("ps0", valid)
        # FWs
        self.assertIn("pep_group", valid)

    def test_empty_model_baseline_only(self):
        model = NetworkModel()
        scenarios = generate_scenarios(model, full=False)
        self.assertEqual(len(scenarios), 1)
        self.assertEqual(scenarios[0]["name"], "baseline")

    def test_no_duplicate_scenarios(self):
        model = make_tc9_network()
        scenarios = generate_scenarios(model, full=True)
        names = [s["name"] for s in scenarios]
        self.assertEqual(len(names), len(set(names)), "Duplicate scenario names found")


# ═══════════════════════════════════════════════════════════════════════════
# 9. Clingo Integration Tests (require clingo)
# ═══════════════════════════════════════════════════════════════════════════

class TestClingoIntegration(unittest.TestCase):
    """End-to-end tests using the actual Clingo solver."""

    @classmethod
    def setUpClass(cls):
        """Verify clingo is available and LP files exist."""
        try:
            import clingo
            cls.has_clingo = True
        except ImportError:
            cls.has_clingo = False
        cls.has_lp_files = os.path.isdir(CLINGO_DIR) and os.path.isfile(
            os.path.join(CLINGO_DIR, "init_enc.lp")
        )

    def setUp(self):
        if not self.has_clingo:
            self.skipTest("clingo not available")
        if not self.has_lp_files:
            self.skipTest("LP files not found")

    def test_clingo_runner_basic(self):
        from dse_tool.core.clingo_runner import ClingoRunner
        runner = ClingoRunner(timeout=10)
        result = runner.solve(
            lp_files=[],
            extra_facts="a(1). b(2). c(X) :- a(X). c(X) :- b(X). #show c/1.",
        )
        self.assertEqual(result["status"], "SAT")

    def test_clingo_unsat(self):
        from dse_tool.core.clingo_runner import ClingoRunner
        runner = ClingoRunner(timeout=10)
        result = runner.solve(
            lp_files=[],
            extra_facts="a(1). :- a(1).",
        )
        self.assertEqual(result["status"], "UNSAT")


class TestPhase1Integration(unittest.TestCase):
    """Test Phase 1 integration across representative topologies."""

    @classmethod
    def setUpClass(cls):
        try:
            import ortools  # noqa: F401
            cls.has_ortools = True
        except ImportError:
            cls.has_ortools = False

    def setUp(self):
        if not self.has_ortools:
            self.skipTest("OR-Tools not available")

    def test_tc9_phase1_max_security(self):
        model = make_tc9_network()
        agent = Phase1MathOptAgent(
            network_model=model,
            strategy="max_security",
            timeout=60,
        )
        result = agent.run()
        self.assertTrue(result.satisfiable, "Phase 1 max_security should be SAT")
        self.assertGreater(len(result.security), 0, "Should have security features")
        self.assertGreater(result.total_luts, 0, "Should have LUT usage")

    def test_tc9_phase1_min_resources(self):
        model = make_tc9_network()
        agent = Phase1MathOptAgent(
            network_model=model,
            strategy="min_resources",
            timeout=60,
        )
        result = agent.run()
        self.assertTrue(result.satisfiable, "Phase 1 min_resources should be SAT")

    def test_tc9_phase1_balanced(self):
        model = make_tc9_network()
        agent = Phase1MathOptAgent(
            network_model=model,
            strategy="balanced",
            timeout=60,
        )
        result = agent.run()
        self.assertTrue(result.satisfiable, "Phase 1 balanced should be SAT")

    def test_refsoc_phase1_max_security(self):
        model = make_reference_soc()
        agent = Phase1MathOptAgent(
            network_model=model,
            strategy="max_security",
            timeout=60,
        )
        result = agent.run()
        self.assertTrue(result.satisfiable, "RefSoC Phase 1 should be SAT")
        self.assertGreater(len(result.security), 0)

    def test_opentitan_phase1_profiles_max_security(self):
        for profile in ("OT-A", "OT-B", "OT-C"):
            with self.subTest(profile=profile):
                model = make_opentitan_network(profile)
                agent = Phase1MathOptAgent(
                    network_model=model,
                    strategy="max_security",
                    timeout=120,
                    solver_config={"cbc_threads": 8},
                )
                result = agent.run()
                self.assertTrue(result.satisfiable, f"{profile} Phase 1 should be SAT")
                self.assertGreater(len(result.security), 0)

    def test_pixhawk6x_uav_phase1_max_security(self):
        model = make_pixhawk6x_uav_network()
        agent = Phase1MathOptAgent(
            network_model=model,
            strategy="max_security",
            timeout=120,
            solver_config={"cpsat_threads": 4},
        )
        result = agent.run()
        self.assertTrue(result.satisfiable, "Pixhawk 6X UAV Phase 1 should be SAT")
        self.assertGreater(len(result.security), 0)


class TestPhase2Integration(unittest.TestCase):
    """Test Phase 2 with real Clingo solver."""

    @classmethod
    def setUpClass(cls):
        try:
            import clingo
            cls.has_clingo = True
        except ImportError:
            cls.has_clingo = False
        cls.has_lp = os.path.isfile(os.path.join(CLINGO_DIR, "zta_policy_enc.lp"))
        if cls.has_clingo and cls.has_lp:
            model = make_tc9_network()
            facts = ASPGenerator(model).generate()
            cls.tc9_facts = facts
            # Use CP-SAT for Phase 1 — ASP is too slow for 60s timeout on TC9
            cls.tc9_p1 = Phase1MathOptAgent(
                network_model=model,
                strategy="max_security",
                timeout=60,
                solver_config={"cpsat_threads": 1},
            ).run()

    def setUp(self):
        if not self.has_clingo or not self.has_lp:
            self.skipTest("clingo or LP files not available")

    def test_tc9_phase2(self):
        from dse_tool.agents.phase2_agent import Phase2Agent
        agent = Phase2Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=self.tc9_p1,
            strategy="max_security",
            timeout=60,
            extra_instance_facts=self.tc9_facts,
        )
        result = agent.run()
        self.assertTrue(result.satisfiable, f"TC9 Phase 2 should be SAT: {result.unsat_reason}")
        self.assertGreater(len(result.placed_fws), 0, "Should place firewalls")
        self.assertGreater(len(result.placed_ps), 0, "Should place PS")

    def test_pixhawk6x_dual_ps_phase2_current_optimum(self):
        from dse_tool.agents.phase2_agent import Phase2Agent

        model = make_pixhawk6x_dual_ps_network()
        facts = ASPGenerator(model).generate()
        p1 = Phase1MathOptAgent(
            network_model=model,
            strategy="max_security",
            timeout=120,
            solver_config={"cpsat_threads": 1},
        ).run()
        self.assertTrue(p1.satisfiable, "Pixhawk dual-PS Phase 1 should be SAT")

        p2 = Phase2Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=p1,
            strategy="max_security",
            timeout=120,
            extra_instance_facts=facts,
            solver_config={"clingo_threads": 1},
        ).run()

        self.assertTrue(p2.satisfiable, f"Pixhawk dual-PS Phase 2 should be SAT: {p2.unsat_reason}")
        self.assertEqual(sorted(set(p2.placed_fws)), ["pep_telem1"])
        self.assertEqual(sorted(set(p2.placed_ps)), ["ps_fmu"])

    def test_pixhawk6x_dual_ps_phase2_control_plane_objective(self):
        from dse_tool.agents.phase2_agent import Phase2Agent

        model = make_pixhawk6x_dual_ps_network()
        facts = ASPGenerator(model).generate()
        p1 = Phase1MathOptAgent(
            network_model=model,
            strategy="max_security",
            timeout=120,
            solver_config={"cpsat_threads": 1},
        ).run()
        self.assertTrue(p1.satisfiable, "Pixhawk dual-PS Phase 1 should be SAT")

        p2 = Phase2Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=p1,
            strategy="max_security",
            timeout=120,
            extra_instance_facts=facts,
            solver_config={"clingo_threads": 1, "phase2_objective": "control_plane"},
        ).run()

        self.assertTrue(p2.satisfiable, f"Pixhawk dual-PS control-plane Phase 2 should be SAT: {p2.unsat_reason}")
        self.assertEqual(sorted(set(p2.placed_fws)), ["pep_can1", "pep_can2", "pep_px4io", "pep_telem1"])
        self.assertEqual(sorted(set(p2.placed_ps)), ["ps_fmu", "ps_io"])
        self.assertEqual(p2.resilience_objective_penalty(), 0)


class TestPhase3Integration(unittest.TestCase):
    """Test Phase 3 with real Clingo solver on TC9."""

    @classmethod
    def setUpClass(cls):
        try:
            import clingo
            cls.has_clingo = True
        except ImportError:
            cls.has_clingo = False
        cls.has_lp = os.path.isfile(os.path.join(CLINGO_DIR, "resilience_enc.lp"))
        if cls.has_clingo and cls.has_lp:
            from dse_tool.agents.phase1_agent import Phase1Agent
            from dse_tool.agents.phase2_agent import Phase2Agent
            model = make_tc9_network()
            facts = ASPGenerator(model).generate()
            cls.tc9_facts = facts
            cls.tc9_model = model
            p1_agent = Phase1Agent(
                clingo_dir=CLINGO_DIR, testcase_lp="",
                strategy="max_security", extra_instance_facts=facts, timeout=60,
            )
            cls.tc9_p1 = p1_agent.run()
            p2_agent = Phase2Agent(
                clingo_dir=CLINGO_DIR, testcase_lp="",
                phase1_result=cls.tc9_p1, strategy="max_security",
                timeout=60, extra_instance_facts=facts,
            )
            cls.tc9_p2 = p2_agent.run()

    def setUp(self):
        if not self.has_clingo or not self.has_lp:
            self.skipTest("clingo or LP files not available")

    def test_tc9_phase3_baseline(self):
        if not self.tc9_p1.satisfiable:
            self.skipTest("TC9 Phase 1 was UNSAT")
        from dse_tool.agents.phase3_agent import Phase3Agent
        agent = Phase3Agent(
            clingo_dir=CLINGO_DIR, testcase_lp="",
            phase1_result=self.tc9_p1, phase2_result=self.tc9_p2,
            strategy="max_security", timeout=30,
            extra_instance_facts=self.tc9_facts,
        )
        scenarios = [{"name": "baseline", "compromised": [], "failed": []}]
        results = agent.run(model_scenarios=scenarios)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].satisfiable, "Baseline scenario should be SAT")
        self.assertGreater(len(results[0].blast_radii), 0, "Should have blast radii")

    def test_tc9_phase3_auto_scenarios(self):
        if not self.tc9_p1.satisfiable:
            self.skipTest("TC9 Phase 1 was UNSAT")
        from dse_tool.agents.phase3_agent import Phase3Agent
        scenarios = generate_scenarios(self.tc9_model, full=False)
        agent = Phase3Agent(
            clingo_dir=CLINGO_DIR, testcase_lp="",
            phase1_result=self.tc9_p1, phase2_result=self.tc9_p2,
            strategy="max_security", timeout=30,
            extra_instance_facts=self.tc9_facts,
        )
        results = agent.run(model_scenarios=scenarios)
        self.assertGreater(len(results), 1, "Should have multiple scenarios")
        sat_count = sum(1 for r in results if r.satisfiable)
        self.assertGreater(sat_count, 0, "At least some scenarios should be SAT")

    def test_tc9_phase3_capability_assessment(self):
        """Verify capability assessment atoms are parsed."""
        if not self.tc9_p1.satisfiable:
            self.skipTest("TC9 Phase 1 was UNSAT")
        from dse_tool.agents.phase3_agent import Phase3Agent
        agent = Phase3Agent(
            clingo_dir=CLINGO_DIR, testcase_lp="",
            phase1_result=self.tc9_p1, phase2_result=self.tc9_p2,
            strategy="max_security", timeout=30,
            extra_instance_facts=self.tc9_facts,
        )
        scenarios = [{"name": "baseline", "compromised": [], "failed": []}]
        results = agent.run(model_scenarios=scenarios)
        baseline = results[0]
        if baseline.satisfiable:
            # TC9 has capabilities defined; baseline should show functional status
            total_caps = (len(baseline.capabilities_ok) +
                         len(baseline.capabilities_degraded) +
                         len(baseline.capabilities_lost))
            # With no compromise, should have some OK capabilities
            if total_caps > 0:
                self.assertGreater(len(baseline.capabilities_ok), 0)

    def test_pixhawk6x_dual_ps_control_plane_ps_fmu_compromise(self):
        from dse_tool.agents.phase2_agent import Phase2Agent
        from dse_tool.agents.phase3_agent import Phase3Agent

        model = make_pixhawk6x_dual_ps_network()
        facts = ASPGenerator(model).generate()
        p1 = Phase1MathOptAgent(
            network_model=model,
            strategy="max_security",
            timeout=120,
            solver_config={"cpsat_threads": 1},
        ).run()
        self.assertTrue(p1.satisfiable, "Pixhawk dual-PS Phase 1 should be SAT")

        p2 = Phase2Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=p1,
            strategy="max_security",
            timeout=120,
            extra_instance_facts=facts,
            solver_config={"clingo_threads": 1, "phase2_objective": "control_plane"},
        ).run()
        self.assertTrue(p2.satisfiable, "Pixhawk dual-PS Phase 2 should be SAT")

        p3 = Phase3Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=p1,
            phase2_result=p2,
            strategy="max_security",
            timeout=120,
            extra_instance_facts=facts,
            solver_config={"clingo_threads": 1},
        ).run(model_scenarios=[{"name": "ps_fmu_compromise", "compromised": ["ps_fmu"], "failed": []}])

        self.assertEqual(len(p3), 1)
        scenario = p3[0]
        self.assertTrue(scenario.satisfiable, "ps_fmu compromise scenario should be SAT")
        self.assertEqual(scenario.active_ps_count, 1)
        self.assertEqual(sorted(set(scenario.ungoverned_peps)), ["pep_telem1"])
        self.assertNotIn("pep_px4io", scenario.ungoverned_peps)
        self.assertNotIn("pep_can1", scenario.ungoverned_peps)
        self.assertNotIn("pep_can2", scenario.ungoverned_peps)


# ═══════════════════════════════════════════════════════════════════════════
# 10. Full Pipeline Integration Test
# ═══════════════════════════════════════════════════════════════════════════

class _ClingoLpAvailabilityMixin:
    @classmethod
    def setUpClass(cls):
        try:
            import clingo
            cls.has_clingo = True
        except ImportError:
            cls.has_clingo = False
        cls.has_lp = os.path.isdir(CLINGO_DIR)

    def setUp(self):
        if not self.has_clingo or not self.has_lp:
            self.skipTest("clingo or LP files not available")


class _MathOptAvailabilityMixin:
    @classmethod
    def setUpClass(cls):
        try:
            import ortools  # noqa: F401
            cls.has_ortools = True
        except ImportError:
            cls.has_ortools = False

    def setUp(self):
        if not self.has_ortools:
            self.skipTest("OR-Tools not available")


class TestFullPipeline(_ClingoLpAvailabilityMixin, unittest.TestCase):
    """Full orchestrator pipeline test (TC9 all 3 strategies)."""

    def test_tc9_full_pipeline(self):
        from dse_tool.agents.orchestrator import DSEOrchestrator
        model = make_tc9_network()
        q = queue.Queue()
        orch = DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp="",
            progress_queue=q,
            full_phase3=False,
            phase_timeout=60,
        )
        orch.run()
        self.assertTrue(orch.done, "Orchestrator should be done")
        self.assertEqual(orch.error, "", f"Orchestrator error: {orch.error}")
        self.assertEqual(len(orch.solutions), 3, "Should have 3 solutions")

        for sol in orch.solutions:
            self.assertIsNotNone(sol.phase1)
            self.assertTrue(sol.phase1.satisfiable,
                          f"Phase 1 should be SAT for {sol.strategy}")
            # Phase 2 might be UNSAT in some configs — just verify it ran
            self.assertIsNotNone(sol.phase2)
            # Phase 3 should have scenarios
            self.assertGreater(len(sol.scenarios), 0,
                             f"Should have scenarios for {sol.strategy}")

        # Report should be generated
        self.assertGreater(len(orch.report_text), 100,
                          "Report should be non-empty")
        self.assertIn("DSE SECURITY ANALYSIS REPORT", orch.report_text)

        # Scores should be populated (security_score can be 0 for
        # min_resources when CIA-weighted risk exceeds MAX_RISK_POSSIBLE)
        for sol in orch.solutions:
            if sol.phase1.satisfiable:
                self.assertGreaterEqual(sol.security_score, 0,
                                  f"Security score should be >= 0 for {sol.strategy}")
        # At least the best strategy should have positive security
        best_sec = max(sol.security_score for sol in orch.solutions)
        self.assertGreater(best_sec, 0, "Best strategy should have positive security")

    def test_tc9_executive_summary(self):
        """Verify executive summary works with real pipeline data."""
        from dse_tool.agents.orchestrator import DSEOrchestrator
        model = make_tc9_network()
        q = queue.Queue()
        orch = DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp="",
            progress_queue=q,
            full_phase3=False,
            phase_timeout=60,
        )
        orch.run()
        if not orch.solutions:
            self.skipTest("No solutions produced")

        analyser = ExecutiveSummaryAnalyser(
            orch.solutions,
            max_luts=model.system_caps.get("max_luts", 53200),
            max_power=model.system_caps.get("max_power", 15000),
        )
        summary = analyser.analyse()
        self.assertIsInstance(summary, ExecutiveSummary)
        self.assertTrue(len(summary.verdict) > 0)
        text = format_executive_summary(summary)
        self.assertIn("VERDICT", text)

    def test_pixhawk6x_uav_full_pipeline(self):
        from dse_tool.agents.orchestrator import DSEOrchestrator
        model = make_pixhawk6x_uav_network()
        q = queue.Queue()
        orch = DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp="",
            progress_queue=q,
            full_phase3=False,
            phase_timeout=90,
        )
        orch.run()
        self.assertTrue(orch.done, "Pixhawk orchestrator should be done")
        self.assertEqual(orch.error, "", f"Pixhawk orchestrator error: {orch.error}")
        self.assertEqual(len(orch.solutions), 3, "Pixhawk should produce 3 strategy results")

    def test_tc9_full_pipeline_python_phase3(self):
        from dse_tool.agents.orchestrator import DSEOrchestrator
        model = make_tc9_network()
        q = queue.Queue()
        orch = DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp="",
            progress_queue=q,
            full_phase3=False,
            phase_timeout=60,
            solver_config={"phase3_backend": "python", "clingo_threads": 1, "cpsat_threads": 1},
        )
        orch.run()
        self.assertTrue(orch.done, "Orchestrator should be done")
        self.assertEqual(orch.error, "", f"Orchestrator error: {orch.error}")
        self.assertEqual(len(orch.solutions), 3, "Should have 3 solutions")
        for sol in orch.solutions:
            self.assertIsNotNone(sol.phase1)
            self.assertTrue(sol.phase1.satisfiable, f"Phase 1 should be SAT for {sol.strategy}")
            self.assertIsNotNone(sol.phase2)
            self.assertGreater(len(sol.scenarios), 0, f"Should have scenarios for {sol.strategy}")

    def test_pixhawk6x_uav_full_pipeline_python_phase3(self):
        from dse_tool.agents.orchestrator import DSEOrchestrator
        model = make_pixhawk6x_uav_network()
        q = queue.Queue()
        orch = DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp="",
            progress_queue=q,
            full_phase3=False,
            phase_timeout=90,
            solver_config={"phase3_backend": "python", "clingo_threads": 1, "cpsat_threads": 1},
        )
        orch.run()
        self.assertTrue(orch.done, "Pixhawk orchestrator should be done")
        self.assertEqual(orch.error, "", f"Pixhawk orchestrator error: {orch.error}")
        self.assertEqual(len(orch.solutions), 3, "Pixhawk should produce 3 strategy results")

class _RefSoCPhase1StrategyMixin:
    strategy: str = ""

    def _assert_refsoc_phase1_strategy(self):
        if not self.has_ortools:
            self.skipTest("OR-Tools not available")
        model = make_reference_soc()
        agent = Phase1MathOptAgent(
            network_model=model,
            strategy=self.strategy,
            timeout=60,
        )
        result = agent.run()
        self.assertTrue(result.satisfiable, f"RefSoC Phase 1 {self.strategy} should be SAT")


class TestRefSoCPhase1MaxSecurity(
    _MathOptAvailabilityMixin,
    _RefSoCPhase1StrategyMixin,
    unittest.TestCase,
):
    strategy = "max_security"

    def test_refsoc_phase1_max_security(self):
        self._assert_refsoc_phase1_strategy()


class TestRefSoCPhase1MinResources(
    _MathOptAvailabilityMixin,
    _RefSoCPhase1StrategyMixin,
    unittest.TestCase,
):
    strategy = "min_resources"

    def test_refsoc_phase1_min_resources(self):
        self._assert_refsoc_phase1_strategy()


class TestRefSoCPhase1Balanced(
    _MathOptAvailabilityMixin,
    _RefSoCPhase1StrategyMixin,
    unittest.TestCase,
):
    strategy = "balanced"

    def test_refsoc_phase1_balanced(self):
        self._assert_refsoc_phase1_strategy()


# ═══════════════════════════════════════════════════════════════════════════
# 11. Edge Case and Regression Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):
    def test_empty_solution_ranker(self):
        """Ranker should handle empty solutions gracefully."""
        ranker = SolutionRanker([])
        ranker.rank()  # Should not raise

    def test_single_solution_comparison(self):
        """Comparison with only one solution."""
        p1 = Phase1Result(strategy="only", satisfiable=True)
        p1.new_risk = [("c1", "c1r1", "read", 5)]
        p1.total_luts = 5000
        p1.total_power = 1000
        sol = SolutionResult(strategy="only", phase1=p1)
        SolutionRanker([sol]).rank()
        engine = ComparisonEngine([sol])
        results = engine.generate_all()
        self.assertEqual(len(results), 1)

    def test_scenario_result_empty_compromise(self):
        sc = ScenarioResult(name="empty", compromised=[], failed=[])
        self.assertEqual(sc.total_risk, 0.0)
        self.assertEqual(sc.max_blast_radius, 0)

    def test_phase1_result_empty(self):
        p1 = Phase1Result(strategy="empty", satisfiable=True)
        self.assertEqual(p1.total_risk(), 0)
        self.assertEqual(p1.max_risk_per_asset(), {})

    def test_phase2_result_unsat(self):
        p2 = Phase2Result(satisfiable=False)
        p2.unsat_reason = "test reason"
        self.assertEqual(p2.as_phase3_facts(), "")

    def test_solution_result_no_scenarios(self):
        sol = SolutionResult(strategy="test")
        self.assertEqual(sol.avg_blast_radius(), 0.0)
        self.assertIsNone(sol.worst_scenario())

    def test_generate_report_no_solutions(self):
        report = generate_report_text([])
        self.assertIn("DSE SECURITY ANALYSIS REPORT", report)

    def test_amp_denom_constant(self):
        self.assertEqual(AMP_DENOM, 10)

    def test_mission_capability_dataclass(self):
        cap = MissionCapability(
            name="test_cap",
            description="Test",
            required_services=["svc1"],
            required_components=["comp1"],
            required_access=[("master", "comp1", "read")],
            criticality="essential",
        )
        self.assertEqual(cap.criticality, "essential")
        self.assertEqual(len(cap.required_access), 1)

    def test_redundancy_group(self):
        grp = RedundancyGroup("g1", ["a", "b", "c"])
        self.assertEqual(len(grp.members), 3)


# ═══════════════════════════════════════════════════════════════════════════
# CSV Export
# ═══════════════════════════════════════════════════════════════════════════

class TestCSVExport(unittest.TestCase):
    """Tests for the CSV export function."""

    def _make_solution(self, strategy: str) -> SolutionResult:
        p1 = Phase1Result(strategy=strategy, satisfiable=True)
        p1.security = {"c1": "zero_trust"}
        p1.realtime = {"c1": "runtime_attestation"}
        p1.new_risk = [("c1", "c1r1", "read", 2)]
        p1.total_luts = 5000
        p1.total_power = 3000
        p2 = Phase2Result(satisfiable=True)
        p2.placed_fws = ["fw1"]
        p2.placed_ps = ["ps1"]
        sc = ScenarioResult(name="baseline", compromised=[], failed=[],
                            satisfiable=True)
        sc.blast_radii = {"c1": 3}
        sol = SolutionResult(strategy=strategy, label=strategy,
                             phase1=p1, phase2=p2, scenarios=[sc], complete=True)
        sol.security_score = 80.0
        sol.resilience_score = 70.0
        return sol

    def test_csv_export_creates_file(self):
        """export_csv writes a valid CSV file with correct columns."""
        from dse_tool.core.comparison import export_csv
        import tempfile, csv
        sols = [self._make_solution(s) for s in
                ["max_security", "min_resources", "balanced"]]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                         delete=False) as f:
            path = f.name
        try:
            export_csv(sols, path)
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 3)
            self.assertIn("Strategy", rows[0])
            self.assertIn("Security_Score", rows[0])
            self.assertIn("CIA_C", rows[0])
            self.assertEqual(rows[0]["Strategy"], "max_security")
        finally:
            os.unlink(path)

    def test_csv_export_values(self):
        """CSV values match solution data."""
        from dse_tool.core.comparison import export_csv
        import tempfile, csv
        sols = [self._make_solution("max_security")]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                         delete=False) as f:
            path = f.name
        try:
            export_csv(sols, path)
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                row = next(reader)
            self.assertEqual(row["LUTs"], "5000")
            self.assertEqual(row["Power_mW"], "3000")
            self.assertEqual(row["FWs_Placed"], "1")
            self.assertEqual(row["Security_Score"], "80.0")
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════
# RefSoC Full Pipeline Integration
# ═══════════════════════════════════════════════════════════════════════════

class TestRefSoCFullPipeline(unittest.TestCase):
    """End-to-end pipeline test for RefSoC-16 topology."""

    @classmethod
    def setUpClass(cls):
        try:
            import clingo
            cls.has_clingo = True
        except ImportError:
            cls.has_clingo = False
        cls.has_lp = os.path.isdir(CLINGO_DIR)
        if cls.has_clingo and cls.has_lp:
            cls.model = make_reference_soc()
            cls.gen = ASPGenerator(cls.model)
            cls.facts = cls.gen.generate()

    def test_refsoc_max_security_pipeline(self):
        """RefSoC max_security: Phase 1+2+3 all SAT."""
        if not self.has_clingo or not self.has_lp:
            self.skipTest("clingo or LP files not available")
        from dse_tool.agents.phase2_agent import Phase2Agent
        from dse_tool.agents.phase3_agent import Phase3Agent, generate_scenarios

        # Use CP-SAT for Phase 1 — ASP cannot solve RefSoC within test timeouts
        p1 = Phase1MathOptAgent(
            network_model=self.model, strategy="max_security",
            timeout=60, solver_config={"cpsat_threads": 1},
        ).run()
        self.assertTrue(p1.satisfiable, "RefSoC Phase 1 should be SAT")

        p2 = Phase2Agent(clingo_dir=CLINGO_DIR, testcase_lp="",
                         phase1_result=p1, strategy="max_security",
                         timeout=60, extra_instance_facts=self.facts).run()
        self.assertTrue(p2.satisfiable, "RefSoC Phase 2 should be SAT")

        scenarios = generate_scenarios(self.model, full=False)
        self.assertGreater(len(scenarios), 5, "Should generate 5+ scenarios")

        p3 = Phase3Agent(clingo_dir=CLINGO_DIR, testcase_lp="",
                         phase1_result=p1, phase2_result=p2,
                         strategy="max_security", timeout=30,
                         extra_instance_facts=self.facts
                         ).run(model_scenarios=scenarios)
        sat_sc = [s for s in p3 if s.satisfiable]
        self.assertGreater(len(sat_sc), 0, "At least one scenario should be SAT")
        # Check capabilities are assessed
        any_caps = any(s.capabilities_ok or s.capabilities_lost for s in sat_sc)
        self.assertTrue(any_caps, "RefSoC has 8 capabilities — should be assessed")


# ═══════════════════════════════════════════════════════════════════════════
# Runner
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
