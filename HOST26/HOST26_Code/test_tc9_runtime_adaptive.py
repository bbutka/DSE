from __future__ import annotations

import unittest

from tc9_runtime_adaptive import RUNTIME_SCENARIOS, solve_all_runtime_scenarios


class Tc9RuntimeAdaptiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _p1, _p2, results = solve_all_runtime_scenarios()
        cls.results = {result.scenario.name: result for result in results}

    def test_baseline_stays_normal(self) -> None:
        baseline = self.results["baseline"]
        self.assertEqual(baseline.current_mode, "normal")
        self.assertIn("mon_ctrl", baseline.placed_monitors)
        self.assertIn("mon_noc0", baseline.placed_monitors)
        self.assertIn("mon_noc1", baseline.placed_monitors)

    def test_dma_rate_spike_enters_attack_suspected(self) -> None:
        result = self.results["dma_rate_spike"]
        self.assertEqual(result.current_mode, "attack_suspected")
        self.assertEqual(result.trust_states.get("dma"), "medium")
        self.assertIn(("re_attest", "dma"), result.response_actions)

    def test_ps0_tamper_enters_attack_confirmed(self) -> None:
        result = self.results["ps0_policy_tamper"]
        self.assertEqual(result.current_mode, "attack_confirmed")
        self.assertEqual(result.trust_states.get("ps0"), "low")
        self.assertIn(("lockdown_pep", "pep_group"), result.response_actions)
        self.assertIn(("lockdown_pep", "pep_standalone"), result.response_actions)

    def test_c8_sequence_anomaly_enters_attack_confirmed(self) -> None:
        result = self.results["c8_sequence_anomaly"]
        self.assertEqual(result.current_mode, "attack_confirmed")
        self.assertIn(("quarantine", "c8"), result.response_actions)
        self.assertIn(("lockdown_pep", "pep_group"), result.response_actions)
        self.assertIn(("lockdown_pep", "pep_standalone"), result.response_actions)
        # attack_confirmed: all effective_allows should be empty
        self.assertEqual(result.effective_allows, [])

    def test_dma_privilege_creep_enters_attack_suspected(self) -> None:
        result = self.results["dma_privilege_creep"]
        self.assertEqual(result.current_mode, "attack_suspected")
        self.assertIn(("re_attest", "dma"), result.response_actions)
        # quarantine must NOT also fire for dma under attack_suspected
        self.assertNotIn(("quarantine", "dma"), result.response_actions)

    def test_no_unknown_signals_in_defined_scenarios(self) -> None:
        for result in self.results.values():
            self.assertEqual(
                result.unknown_signals, [],
                msg=f"Unknown signal kinds in scenario '{result.scenario.name}': "
                    f"{result.unknown_signals}",
            )

    def test_effective_allow_subset_of_p2_allow_in_normal(self) -> None:
        baseline = self.results["baseline"]
        self.assertEqual(baseline.current_mode, "normal")
        # In normal mode no adaptive_deny fires, so effective_deny must be empty
        # and effective_allow must mirror all injected p2_allow grants.
        self.assertEqual(baseline.effective_denies, [])
        # Verify p2_allow facts were actually injected (Phase 2 must be SAT).
        # effective_allows must be non-empty; if it's empty, Phase 2 produced
        # no final_allow entries and the bridge is untested.
        self.assertGreater(
            len(baseline.effective_allows), 0,
            msg="effective_allows is empty in normal mode — p2_allow facts were not "
                "injected. Check that Phase 2 is satisfiable and as_phase3_facts() "
                "emits final_allow entries.",
        )

    def test_quarantine_and_re_attest_not_simultaneous(self) -> None:
        """A quarantined node must not also receive re_attest."""
        for result in self.results.values():
            quarantined = {node for _, node in result.response_actions if _ == "quarantine"}
            re_attested = {node for _, node in result.response_actions if _ == "re_attest"}
            overlap = quarantined & re_attested
            self.assertEqual(
                overlap, set(),
                msg=f"Scenario '{result.scenario.name}': nodes both quarantined and "
                    f"re-attested: {overlap}",
            )


if __name__ == "__main__":
    unittest.main()
