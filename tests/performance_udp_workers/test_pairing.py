from __future__ import annotations

import unittest

from tools.performance_udp_workers.pairing import build_trials, pair_members


class PairingTests(unittest.TestCase):
    def test_plan_has_two_aa_rounds_and_all_six_pair_comparisons(self) -> None:
        trials = build_trials()
        self.assertEqual(len(trials), 120)
        self.assertEqual(
            {trial.session_topology for trial in trials},
            {"same-session", "multi-session"},
        )
        self.assertEqual(
            {
                trial.comparison_receive_workers
                for trial in trials
                if trial.phase == "comparison"
            },
            {2, 4, 8},
        )
        self.assertEqual(
            {trial.round for trial in trials if trial.phase == "calibration-aa"},
            {1, 2},
        )

    def test_fixed_pair_order_is_abba(self) -> None:
        self.assertEqual(pair_members(1), ("baseline", "variant"))
        self.assertEqual(pair_members(2), ("variant", "baseline"))
        self.assertEqual(pair_members(3), ("baseline", "variant"))
        self.assertEqual(pair_members(4), ("variant", "baseline"))

    def test_only_server_receive_workers_changes_within_a_pair(self) -> None:
        trials = build_trials()
        selected = [
            trial
            for trial in trials
            if trial.phase == "comparison"
            and trial.session_topology == "multi-session"
            and trial.comparison_receive_workers == 8
            and trial.pair == 1
        ]
        self.assertEqual([trial.server_receive_workers for trial in selected], [1, 8])
        self.assertEqual({trial.logical_sessions for trial in selected}, {32})


if __name__ == "__main__":
    unittest.main()
