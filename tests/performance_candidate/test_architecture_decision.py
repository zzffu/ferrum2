import copy
import json
import pathlib
import tempfile
import unittest

from tools.performance_candidate import architecture_decision
from tools.performance_candidate.json_contract import CandidateControlError


class ArchitectureDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def write(self, value: object) -> pathlib.Path:
        path = self.root / "decisions.json"
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def test_closed_decisions_preserve_tcp_fairness_and_external_boundaries(self):
        record = architecture_decision.create_architecture_decisions(
            source_sha="a" * 40, source_tree="b" * 40
        )
        decisions = {row["item_id"]: row for row in record["decisions"]}

        self.assertEqual(
            decisions["TCP-06"]["decision"],
            "SUPERSEDED_BY_FAIRNESS_INVARIANT",
        )
        self.assertIn("at most one successful read", decisions["TCP-06"]["invariant"])
        self.assertEqual(decisions["LINUX-BUSY-POLL"]["decision"], "NOT_ADOPTED")
        self.assertEqual(
            decisions["WIN-01-LOCK-ETW"]["decision"], "EXTERNAL_LAB_REQUIRED"
        )
        self.assertFalse(record["performance_authoritative"])
        architecture_decision.load_architecture_decisions(self.write(record))

    def test_decision_mutation_and_unknown_fields_fail_closed(self):
        record = architecture_decision.create_architecture_decisions(
            source_sha="a" * 40, source_tree="b" * 40
        )
        mutated = copy.deepcopy(record)
        mutated["decisions"][0]["decision"] = "ADOPTED"
        with self.assertRaisesRegex(CandidateControlError, "values changed"):
            architecture_decision.load_architecture_decisions(self.write(mutated))

        unexpected = copy.deepcopy(record)
        unexpected["authority"] = "hosted"
        with self.assertRaisesRegex(CandidateControlError, "schema mismatch"):
            architecture_decision.load_architecture_decisions(self.write(unexpected))


if __name__ == "__main__":
    unittest.main()
