import pathlib
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


class ReusablePerformanceDispatchTests(unittest.TestCase):
    def test_dispatch_input_count_stays_within_github_limit(self):
        caller_path = WORKFLOWS / "performance-candidate.yml"
        document = yaml.safe_load(caller_path.read_text(encoding="utf-8"))
        dispatch = document[True]["workflow_dispatch"]
        self.assertLessEqual(len(dispatch["inputs"]), 10)
        self.assertIn("campaign_options", dispatch["inputs"])
        parent = dispatch["inputs"]["parent_sha"]
        self.assertFalse(parent["required"])
        self.assertEqual(parent["default"], "0" * 40)

    def test_registered_workflow_dispatches_new_campaigns_from_the_same_commit(self):
        caller = (WORKFLOWS / "performance-candidate.yml").read_text(encoding="utf-8")
        expected = {
            "rule": "performance-rule.yml",
            "build": "performance-build.yml",
            "conditional": "performance-conditional.yml",
            "udp-workers": "performance-udp-workers.yml",
            "udp-headroom": "performance-udp-headroom.yml",
            "frame-size": "performance-frame.yml",
        }
        for campaign, filename in expected.items():
            with self.subTest(campaign=campaign):
                self.assertIn(f"inputs.campaign == '{campaign}'", caller)
                self.assertIn(f"uses: ./.github/workflows/{filename}", caller)
                called = (WORKFLOWS / filename).read_text(encoding="utf-8")
                self.assertIn("  workflow_call:\n", called)

        self.assertNotIn("uses: zzffu/ferrum2/.github/workflows/", caller)
        self.assertIn("candidate_sha: ${{ github.sha }}", caller)
        self.assertIn("source_sha: ${{ github.sha }}", caller)
        self.assertIn("fromJSON(inputs.campaign_options)", caller)

    def test_rule_reusable_call_retains_cross_run_read_only_permissions(self):
        caller = (WORKFLOWS / "performance-candidate.yml").read_text(encoding="utf-8")
        rule = caller.split("  rule-qualification:\n", 1)[1].split(
            "  build-qualification:\n", 1
        )[0]
        self.assertIn("      actions: read\n", rule)
        self.assertIn("      contents: read\n", rule)
        self.assertNotIn("write", rule)


if __name__ == "__main__":
    unittest.main()
