import pathlib
import unittest


class UdpHeadroomWorkflowTests(unittest.TestCase):
    def test_workflow_is_amd_fail_closed_and_separates_timed_from_structural(
        self,
    ) -> None:
        workflow = pathlib.Path(
            ".github/workflows/performance-udp-headroom.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("  workflow_call:\n", workflow)
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertIn('vendor_id" != AuthenticAMD', workflow)
        self.assertIn(
            "default candidate diagnostic-default diagnostic-candidate", workflow
        )
        timed = workflow.index("- name: Run two A/A rounds and one six-pair ABBA round")
        diagnostic_build = workflow.index(
            "- name: Build separate default and feature structural diagnostics after ABBA"
        )
        self.assertLess(timed, diagnostic_build)
        self.assertIn(
            'run_schedule "$UDP_HEADROOM_PROFILE_ROOT/timed/aa-1" candidate',
            workflow,
        )
        self.assertIn(
            'run_schedule "$UDP_HEADROOM_PROFILE_ROOT/timed/aa-2" candidate',
            workflow,
        )
        self.assertIn(
            'run_schedule "$UDP_HEADROOM_PROFILE_ROOT/timed/comparison" default',
            workflow,
        )
        self.assertIn("for pair in 1 2 3 4 5 6; do", workflow)
        self.assertIn(
            "for scenario in udp-small-high udp-mtu-1200 udp-payload-8192 udp-max-wire-65507 udp-response-concurrency-32; do",
            workflow,
        )
        self.assertEqual(
            workflow.count('--destination "$UDP_HEADROOM_STAGE"'),
            2,
        )
        self.assertIn(
            '"$UDP_HEADROOM_STAGE/m4-qualification" profile-workload',
            workflow,
        )
        self.assertIn(
            '"$UDP_HEADROOM_STAGE/m4-qualification" udp-worker-workload',
            workflow,
        )
        self.assertEqual(workflow.count('--binary-dir "$UDP_HEADROOM_STAGE"'), 2)
        default_diagnostic = workflow.index(
            'run_diagnostic diagnostic-default "$UDP_HEADROOM_DIAGNOSTIC_DEFAULT_BUILD"'
        )
        candidate_diagnostic = workflow.index(
            'run_diagnostic diagnostic-candidate "$UDP_HEADROOM_DIAGNOSTIC_CANDIDATE_BUILD"'
        )
        self.assertLess(default_diagnostic, candidate_diagnostic)
        self.assertIn("--variant diagnostic-default", workflow)
        self.assertIn("--variant diagnostic-candidate", workflow)
        self.assertIn("local variant=$1", workflow)
        self.assertIn('--variant "$variant"', workflow)
        self.assertIn('assert diagnostic["same_host_same_workload"] is True', workflow)
        self.assertIn('assert default["udp_payload_to_wire_copy_bytes"] > 0', workflow)
        self.assertIn(
            'assert candidate["udp_payload_to_wire_copy_bytes"] == 0', workflow
        )
        self.assertIn('assert candidate["udp_owned_fast_path_hits"] > 0', workflow)
        self.assertIn("gate03_stable_host_satisfied", workflow)
        self.assertIn("gate07_durable_evidence_satisfied", workflow)
        upload = workflow.index("- name: Upload provisional AMD UDP headroom evidence")
        enforce = workflow.index(
            "- name: Enforce provisional default-off closure after upload"
        )
        self.assertLess(upload, enforce)
        upload_block = workflow[upload:enforce]
        self.assertNotIn("${{ env.UDP_HEADROOM_ROOT }}\n", upload_block)
        self.assertNotIn("/targets", upload_block)
        for retained in (
            "UDP_HEADROOM_ENVIRONMENT",
            "UDP_HEADROOM_PLAN",
            "UDP_HEADROOM_QUALIFICATION",
            "UDP_HEADROOM_ROOT }}/builds",
            "UDP_HEADROOM_ROOT }}/logs",
            "UDP_HEADROOM_PROFILE_ROOT",
        ):
            self.assertIn(retained, upload_block)


if __name__ == "__main__":
    unittest.main()
