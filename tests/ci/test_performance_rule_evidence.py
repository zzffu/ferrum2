import copy
import pathlib
import tempfile
import unittest

from tools.ci import performance_rule_evidence as evidence


class PerformanceRuleEvidenceAuthorityTests(unittest.TestCase):
    @staticmethod
    def manifest(fields: frozenset[str], schema: str) -> dict[str, object]:
        value: dict[str, object] = {field: None for field in fields}
        value.update(
            {
                "schema": schema,
                "authority": dict(evidence.HOSTED_AMD_PROVISIONAL_AUTHORITY),
                "adoption_claim": False,
                "production_feature_enabled_by_default": False,
            }
        )
        return value

    def test_both_outer_manifests_close_hosted_amd_authority(self) -> None:
        calibration = self.manifest(
            evidence.CALIBRATION_MANIFEST_FIELDS,
            evidence.CALIBRATION_BUNDLE_SCHEMA,
        )
        comparison = self.manifest(
            evidence.COMPARISON_MANIFEST_FIELDS,
            evidence.COMPARISON_BUNDLE_SCHEMA,
        )

        evidence.validate_calibration_manifest_authority(calibration)
        evidence.validate_comparison_manifest_authority(comparison)
        for manifest in (calibration, comparison):
            self.assertEqual(
                manifest["authority"],
                {
                    "scope": "github-hosted-amd-provisional",
                    "performance_authoritative": False,
                    "bare_metal_gate_satisfied": False,
                    "durable_evidence_gate_satisfied": False,
                },
            )
            self.assertFalse(manifest["adoption_claim"])
            self.assertFalse(manifest["production_feature_enabled_by_default"])

    def test_missing_or_broadened_authority_is_rejected(self) -> None:
        baseline = self.manifest(
            evidence.COMPARISON_MANIFEST_FIELDS,
            evidence.COMPARISON_BUNDLE_SCHEMA,
        )
        mutations = {
            "missing": lambda row: row.pop("authority"),
            "extra-outer": lambda row: row.update({"unexpected": False}),
            "extra-authority": lambda row: row["authority"].update(
                {"unexpected": False}
            ),
            "scope": lambda row: row["authority"].update({"scope": "bare-metal"}),
            "authoritative": lambda row: row["authority"].update(
                {"performance_authoritative": True}
            ),
            "integer-false": lambda row: row["authority"].update(
                {"performance_authoritative": 0}
            ),
            "bare-metal": lambda row: row["authority"].update(
                {"bare_metal_gate_satisfied": True}
            ),
            "durable": lambda row: row["authority"].update(
                {"durable_evidence_gate_satisfied": True}
            ),
            "adoption": lambda row: row.update({"adoption_claim": True}),
            "default-feature": lambda row: row.update(
                {"production_feature_enabled_by_default": True}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(baseline)
                mutate(candidate)
                with self.assertRaises(evidence.WorkflowContractError):
                    evidence.validate_comparison_manifest_authority(candidate)

    def test_persisted_manifest_must_equal_recomputed_raw_result(self) -> None:
        expected = self.manifest(
            evidence.COMPARISON_MANIFEST_FIELDS,
            evidence.COMPARISON_BUNDLE_SCHEMA,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "comparison-manifest.json"
            evidence.write_json_atomic(path, expected)
            evidence._read_persisted_manifest(
                path,
                expected=expected,
                expected_fields=evidence.COMPARISON_MANIFEST_FIELDS,
                schema=evidence.COMPARISON_BUNDLE_SCHEMA,
                label="comparison manifest",
            )

            tampered = copy.deepcopy(expected)
            tampered["authority"]["scope"] = "bare-metal"
            evidence.write_json_atomic(path, tampered)
            with self.assertRaisesRegex(evidence.WorkflowContractError, "authority"):
                evidence._read_persisted_manifest(
                    path,
                    expected=expected,
                    expected_fields=evidence.COMPARISON_MANIFEST_FIELDS,
                    schema=evidence.COMPARISON_BUNDLE_SCHEMA,
                    label="comparison manifest",
                )


if __name__ == "__main__":
    unittest.main()
