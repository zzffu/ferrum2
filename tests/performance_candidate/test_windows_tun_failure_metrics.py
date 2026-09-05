"""Compact public-emitter samples through the pure host failure reducer; no HTTP/product."""

import json
import itertools
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RESET_REASONS = ("network_change", "retry")
REBUILD_REASONS = (
    "adapter_damage", "session_damage", "address_damage", "route_damage",
    "dns_damage", "strict_route_damage", "ownership_ledger_damage",
)
RESULT_FAMILIES = (
    ("ferrum2_ruleset_load_total", {}, ("success", "failure", "unchanged"), ("failure",)),
    ("ferrum2_ruleset_refresh_total", {}, ("success", "failure", "unchanged"), ("failure",)),
    ("ferrum2_dns_resolve_total", {
        "resolver": ("system", "configured"),
        "purpose": ("application", "fixed_endpoint", "ruleset_download"),
    }, ("success", "failure"), ("failure",)),
    ("ferrum2_tun_strict_route_filter_install_total", {}, ("success", "failure"), ("failure",)),
    ("ferrum2_outbound_interface_resolution_total", {
        "source": ("outbound_explicit", "auto_detected", "route_default", "system_best_route"),
    }, ("success", "failure"), ("failure",)),
    ("ferrum2_tun_udp_association_route_total", {},
     ("success", "rejected", "failure", "stale_generation"),
     ("rejected", "failure", "stale_generation")),
)
# Provenance: observability/src/metrics/tun.rs label structs and closed arrays;
# observability/tests/network_metrics_contract.rs exact public encoded series.


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required for the pure reducer")
class WindowsTunFailureMetricsTests(unittest.TestCase):
    def reduce_samples(self, samples: list[str]) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "samples.json").write_text(json.dumps(samples), encoding="utf-8")
            script = directory / "reduce.ps1"
            script.write_text(
                "param($Source, $Samples)\n"
                "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
                "$tokens = $null; $errors = $null\n"
                "$ast = [Management.Automation.Language.Parser]::ParseFile($Source, [ref]$tokens, [ref]$errors)\n"
                "if ($errors.Count -ne 0) { throw 'source parse failed' }\n"
                "$functions = @($ast.FindAll({ param($node)\n"
                "  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and\n"
                "    $node.Name -ceq 'Get-Ferrum2FailureCounterTotal'\n}, $true))\n"
                "if ($functions.Count -ne 1) { throw 'pure reducer definition missing' }\n"
                ". ([scriptblock]::Create($functions[0].Extent.Text))\n"
                "$rows = @(foreach ($sample in (Get-Content -Raw -LiteralPath $Samples | ConvertFrom-Json)) {\n"
                "  try {\n"
                "    $value = Get-Ferrum2FailureCounterTotal -Metrics $sample\n"
                "    [pscustomobject]@{ rejected = $false; value = $value }\n"
                "  } catch { [pscustomobject]@{ rejected = $true; value = $null } }\n"
                "})\nConvertTo-Json -InputObject $rows -Depth 5\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(script),
                 str(ROOT / "tools/powershell/Ferrum2.Performance/HostTrial.ps1"),
                 str(directory / "samples.json")],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return json.loads(result.stdout)

    def test_every_closed_lifecycle_failed_series_counts_once(self) -> None:
        samples = []
        for family, reasons in (("reset", RESET_REASONS), ("full_rebuild", REBUILD_REASONS)):
            for reason in reasons:
                for labels in (f'reason="{reason}",result="failed"', f'result="failed",reason="{reason}"'):
                    samples.append(f"ferrum2_network_{family}_total{{{labels}}} 3\n")
        rows = self.reduce_samples(samples)
        self.assertEqual(rows, [{"rejected": False, "value": 3}] * len(samples))

    def test_started_succeeded_and_association_reset_do_not_count_as_failures(self) -> None:
        lines = []
        for family, reasons in (("reset", RESET_REASONS), ("full_rebuild", REBUILD_REASONS)):
            for reason in reasons:
                for result in ("started", "succeeded"):
                    lines.append(f'ferrum2_network_{family}_total{{reason="{reason}",result="{result}"}} 100')
        for operation in ("reset_network", "full_rebuild"):
            for transport in ("tcp", "udp"):
                lines.append(f'ferrum2_network_associations_reset_total{{operation="{operation}",transport="{transport}"}} 100')
        self.assertEqual(self.reduce_samples(["\n".join(lines)]), [{"rejected": False, "value": 0}])

    def test_every_other_closed_result_family_has_an_explicit_failure_subset(self) -> None:
        samples = []
        expected = []
        for family, dimensions, results, failures in RESULT_FAMILIES:
            for values in itertools.product(*dimensions.values()):
                labels = dict(zip(dimensions, values))
                for result in results:
                    labels["result"] = result
                    encoded = ",".join(f'{key}="{value}"' for key, value in labels.items())
                    samples.append(f"{family}{{{encoded}}} 5\n")
                    expected.append({"rejected": False, "value": 5 if result in failures else 0})
        self.assertEqual(self.reduce_samples(samples), expected)

    def test_existing_named_failures_count_once_and_benign_labels_do_not_become_failures(self) -> None:
        sample = '\n'.join((
            'ferrum2_tcp_failures_total{role="client",stage="listen",reason="listener_failure"} 7',
            'ferrum2_udp_failures_total{role="server",stage="relay",reason="receive"} 11',
            'ferrum2_tcp_connections_total{role="client",inbound="socks5",outcome="failed"} 7',
            'ferrum2_udp_datagrams_total{role="server",direction="target_to_client",outcome="failed"} 11',
            'ferrum2_dns_explicit_system_resolve_total{purpose="application"} 100',
            'ferrum2_dns_implicit_system_fallback_total 100',
            'ferrum2_route_match_total{source="inline",type="domain",result="missed"} 100',
        ))
        self.assertEqual(self.reduce_samples([sample]), [{"rejected": False, "value": 18}])

    def test_other_closed_families_reject_unknown_results_instead_of_zero(self) -> None:
        samples = []
        for family, dimensions, _, _ in RESULT_FAMILIES:
            labels = {key: values[0] for key, values in dimensions.items()}
            labels["result"] = "unknown"
            encoded = ",".join(f'{key}="{value}"' for key, value in labels.items())
            samples.append(f"{family}{{{encoded}}} 1\n")
        self.assertEqual(self.reduce_samples(samples), [{"rejected": True, "value": None}] * len(samples))

    def test_existing_name_detection_is_not_narrowed_to_the_current_emitter_catalog(self) -> None:
        sample = "ferrum2_future_failure_total 13\nferrum2_future_drop_total 2\n"
        self.assertEqual(self.reduce_samples([sample]), [{"rejected": False, "value": 15}])

    def test_failure_delta_includes_failed_labels_and_preserves_existing_exclusions(self) -> None:
        before = '\n'.join((
            'ferrum2_network_reset_total{reason="retry",result="failed"} 2',
            'ferrum2_network_full_rebuild_total{reason="route_damage",result="failed"} 3',
            'ferrum2_tun_packets_rejected_total{reason="family_disabled"} 400',
            'ferrum2_tun_packets_rejected_total{reason="invalid_destination"} 500',
            'ferrum2_tun_reassembly_dropped_overlap_total 7',
        ))
        after = before.replace('result="failed"} 2', 'result="failed"} 5').replace(
            'result="failed"} 3', 'result="failed"} 8'
        )
        self.assertEqual(self.reduce_samples([before, after]), [
            {"rejected": False, "value": 12}, {"rejected": False, "value": 20},
        ])

    def test_invalid_closed_lifecycle_labels_cannot_be_reported_as_zero(self) -> None:
        labels = (
            'reason="retry"', 'result="failed"', 'reason="unknown",result="failed"',
            'reason="retry",result="unknown"', 'reason="retry",result="failed",result="succeeded"',
            'reason="retry",result="failed",extra="unexpected"',
        )
        samples = [f"ferrum2_network_reset_total{{{label}}} 1\n" for label in labels]
        self.assertEqual(self.reduce_samples(samples), [{"rejected": True, "value": None}] * len(samples))
