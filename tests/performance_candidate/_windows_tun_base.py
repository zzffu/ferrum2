import copy
import unittest

from tests.performance_candidate._shared_fixture import WINDOWS_TUN_POLICY_PATH
from tools.performance_candidate.windows_tun import policy as windows_policy
from tools.performance_candidate.windows_tun import recipe as windows_recipe
from tools.performance_candidate.windows_tun import udp_schema

class WindowsTunBase(unittest.TestCase):
    CONTROLLER_BUNDLE_SHA256 = "c" * 64
    AA_SHA = "1" * 40
    PARENT_SHA = "2" * 40
    CANDIDATE_SHA = "3" * 40
    def topology_environment() -> dict[str, object]:
        return {
            "checkpoint_id": "81000000-0000-4000-8000-000000000001",
            "topology_manifest_sha256": "8" * 64,
            "topology_plan_sha256": "9" * 64,
            "support_switch_id": "82000000-0000-4000-8000-000000000002",
        }

    def policy(self, *, calibrated: bool = False) -> dict[str, object]:
        policy = windows_policy.load_windows_tun_policy(
            WINDOWS_TUN_POLICY_PATH,
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        if not calibrated:
            return policy
        environment = {
            **windows_recipe.WINDOWS_TUN_GUEST,
            **self.topology_environment(),
            "recipe_sha256": windows_recipe.recipe_sha256(
                self.CONTROLLER_BUNDLE_SHA256
            ),
            "controller_bundle_sha256": self.CONTROLLER_BUNDLE_SHA256,
            "guest_build": "19045.6216",
            "cpu_model": "Synthetic CPU",
            "cpu_count": 8,
            "memory_bytes": 17_179_869_184,
            "power_plan_guid": "381b4222-f694-41f0-9685-ff5bb260df2e",
        }
        digest = "4" * 64
        for scenario in policy["scenarios"].values():
            for entry in scenario["metrics"].values():
                entry.update(
                    {
                        "noise_band_percent": 2.0,
                        "regression_threshold_percent": -5.0,
                        "adoption_threshold_percent": 5.0,
                        "minimum_pairs": 6,
                        "minimum_wins": 4,
                        "minimum_losses": 4,
                        "calibration_source": f"artifact:test-aa@sha256:{digest}",
                        "calibration_artifact_sha256": digest,
                        "calibration_environment": copy.deepcopy(environment),
                    }
                )
        windows_policy.validate_windows_tun_policy(
            policy, controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256
        )
        return policy

    def environment(self) -> dict[str, object]:
        return {
            **windows_recipe.WINDOWS_TUN_GUEST,
            **self.topology_environment(),
            "guest_build": "19045.6216",
            "cpu_model": "Synthetic CPU",
            "cpu_count": 8,
            "memory_bytes": 17_179_869_184,
            "power_plan_guid": "381b4222-f694-41f0-9685-ff5bb260df2e",
        }

    @staticmethod
    def udp_association_source_preflight() -> dict[str, object]:
        dynamic_lines = [
            "Protocol udp Dynamic Port Range",
            "---------------------------------",
            "Start Port      : 49152",
            "Number of Ports : 16384",
        ]
        excluded_lines = [
            "Protocol udp Port Exclusion Ranges",
            "Start Port    End Port",
            "----------    --------",
            "      5357        5357",
            "     50000       50059     *",
        ]
        return {
            "schema": udp_schema.WINDOWS_TUN_UDP_SOURCE_PREFLIGHT_SCHEMA,
            "captured_utc": "2026-08-22T00:00:00.0000000Z",
            "source_contract": {
                "adapter_name": "Ferrum2Perf",
                "source_ip": windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4,
                "source_prefix_length": (
                    windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PREFIX_LENGTH
                ),
                "source_port_first": (
                    windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST
                ),
                "source_port_last": (
                    windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST
                ),
                "source_port_count": (
                    windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_COUNT
                ),
            },
            "adapter": {
                "match_count": 1,
                "retained_count": 1,
                "matches": [
                    {
                        "name": "Ferrum2Perf",
                        "interface_description": "Wintun Userspace Tunnel",
                        "interface_index": 17,
                        "status": "Up",
                        "mac_address": "",
                    }
                ],
            },
            "ip_owner": {
                "match_count": 1,
                "retained_count": 1,
                "matches": [
                    {
                        "ip_address": (
                            windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4
                        ),
                        "prefix_length": (
                            windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PREFIX_LENGTH
                        ),
                        "interface_index": 17,
                        "interface_alias": "Ferrum2Perf",
                        "address_state": "Preferred",
                        "prefix_origin": "Manual",
                        "suffix_origin": "Manual",
                    }
                ],
            },
            "udp_endpoint_conflicts": {
                "count": 0,
                "retained_count": 0,
                "truncated": False,
                "endpoints": [],
            },
            "dynamic_port_udp": {
                "command": "netsh.exe interface ipv4 show dynamicport udp",
                "exit_code": 0,
                "total_lines": len(dynamic_lines),
                "truncated": False,
                "lines": dynamic_lines,
            },
            "dynamic_port_range": {
                "first_port": 49_152,
                "last_port": 65_535,
                "port_count": 16_384,
            },
            "dynamic_port_intersects_source": False,
            "excluded_port_ranges_udp": {
                "command": (
                    "netsh.exe interface ipv4 show excludedportrange protocol=udp"
                ),
                "exit_code": 0,
                "total_lines": len(excluded_lines),
                "truncated": False,
                "lines": excluded_lines,
            },
            "excluded_port_ranges": [
                {"first_port": 5_357, "last_port": 5_357},
                {"first_port": 50_000, "last_port": 50_059},
            ],
            "excluded_port_intersections": [],
            "valid": True,
            "violations": [],
            "errors": [],
        }
