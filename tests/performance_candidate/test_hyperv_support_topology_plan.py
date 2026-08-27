import ipaddress
import json
from pathlib import Path
import re
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = ROOT / "tools" / "windows_tun_hyperv_support_topology_plan.json"


def decode_closed_json(payload):
    def reject_duplicate_keys(pairs):
        value = {}
        folded_keys = set()
        for key, item in pairs:
            folded = key.casefold()
            if folded in folded_keys:
                raise ValueError(f"duplicate JSON key: {key}")
            folded_keys.add(folded)
            value[key] = item
        return value

    return json.loads(payload, object_pairs_hook=reject_duplicate_keys)


def load_closed_json(path):
    return decode_closed_json(path.read_text(encoding="utf-8"))


class HyperVSupportTopologyPlanTests(unittest.TestCase):
    def test_plan_is_a_closed_isolated_point_to_point_contract(self):
        plan = load_closed_json(PLAN_PATH)

        self.assertEqual(
            list(plan),
            [
                "schema",
                "vm",
                "source_checkpoint",
                "management_adapter",
                "support",
                "lab_checkpoint",
            ],
        )
        self.assertIs(type(plan["schema"]), int)
        self.assertEqual(plan["schema"], 1)
        self.assertEqual(
            list(plan["vm"]),
            ["name", "id", "automatic_checkpoints_enabled"],
        )
        self.assertIs(type(plan["vm"]["name"]), str)
        self.assertTrue(plan["vm"]["name"].strip())
        vm_id = uuid.UUID(plan["vm"]["id"])
        self.assertNotEqual(vm_id.int, 0)
        self.assertIs(plan["vm"]["automatic_checkpoints_enabled"], False)
        self.assertEqual(
            list(plan["source_checkpoint"]),
            ["name", "id", "type"],
        )
        self.assertEqual(
            list(plan["management_adapter"]),
            [
                "name",
                "id",
                "switch_name",
                "switch_id",
                "mac_address",
                "dynamic_mac_address",
            ],
        )
        self.assertEqual(
            list(plan["support"]),
            [
                "switch_name",
                "switch_type",
                "vm_adapter_name",
                "vm_mac_address",
                "guest_interface_alias",
                "network",
                "host_ipv4",
                "guest_ipv4",
                "prefix_length",
                "gateway",
                "dns_servers",
            ],
        )
        self.assertEqual(
            list(plan["lab_checkpoint"]),
            ["name", "type"],
        )
        source_checkpoint = plan["source_checkpoint"]
        self.assertTrue(source_checkpoint["name"].strip())
        self.assertNotEqual(uuid.UUID(source_checkpoint["id"]).int, 0)
        self.assertEqual(source_checkpoint["type"], "Standard")
        self.assertTrue(plan["lab_checkpoint"]["name"].strip())
        self.assertEqual(plan["lab_checkpoint"]["type"], "Standard")
        self.assertNotEqual(
            source_checkpoint["name"], plan["lab_checkpoint"]["name"]
        )

        management = plan["management_adapter"]
        for field in ("name", "id", "switch_name", "mac_address"):
            self.assertIs(type(management[field]), str)
            self.assertTrue(management[field].strip())
        self.assertNotEqual(uuid.UUID(management["switch_id"]).int, 0)
        self.assertRegex(management["mac_address"], r"^[0-9A-F]{12}$")
        self.assertIs(type(management["dynamic_mac_address"]), bool)
        self.assertTrue(
            management["id"].upper().startswith(f"MICROSOFT:{str(vm_id).upper()}\\")
        )

        network = ipaddress.ip_network(plan["support"]["network"], strict=True)
        self.assertEqual(network.prefixlen, 30)
        self.assertIs(type(plan["support"]["prefix_length"]), int)
        self.assertEqual(plan["support"]["prefix_length"], network.prefixlen)
        self.assertEqual(
            ipaddress.ip_address(plan["support"]["host_ipv4"]),
            list(network.hosts())[0],
        )
        self.assertEqual(
            ipaddress.ip_address(plan["support"]["guest_ipv4"]),
            list(network.hosts())[1],
        )
        self.assertIsNone(plan["support"]["gateway"])
        self.assertIs(type(plan["support"]["dns_servers"]), list)
        self.assertEqual(plan["support"]["dns_servers"], [])
        self.assertEqual(plan["support"]["switch_type"], "Internal")
        for field in (
            "switch_name",
            "vm_adapter_name",
            "guest_interface_alias",
        ):
            self.assertTrue(plan["support"][field].strip())
        self.assertNotEqual(
            plan["support"]["switch_name"], management["switch_name"]
        )
        self.assertNotEqual(
            plan["support"]["vm_adapter_name"], management["name"]
        )
        self.assertTrue(
            re.fullmatch(
                r"00155D[0-9A-F]{6}", plan["support"]["vm_mac_address"]
            )
        )

        support_mac = int(plan["support"]["vm_mac_address"], 16)
        management_mac = int(plan["management_adapter"]["mac_address"], 16)
        self.assertNotEqual(support_mac, management_mac)
        self.assertTrue(plan["support"]["vm_mac_address"].startswith("00155D"))
        self.assertIs(plan["vm"]["automatic_checkpoints_enabled"], False)

    def test_plan_is_utf8_lf_terminated_without_a_bom(self):
        payload = PLAN_PATH.read_bytes()

        self.assertFalse(payload.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(payload.endswith(b"\n"))
        self.assertNotIn(b"\r", payload)

    def test_closed_json_loader_rejects_case_insensitive_duplicate_keys(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            decode_closed_json('{"schema":1,"Schema":2}')


if __name__ == "__main__":
    unittest.main()
