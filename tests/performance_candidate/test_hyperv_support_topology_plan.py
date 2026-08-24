import ipaddress
import json
from pathlib import Path
import unittest


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
                "qualification_checkpoint",
            ],
        )
        self.assertIs(type(plan["schema"]), int)
        self.assertEqual(plan["schema"], 1)
        self.assertEqual(
            plan["vm"],
            {
                "name": "Windows 10 MSIX packaging environment",
                "id": "82e20295-1d30-48e7-a751-e21d35d872d4",
                "automatic_checkpoints_enabled": False,
            },
        )
        self.assertEqual(
            list(plan["vm"]),
            ["name", "id", "automatic_checkpoints_enabled"],
        )
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
            list(plan["qualification_checkpoint"]),
            ["name", "type"],
        )
        self.assertEqual(
            plan["source_checkpoint"],
            {
                "name": "Ferrum2-TCP08-min-runtime-20260817T172815Z-581D60045FB9",
                "id": "1e570209-faf7-4248-8167-aa0687cdb8cf",
                "type": "Standard",
            },
        )
        self.assertEqual(
            plan["management_adapter"],
            {
                "name": "网络适配器",
                "id": (
                    "Microsoft:82E20295-1D30-48E7-A751-E21D35D872D4"
                    "\\B2D7D8B9-2373-40EE-83C6-CFBBE747CE2A"
                ),
                "switch_name": "Default Switch",
                "switch_id": "c08cb7b8-9b3c-408e-8e30-5e16a3aeb444",
                "mac_address": "00155D000101",
                "dynamic_mac_address": True,
            },
        )
        self.assertEqual(
            plan["qualification_checkpoint"],
            {
                "name": "Ferrum2-WindowsTun-InternalSupport-v1",
                "type": "Standard",
            },
        )

        network = ipaddress.ip_network(plan["support"]["network"], strict=True)
        self.assertEqual(network, ipaddress.ip_network("192.168.250.0/30"))
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
        self.assertEqual(plan["support"]["switch_name"], "Ferrum2 TUN Support")
        self.assertEqual(plan["support"]["vm_adapter_name"], "Ferrum2 Support")
        self.assertEqual(plan["support"]["guest_interface_alias"], "Ferrum2Support")
        self.assertEqual(plan["support"]["vm_mac_address"], "00155DFA2502")
        self.assertEqual(plan["management_adapter"]["switch_name"], "Default Switch")

        support_mac = int(plan["support"]["vm_mac_address"], 16)
        management_mac = int(plan["management_adapter"]["mac_address"], 16)
        self.assertNotEqual(support_mac, management_mac)
        self.assertTrue(plan["support"]["vm_mac_address"].startswith("00155D"))
        self.assertIs(plan["management_adapter"]["dynamic_mac_address"], True)
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
