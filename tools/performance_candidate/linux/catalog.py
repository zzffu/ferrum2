"""linux catalog owner."""

from __future__ import annotations


SUMMARY_SCHEMA_VERSION = 8

WARNING_POLICY = {
    "decision_effect": "none",
    "outlier_method": "modified z-score using median absolute deviation",
    "outlier_modified_z_threshold": 3.5,
    "high_variance_rule": "spread exceeds six MADs, or a calibrated noise-band width",
}


WARMUP_SECONDS = frozenset({1, 3, 5, 10})


ACTIVE_SECONDS = frozenset({15, 30, 60})


PAIR_COUNTS = frozenset({6})


PAIR_SCHEDULE = "abba-six-pairs"


MODES = frozenset({"diagnostic", "qualification"})


SCENARIO_CATALOG = {
    "tcp-bulk": ("bytes_per_second", "higher_is_better", "tcp-throughput"),
    "tcp-stream-64k": (
        "bytes_per_second",
        "higher_is_better",
        "tcp-throughput",
    ),
    "tcp-request-1k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "tcp-request-4k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "tcp-request-16k": ("p99_nanoseconds", "lower_is_better", "tcp-request"),
    "dns-udp-concurrency": (
        "queries_per_second",
        "higher_is_better",
        "dns-concurrency",
    ),
    "udp-small-high": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-established",
    ),
    "udp-mtu-1200": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-established",
    ),
    "udp-payload-1472": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-ss-payload",
    ),
    "udp-payload-1500": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-ss-payload",
    ),
    "udp-payload-8192": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-ss-payload",
    ),
    "udp-max-wire-65507": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-ss-payload",
    ),
    "udp-direct-small-128": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-direct",
    ),
    "udp-direct-max-65497": (
        "datagrams_per_second",
        "higher_is_better",
        "udp-direct",
    ),
}


SCENARIO_EVIDENCE = {
    "tcp-bulk": ("shadowsocks", 65_536, None, None),
    "tcp-stream-64k": ("shadowsocks", 65_536, None, None),
    "tcp-request-1k": ("shadowsocks", 1_024, None, None),
    "tcp-request-4k": ("shadowsocks", 4_096, None, None),
    "tcp-request-16k": ("shadowsocks", 16_384, None, None),
    "dns-udp-concurrency": ("dns-direct", 46, None, None),
    "udp-small-high": ("shadowsocks", 128, 138, 186),
    "udp-mtu-1200": ("shadowsocks", 1_200, 1_210, 1_258),
    "udp-payload-1472": ("shadowsocks", 1_472, 1_482, 1_530),
    "udp-payload-1500": ("shadowsocks", 1_500, 1_510, 1_558),
    "udp-payload-8192": ("shadowsocks", 8_192, 8_202, 8_250),
    # 65,449 application bytes fill the AES-2022 response wire to 65,507 bytes.
    "udp-max-wire-65507": ("shadowsocks", 65_449, 65_459, 65_507),
    # SOCKS/IPv4 consumes 10 of its 65,507-byte UDP datagram bound.
    "udp-direct-small-128": ("direct", 128, 138, 128),
    "udp-direct-max-65497": ("direct", 65_497, 65_507, 65_497),
}


TCP_REQUEST_SCENARIOS = (
    "tcp-request-1k",
    "tcp-request-4k",
    "tcp-request-16k",
)


UDP_SS_PAYLOAD_MATRIX = (
    "udp-small-high",
    "udp-mtu-1200",
    "udp-payload-1472",
    "udp-payload-1500",
    "udp-payload-8192",
    "udp-max-wire-65507",
)


UDP_DIRECT_PAYLOAD_BOUNDS = (
    "udp-direct-small-128",
    "udp-direct-max-65497",
)


QUALIFICATION_GROUPS = frozenset(
    {"tcp-frame-capacity", "udp-payload-matrix", "udp-direct-payload-bounds"}
)
FULL_NON_TUN_SELECTION = "full-non-tun"


FULL_NON_TUN_GROUPS = (
    "tcp-frame-capacity",
    "udp-payload-matrix",
    "udp-direct-payload-bounds",
    "dns-udp-concurrency",
)
