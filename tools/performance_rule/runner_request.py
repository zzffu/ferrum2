"""Current Rust runner measurement arguments and their reported configuration."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from tools.performance_rule.schema import ControlError


@dataclass(frozen=True)
class RunnerRequest:
    profile: str
    configuration: dict[str, Any]

    def validate_report(self, report: dict[str, Any]) -> None:
        if report["profile"] != self.profile or report["configuration"] != self.configuration:
            raise ControlError("runner configuration does not match requested arguments")


def parse_runner_request(arguments: list[str]) -> RunnerRequest:
    if not isinstance(arguments, list) or any(not isinstance(value, str) for value in arguments):
        raise ControlError("runner arguments must be strings")
    valued = {"--profile", "--samples", "--iterations-per-sample", "--workspace-root", "--output"}
    values: dict[str, str | bool] = {}
    position = 0
    while position < len(arguments):
        token = arguments[position]
        position += 1
        flag, equals, value = token.partition("=")
        if flag in values:
            raise ControlError("runner argument is duplicated")
        if flag == "--include-100k" and not equals:
            values[flag] = True
            continue
        if flag not in valued:
            raise ControlError("runner argument is not a current measurement option")
        if not equals:
            if position == len(arguments) or arguments[position].startswith("-"):
                raise ControlError("runner argument requires a value")
            value = arguments[position]
            position += 1
        if not value:
            raise ControlError("runner argument value is empty")
        values[flag] = value
    profile = values.get("--profile", "smoke")
    if profile not in ("smoke", "qualification"):
        raise ControlError("runner profile is invalid")

    def integer(flag: str, default: int, minimum: int, maximum: int) -> int:
        raw = values.get(flag)
        if raw is None:
            return default
        if not isinstance(raw, str) or not re.fullmatch(r"\+?[0-9]{1,20}", raw):
            raise ControlError("runner numeric argument is invalid")
        value = int(raw)
        if not minimum <= value <= maximum:
            raise ControlError("runner numeric argument is outside producer limits")
        return value

    match_sizes = [100] if profile == "smoke" else [100, 1_000, 10_000]
    include_100k = values.get("--include-100k", False)
    if include_100k:
        match_sizes.append(100_000)
    return RunnerRequest(profile, {
        "match_sizes": match_sizes,
        "route_sizes": [1, 32, 64] if profile == "smoke" else [1, 32, 64, 1_000, 10_000],
        "dns_rule_sizes": [1] if profile == "smoke" else [1, 64, 65, 100, 1_000, 10_000],
        "samples": integer("--samples", 101, 5, 1_001),
        "base_iterations_per_sample": integer("--iterations-per-sample", 8_192, 1, 10_000_000),
        "includes_100k": include_100k,
    })
