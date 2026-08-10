from __future__ import annotations

import re
from ipaddress import ip_address, ip_network

from .models import Scenario

SCENARIO_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
STEP_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
LAB_RANGES = tuple(
    ip_network(value)
    for value in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def validate_scenario(scenario: Scenario) -> list[str]:
    errors: list[str] = []
    if not SCENARIO_ID.fullmatch(scenario.id):
        errors.append("id must be a lowercase slug with 3-64 characters")
    if not scenario.name.strip():
        errors.append("name is required")
    if not scenario.description.strip():
        errors.append("description is required")
    if not scenario.targets:
        errors.append("scope.targets must contain at least one lab target")
    for target in scenario.targets:
        if not is_lab_target(target):
            errors.append(f"target '{target}' is not loopback, private, or a .test/.localhost host")
    if not scenario.stop_conditions:
        errors.append("safety.stop_conditions must contain at least one condition")
    if not scenario.steps:
        errors.append("steps must contain at least one step")

    seen: set[str] = set()
    for index, step in enumerate(scenario.steps, start=1):
        prefix = f"steps[{index}]"
        if not STEP_ID.fullmatch(step.id):
            errors.append(f"{prefix}.id must be a lowercase slug with 3-64 characters")
        if step.id in seen:
            errors.append(f"{prefix}.id '{step.id}' is duplicated")
        seen.add(step.id)
        if not step.name.strip():
            errors.append(f"{prefix}.name is required")
        if not TECHNIQUE_ID.fullmatch(step.technique):
            errors.append(f"{prefix}.technique must match T1234 or T1234.001")
        if not step.tactic.strip():
            errors.append(f"{prefix}.tactic is required")
        if not step.objective.strip():
            errors.append(f"{prefix}.objective is required")
        if not step.expected_evidence:
            errors.append(f"{prefix}.expected_evidence must not be empty")
        if not step.cleanup.strip():
            errors.append(f"{prefix}.cleanup is required")
    return errors


def is_lab_target(target: str) -> bool:
    host = target.strip().lower()
    if host.endswith((".test", ".localhost")) or host == "localhost":
        return True
    try:
        parsed = ip_address(host)
    except ValueError:
        return False
    return any(parsed in network for network in LAB_RANGES)

