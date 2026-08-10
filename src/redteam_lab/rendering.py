from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from .models import Scenario


def scenario_digest(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def render_plan(scenario: Scenario, digest: str) -> str:
    lines = [
        f"# Execution plan — {scenario.name}",
        "",
        f"- Scenario: `{scenario.id}`",
        f"- Generated: `{datetime.now(UTC).isoformat(timespec='seconds')}`",
        f"- Source SHA-256: `{digest}`",
        f"- Targets: {', '.join(f'`{value}`' for value in scenario.targets)}",
        "",
        "## Purpose",
        "",
        scenario.description,
        "",
        "## Stop conditions",
        "",
    ]
    lines.extend(f"- {condition}" for condition in scenario.stop_conditions)
    lines.extend(["", "## Sequence", ""])
    for index, step in enumerate(scenario.steps, start=1):
        lines.extend(
            [
                f"### {index}. {step.name}",
                "",
                f"- Step ID: `{step.id}`",
                f"- ATT&CK: `{step.technique}` — {step.tactic}",
                f"- Objective: {step.objective}",
                f"- Expected evidence: {', '.join(step.expected_evidence)}",
                f"- Cleanup: {step.cleanup}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"

