from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from .models import Scenario

STATUSES = {"passed", "failed", "blocked", "skipped"}


def record_step(
    scenario: Scenario,
    step_id: str,
    status: str,
    evidence: str | Path,
    journal_path: str | Path,
    note: str = "",
) -> dict[str, str]:
    if status not in STATUSES:
        raise ValueError(f"status must be one of: {', '.join(sorted(STATUSES))}")
    if step_id not in {step.id for step in scenario.steps}:
        raise ValueError(f"unknown step id: {step_id}")
    evidence_path = Path(evidence)
    if not evidence_path.is_file():
        raise ValueError(f"evidence file does not exist: {evidence_path}")

    entry = {
        "scenario_id": scenario.id,
        "step_id": step_id,
        "status": status,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "evidence": str(evidence_path.resolve()),
        "evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "note": note,
    }
    output = Path(journal_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def read_journal(path: str | Path) -> list[dict[str, str]]:
    source = Path(path)
    if not source.exists():
        return []
    entries = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def scenario_status(scenario: Scenario, entries: list[dict[str, str]]) -> list[tuple[str, str]]:
    latest = {entry["step_id"]: entry["status"] for entry in entries}
    return [(step.id, latest.get(step.id, "pending")) for step in scenario.steps]

