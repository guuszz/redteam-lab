from __future__ import annotations

import hashlib
import shutil
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from .models import Scenario


class ExportError(ValueError):
    """Raised when a compatible report cannot be produced."""


def export_redreport(
    scenario: Scenario,
    entries: list[dict[str, str]],
    output: str | Path,
    client: str,
    start_date: date,
    end_date: date,
    force: bool = False,
) -> list[Path]:
    root = Path(output)
    if end_date < start_date:
        raise ExportError("end date must be on or after start date")
    if root.is_file():
        raise ExportError(f"output path is a file: {root}")
    if root.exists() and any(root.iterdir()) and not force:
        raise ExportError(f"output directory is not empty: {root}; use --force")

    latest = {entry["step_id"]: entry for entry in entries}
    confirmed = [
        (step, latest[step.id])
        for step in scenario.steps
        if step.finding and step.id in latest and latest[step.id]["status"] == "passed"
    ]
    if not confirmed:
        raise ExportError("no passed steps with finding metadata were found")

    for _, entry in confirmed:
        source = Path(entry["evidence"])
        if not source.is_file():
            raise ExportError(f"evidence file no longer exists: {source}")
        actual_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual_digest != entry["evidence_sha256"]:
            raise ExportError(f"evidence integrity check failed: {source}")

    findings_dir = root / "findings"
    evidence_dir = root / "evidence"
    findings_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    report = {
        "version": 1,
        "engagement": {
            "title": f"{scenario.name} — Red Team Lab",
            "client": client,
            "assessment_type": "Adversary Emulation Lab",
            "start_date": start_date,
            "end_date": end_date,
            "scope": scenario.targets,
            "executive_summary": (
                f"The {scenario.name} exercise confirmed {len(confirmed)} reportable finding(s). "
                "Results were exported from a hashed Red Team Lab evidence journal."
            ),
        },
    }
    report_path = root / "report.yaml"
    _write_yaml(report_path, report)
    written.append(report_path)

    for index, (step, entry) in enumerate(confirmed, start=1):
        assert step.finding is not None
        source = Path(entry["evidence"])
        copied_name = f"RTL-{index:03d}-{source.name}"
        copied = evidence_dir / copied_name
        shutil.copy2(source, copied)
        finding: dict[str, Any] = {
            "id": f"RTL-{index:03d}",
            "title": step.finding.title,
            "severity": step.finding.severity.lower(),
            "status": "open",
            "description": step.finding.description,
            "impact": step.finding.impact,
            "remediation": step.finding.remediation,
            "affected_assets": scenario.targets,
            "mitre": [step.technique],
            "evidence": [
                {
                    "title": f"Evidence for {step.name}",
                    "path": f"evidence/{copied_name}",
                    "description": (
                        f"Red Team Lab journal SHA-256: {entry['evidence_sha256']}"
                    ),
                }
            ],
            "references": step.finding.references,
        }
        if step.finding.cwe:
            finding["cwe"] = step.finding.cwe
        if step.finding.owasp:
            finding["owasp"] = step.finding.owasp
        finding_path = findings_dir / f"RTL-{index:03d}.yaml"
        _write_yaml(finding_path, finding)
        written.extend((finding_path, copied))
    return written


def _write_yaml(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        yaml.safe_dump(value, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
