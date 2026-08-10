from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class FindingTemplate:
    title: str
    severity: str
    description: str
    impact: str
    remediation: str
    cwe: str | None
    owasp: str | None
    references: list[str]


@dataclass(frozen=True)
class Step:
    id: str
    name: str
    technique: str
    tactic: str
    objective: str
    expected_evidence: list[str]
    cleanup: str
    finding: FindingTemplate | None = None


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    description: str
    targets: list[str]
    exclusions: list[str]
    stop_conditions: list[str]
    steps: list[Step]


def load_scenario(path: str | Path) -> tuple[Scenario | None, list[str]]:
    source = Path(path)
    try:
        raw: Any = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return None, [f"could not read scenario: {exc}"]

    if not isinstance(raw, dict):
        return None, ["scenario root must be a mapping"]

    scope = raw.get("scope") if isinstance(raw.get("scope"), dict) else {}
    safety = raw.get("safety") if isinstance(raw.get("safety"), dict) else {}
    raw_steps = raw.get("steps") if isinstance(raw.get("steps"), list) else []

    steps = []
    for item in raw_steps:
        if not isinstance(item, dict):
            continue
        raw_finding = item.get("finding") if isinstance(item.get("finding"), dict) else None
        finding = (
            FindingTemplate(
                title=str(raw_finding.get("title", "")),
                severity=str(raw_finding.get("severity", "")),
                description=str(raw_finding.get("description", "")),
                impact=str(raw_finding.get("impact", "")),
                remediation=str(raw_finding.get("remediation", "")),
                cwe=_optional_string(raw_finding.get("cwe")),
                owasp=_optional_string(raw_finding.get("owasp")),
                references=_strings(raw_finding.get("references")),
            )
            if raw_finding
            else None
        )
        steps.append(
            Step(
                id=str(item.get("id", "")),
                name=str(item.get("name", "")),
                technique=str(item.get("technique", "")),
                tactic=str(item.get("tactic", "")),
                objective=str(item.get("objective", "")),
                expected_evidence=_strings(item.get("expected_evidence")),
                cleanup=str(item.get("cleanup", "")),
                finding=finding,
            )
        )

    return (
        Scenario(
            id=str(raw.get("id", "")),
            name=str(raw.get("name", "")),
            description=str(raw.get("description", "")),
            targets=_strings(scope.get("targets")),
            exclusions=_strings(scope.get("exclusions")),
            stop_conditions=_strings(safety.get("stop_conditions")),
            steps=steps,
        ),
        [],
    )


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))]


def _optional_string(value: Any) -> str | None:
    return str(value) if isinstance(value, (str, int, float)) else None

