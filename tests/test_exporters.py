import hashlib
from datetime import date

import yaml

from redteam_lab.exporters import ExportError, export_redreport
from redteam_lab.models import FindingTemplate, Scenario, Step


def reportable_scenario() -> Scenario:
    finding = FindingTemplate(
        title="Fixture authorization weakness confirmed",
        severity="high",
        description="The fixture accepted access without the expected authorization decision.",
        impact="A lab identity could access a synthetic record assigned to another identity.",
        remediation="Enforce object ownership in the service layer before returning the resource.",
        cwe="CWE-639",
        owasp="API1:2023 Broken Object Level Authorization",
        references=["https://owasp.org/API-Security/"],
    )
    step = Step(
        id="controlled-access",
        name="Controlled access",
        technique="T1190",
        tactic="Initial Access",
        objective="Exercise the fixture path.",
        expected_evidence=["response.txt"],
        cleanup="Reset the fixture.",
        finding=finding,
    )
    return Scenario(
        id="export-fixture",
        name="Export fixture",
        description="Export integration fixture.",
        targets=["api.target.test"],
        exclusions=[],
        stop_conditions=["Stop on instability."],
        steps=[step],
    )


def test_export_creates_redreport_project_and_copies_evidence(tmp_path) -> None:
    evidence = tmp_path / "response.txt"
    evidence.write_text("redacted fixture response", encoding="utf-8")
    entries = [
        {
            "scenario_id": "export-fixture",
            "step_id": "controlled-access",
            "status": "passed",
            "timestamp": "2026-08-10T00:00:00+00:00",
            "evidence": str(evidence),
            "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
            "note": "confirmed",
        }
    ]

    files = export_redreport(
        reportable_scenario(),
        entries,
        tmp_path / "report",
        "Portfolio Lab",
        date(2026, 8, 10),
        date(2026, 8, 10),
    )

    report = yaml.safe_load((tmp_path / "report" / "report.yaml").read_text("utf-8"))
    finding = yaml.safe_load(
        (tmp_path / "report" / "findings" / "RTL-001.yaml").read_text("utf-8")
    )
    assert report["version"] == 1
    assert report["engagement"]["scope"] == ["api.target.test"]
    assert finding["id"] == "RTL-001"
    assert finding["mitre"] == ["T1190"]
    assert finding["cwe"] == "CWE-639"
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    assert digest in finding["evidence"][0]["description"]
    assert (tmp_path / "report" / finding["evidence"][0]["path"]).is_file()
    assert len(files) == 3


def test_export_requires_a_confirmed_finding(tmp_path) -> None:
    try:
        export_redreport(
            reportable_scenario(),
            [],
            tmp_path / "report",
            "Portfolio Lab",
            date(2026, 8, 10),
            date(2026, 8, 10),
        )
    except ExportError as exc:
        assert "no passed steps" in str(exc)
    else:
        raise AssertionError("expected ExportError")


def test_export_rejects_modified_evidence(tmp_path) -> None:
    evidence = tmp_path / "response.txt"
    evidence.write_text("modified", encoding="utf-8")
    entries = [
        {
            "step_id": "controlled-access",
            "status": "passed",
            "evidence": str(evidence),
            "evidence_sha256": "0" * 64,
        }
    ]
    try:
        export_redreport(
            reportable_scenario(),
            entries,
            tmp_path / "report",
            "Portfolio Lab",
            date(2026, 8, 10),
            date(2026, 8, 10),
        )
    except ExportError as exc:
        assert "integrity check failed" in str(exc)
    else:
        raise AssertionError("expected ExportError")
