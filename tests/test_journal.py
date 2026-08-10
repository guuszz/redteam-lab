import hashlib

import pytest
from test_validation import valid_scenario

from redteam_lab.journal import read_journal, record_step, scenario_status


def test_record_hashes_evidence_and_updates_status(tmp_path) -> None:
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("fixture result\n", encoding="utf-8")
    journal = tmp_path / "journal.ndjson"

    entry = record_step(valid_scenario(), "service-discovery", "passed", evidence, journal)

    expected = hashlib.sha256(evidence.read_bytes()).hexdigest()
    assert entry["evidence_sha256"] == expected
    assert scenario_status(valid_scenario(), read_journal(journal)) == [
        ("service-discovery", "passed")
    ]


def test_unknown_step_is_rejected(tmp_path) -> None:
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("fixture", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown step"):
        record_step(valid_scenario(), "missing-step", "passed", evidence, tmp_path / "j")


def test_missing_evidence_is_rejected(tmp_path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        record_step(
            valid_scenario(),
            "service-discovery",
            "passed",
            tmp_path / "missing",
            tmp_path / "j",
        )

