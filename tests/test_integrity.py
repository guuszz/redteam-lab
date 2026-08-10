import json

import pytest
from test_validation import valid_scenario

from redteam_lab.integrity import (
    IntegrityError,
    generate_keypair,
    seal_evidence,
    verify_evidence,
)
from redteam_lab.journal import record_step


def sealed_fixture(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    fingerprint = generate_keypair(private_key, public_key)
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("synthetic evidence\n", encoding="utf-8")
    journal = tmp_path / "journal.ndjson"
    record_step(valid_scenario(), "service-discovery", "passed", evidence, journal)
    package = tmp_path / "package"
    manifest = seal_evidence(valid_scenario(), journal, package, private_key)
    return manifest, public_key, fingerprint


def test_keygen_seal_and_verify_round_trip(tmp_path) -> None:
    manifest, public_key, fingerprint = sealed_fixture(tmp_path)
    result = verify_evidence(manifest, public_key)
    assert result == {
        "scenario_id": "fixture-lab",
        "artifacts": 1,
        "journal_entries": 1,
        "public_key_sha256": fingerprint,
    }


def test_manifest_is_canonical_and_contains_relative_paths(tmp_path) -> None:
    manifest, _, _ = sealed_fixture(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["algorithm"] == "Ed25519"
    assert payload["journal"]["path"] == "journal.ndjson"
    assert payload["artifacts"][0]["path"].startswith("artifacts/")
    assert len(payload["signature"]) > 80


def test_modified_artifact_is_rejected(tmp_path) -> None:
    manifest, public_key, _ = sealed_fixture(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    artifact = manifest.parent / payload["artifacts"][0]["path"]
    artifact.write_text("tampered", encoding="utf-8")
    with pytest.raises(IntegrityError, match="digest mismatch"):
        verify_evidence(manifest, public_key)


def test_modified_manifest_is_rejected(tmp_path) -> None:
    manifest, public_key, _ = sealed_fixture(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["scenario_id"] = "tampered-scenario"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(IntegrityError, match="signature is invalid"):
        verify_evidence(manifest, public_key)


def test_keygen_refuses_to_overwrite_existing_key(tmp_path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(private_key, public_key)
    with pytest.raises(IntegrityError, match="already exists"):
        generate_keypair(private_key, public_key)


def test_keygen_requires_distinct_paths(tmp_path) -> None:
    path = tmp_path / "same.pem"
    with pytest.raises(IntegrityError, match="must be different"):
        generate_keypair(path, path)
