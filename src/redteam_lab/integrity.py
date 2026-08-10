from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .models import Scenario


class IntegrityError(ValueError):
    """Raised when an evidence package cannot be trusted or created."""


def generate_keypair(
    private_path: str | Path, public_path: str | Path, force: bool = False
) -> str:
    private_file = Path(private_path)
    public_file = Path(public_path)
    if private_file.resolve() == public_file.resolve():
        raise IntegrityError("private and public key paths must be different")
    existing = [path for path in (private_file, public_file) if path.exists()]
    if existing and not force:
        raise IntegrityError(f"key file already exists: {existing[0]}; use --force")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_file.parent.mkdir(parents=True, exist_ok=True)
    public_file.parent.mkdir(parents=True, exist_ok=True)
    private_file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(private_file, 0o600)
    except OSError:
        pass
    public_file.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return public_key_fingerprint(public_key)


def seal_evidence(
    scenario: Scenario,
    journal_path: str | Path,
    output: str | Path,
    private_key_path: str | Path,
) -> Path:
    journal_file = Path(journal_path)
    if not journal_file.is_file():
        raise IntegrityError(f"journal does not exist: {journal_file}")
    root = Path(output)
    if root.exists() and (root.is_file() or any(root.iterdir())):
        raise IntegrityError(f"output already exists and is not empty: {root}")

    entries = _read_entries(journal_file, scenario.id)
    if not entries:
        raise IntegrityError(f"journal has no entries for scenario: {scenario.id}")
    private_key = _load_private_key(private_key_path)
    fingerprint = public_key_fingerprint(private_key.public_key())

    checked: list[tuple[dict[str, Any], Path, str]] = []
    known_steps = {step.id for step in scenario.steps}
    for entry in entries:
        if entry.get("step_id") not in known_steps:
            raise IntegrityError(f"journal contains unknown step: {entry.get('step_id')}")
        if entry.get("status") not in {"passed", "failed", "blocked", "skipped"}:
            raise IntegrityError(f"journal contains invalid status: {entry.get('status')}")
        source = Path(str(entry.get("evidence", "")))
        if not source.is_file():
            raise IntegrityError(f"evidence file does not exist: {source}")
        digest = _sha256_file(source)
        if digest != entry.get("evidence_sha256"):
            raise IntegrityError(f"journal digest mismatch: {source}")
        checked.append((entry, source, digest))

    artifacts_dir = root / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    journal_copy = root / "journal.ndjson"
    artifacts = []
    package_entries = []
    for index, (entry, source, digest) in enumerate(checked, start=1):
        safe_step = _safe_name(str(entry["step_id"]))
        filename = f"{index:03d}-{safe_step}-{_safe_name(source.name)}"
        copied = artifacts_dir / filename
        shutil.copy2(source, copied)
        packaged_entry = dict(entry)
        packaged_entry["evidence"] = f"artifacts/{filename}"
        package_entries.append(packaged_entry)
        artifacts.append(
            {
                "step_id": entry["step_id"],
                "status": entry["status"],
                "recorded_at": entry["timestamp"],
                "path": f"artifacts/{filename}",
                "sha256": digest,
                "size": copied.stat().st_size,
            }
        )
    journal_copy.write_text(
        "".join(
            json.dumps(entry, ensure_ascii=False) + "\n" for entry in package_entries
        ),
        encoding="utf-8",
    )

    manifest: dict[str, Any] = {
        "version": 1,
        "algorithm": "Ed25519",
        "scenario_id": scenario.id,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "journal": {
            "path": "journal.ndjson",
            "sha256": _sha256_file(journal_copy),
            "source_sha256": _sha256_file(journal_file),
            "entries": len(entries),
        },
        "public_key_sha256": fingerprint,
        "artifacts": artifacts,
    }
    manifest["signature"] = base64.b64encode(
        private_key.sign(canonical_manifest(manifest))
    ).decode("ascii")
    manifest_path = root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest_path


def verify_evidence(manifest_path: str | Path, public_key_path: str | Path) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"could not read manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise IntegrityError("manifest root must be an object")
    if manifest.get("version") != 1 or manifest.get("algorithm") != "Ed25519":
        raise IntegrityError("unsupported manifest version or algorithm")

    public_key = _load_public_key(public_key_path)
    if manifest.get("public_key_sha256") != public_key_fingerprint(public_key):
        raise IntegrityError("public key fingerprint does not match manifest")
    try:
        signature = base64.b64decode(manifest["signature"], validate=True)
        public_key.verify(signature, canonical_manifest(manifest))
    except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
        raise IntegrityError("manifest signature is invalid") from exc

    root = manifest_file.resolve().parent
    journal = manifest.get("journal")
    if not isinstance(journal, dict):
        raise IntegrityError("manifest journal section is invalid")
    _verify_file(root, journal)

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise IntegrityError("manifest has no artifacts")
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise IntegrityError("manifest artifact entry is invalid")
        _verify_file(root, artifact)
    return {
        "scenario_id": manifest.get("scenario_id"),
        "artifacts": len(artifacts),
        "journal_entries": journal.get("entries"),
        "public_key_sha256": manifest.get("public_key_sha256"),
    }


def canonical_manifest(manifest: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise IntegrityError(f"could not load private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise IntegrityError("private key is not Ed25519")
    return key


def _load_public_key(path: str | Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise IntegrityError(f"could not load public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise IntegrityError("public key is not Ed25519")
    return key


def _read_entries(path: Path, scenario_id: str) -> list[dict[str, Any]]:
    entries = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"invalid journal JSON at line {number}") from exc
        if isinstance(entry, dict) and entry.get("scenario_id") == scenario_id:
            entries.append(entry)
    return entries


def _verify_file(root: Path, item: dict[str, Any]) -> None:
    relative = item.get("path")
    if not isinstance(relative, str):
        raise IntegrityError("manifest file path is invalid")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise IntegrityError(f"manifest path escapes package: {relative}") from exc
    if not candidate.is_file():
        raise IntegrityError(f"package file is missing: {relative}")
    if _sha256_file(candidate) != item.get("sha256"):
        raise IntegrityError(f"package digest mismatch: {relative}")
    if "size" in item and candidate.stat().st_size != item.get("size"):
        raise IntegrityError(f"package size mismatch: {relative}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(value: str) -> str:
    cleaned = "".join(
        character if character.isalnum() or character in ".-_" else "-"
        for character in value
    )
    return cleaned.strip(".-") or "evidence.bin"
