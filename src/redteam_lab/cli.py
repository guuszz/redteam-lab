from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from .exporters import ExportError, export_redreport
from .integrity import IntegrityError, generate_keypair, seal_evidence, verify_evidence
from .journal import read_journal, record_step, scenario_status
from .models import Scenario, load_scenario
from .rendering import render_plan, scenario_digest
from .validation import validate_scenario
from .visualization import write_dashboard, write_navigator_layer


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="rtl", description="Reproducible Red Team lab journal")
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate a scenario")
    validate.add_argument("scenario")
    plan = commands.add_parser("plan", help="render a signed execution plan")
    plan.add_argument("scenario")
    plan.add_argument("--output", "-o", required=True)
    record = commands.add_parser("record", help="append a step result and evidence hash")
    record.add_argument("scenario")
    record.add_argument("--step", required=True)
    record.add_argument("--status", required=True)
    record.add_argument("--evidence", required=True)
    record.add_argument("--journal", default="evidence/runs/journal.ndjson")
    record.add_argument("--note", default="")
    status = commands.add_parser("status", help="show latest status for every step")
    status.add_argument("scenario")
    status.add_argument("--journal", default="evidence/runs/journal.ndjson")
    export = commands.add_parser("export", help="export confirmed findings")
    export.add_argument("format", choices=["redreport", "navigator"])
    export.add_argument("scenario")
    export.add_argument("--journal", default="evidence/runs/journal.ndjson")
    export.add_argument("--output", "-o", required=True)
    export.add_argument("--client", default="Portfolio Lab")
    export.add_argument("--start-date", type=date.fromisoformat, default=date.today())
    export.add_argument("--end-date", type=date.fromisoformat, default=date.today())
    export.add_argument("--force", action="store_true")
    dashboard = commands.add_parser("dashboard", help="render an offline coverage dashboard")
    dashboard.add_argument("scenario")
    dashboard.add_argument("--journal", default="evidence/runs/journal.ndjson")
    dashboard.add_argument("--output", "-o", required=True)
    keygen = commands.add_parser("keygen", help="generate an Ed25519 signing key pair")
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-key", required=True)
    keygen.add_argument("--force", action="store_true")
    seal = commands.add_parser("seal", help="create a signed evidence package")
    seal.add_argument("scenario")
    seal.add_argument("--journal", default="evidence/runs/journal.ndjson")
    seal.add_argument("--output", "-o", required=True)
    seal.add_argument("--private-key", required=True)
    verify = commands.add_parser("verify", help="verify a signed evidence package")
    verify.add_argument("manifest")
    verify.add_argument("--public-key", required=True)
    return root


def checked_scenario(path: str) -> Scenario:
    scenario, read_errors = load_scenario(path)
    errors = read_errors if scenario is None else validate_scenario(scenario)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
    assert scenario is not None
    return scenario


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "keygen":
        try:
            fingerprint = generate_keypair(
                args.private_key, args.public_key, force=args.force
            )
        except IntegrityError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"KEYPAIR: public_key_sha256={fingerprint}")
        return 0
    if args.command == "verify":
        try:
            result = verify_evidence(args.manifest, args.public_key)
        except IntegrityError as exc:
            print(f"INVALID: {exc}", file=sys.stderr)
            return 2
        print(
            "VERIFIED: "
            f"scenario={result['scenario_id']} "
            f"artifacts={result['artifacts']} "
            f"journal_entries={result['journal_entries']} "
            f"public_key_sha256={result['public_key_sha256']}"
        )
        return 0
    scenario = checked_scenario(args.scenario)
    if args.command == "validate":
        print(f"VALID: {scenario.id} ({len(scenario.steps)} steps)")
        return 0
    if args.command == "plan":
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_plan(scenario, scenario_digest(args.scenario)), encoding="utf-8")
        print(f"PLAN: {output.resolve()}")
        return 0
    if args.command == "record":
        entry = record_step(
            scenario, args.step, args.status, args.evidence, args.journal, args.note
        )
        print(json.dumps(entry, ensure_ascii=False))
        return 0
    if args.command == "status":
        for step_id, value in scenario_status(scenario, read_journal(args.journal)):
            print(f"{step_id:24} {value}")
        return 0
    if args.command == "export":
        if args.format == "navigator":
            output = write_navigator_layer(
                scenario, read_journal(args.journal), args.output
            )
            print(f"EXPORTED: {output.resolve()}")
            return 0
        try:
            files = export_redreport(
                scenario,
                read_journal(args.journal),
                args.output,
                args.client,
                args.start_date,
                args.end_date,
                args.force,
            )
        except ExportError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        for path in files:
            print(f"EXPORTED: {path.resolve()}")
        return 0
    if args.command == "dashboard":
        output = write_dashboard(scenario, read_journal(args.journal), args.output)
        print(f"DASHBOARD: {output.resolve()}")
        return 0
    if args.command == "seal":
        try:
            manifest = seal_evidence(
                scenario, args.journal, args.output, args.private_key
            )
        except IntegrityError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"SEALED: {manifest.resolve()}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
