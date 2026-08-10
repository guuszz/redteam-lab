import json
from dataclasses import replace

from test_validation import valid_scenario

from redteam_lab.visualization import (
    ATTACK_VERSION,
    LAYER_VERSION,
    NAVIGATOR_VERSION,
    attack_url,
    build_navigator_layer,
    render_dashboard,
    tactic_slug,
    write_dashboard,
    write_navigator_layer,
)


def entries(status: str = "passed") -> list[dict[str, str]]:
    return [{"step_id": "service-discovery", "status": status}]


def test_navigator_layer_uses_current_format_and_journal_status() -> None:
    layer = build_navigator_layer(valid_scenario(), entries())
    assert layer["versions"] == {
        "attack": ATTACK_VERSION,
        "navigator": NAVIGATOR_VERSION,
        "layer": LAYER_VERSION,
    }
    assert layer["domain"] == "enterprise-attack"
    technique = layer["techniques"][0]
    assert technique["techniqueID"] == "T1046"
    assert technique["score"] == 100
    assert technique["color"] == "#22c55e"
    assert {item["value"] for item in technique["metadata"]} >= {
        "service-discovery",
        "passed",
    }


def test_pending_technique_is_visible_with_zero_score() -> None:
    technique = build_navigator_layer(valid_scenario(), [])["techniques"][0]
    assert technique["score"] == 0
    assert technique["comment"].endswith("pending")


def test_navigator_file_is_valid_json(tmp_path) -> None:
    output = write_navigator_layer(valid_scenario(), entries("blocked"), tmp_path / "layer.json")
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded["techniques"][0]["score"] == 40


def test_dashboard_contains_coverage_status_and_escaped_content() -> None:
    scenario = replace(valid_scenario(), name="Fixture <script>alert(1)</script>")
    markup = render_dashboard(scenario, entries())
    assert "100%" in markup
    assert "service-discovery" in markup
    assert "T1046" in markup
    assert "passed" in markup
    assert "&lt;script&gt;" in markup
    assert "<script>alert" not in markup


def test_dashboard_file_is_standalone_html(tmp_path) -> None:
    output = write_dashboard(valid_scenario(), [], tmp_path / "dashboard.html")
    markup = output.read_text(encoding="utf-8")
    assert markup.startswith("<!doctype html>")
    assert "<script" not in markup
    assert "pending" in markup


def test_tactic_and_attack_urls_are_normalized() -> None:
    assert tactic_slug("Initial Access") == "initial-access"
    assert attack_url("T1074.001").endswith("/T1074/001/")
