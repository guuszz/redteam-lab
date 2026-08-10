from __future__ import annotations

import html
import json
import re
from collections import Counter
from pathlib import Path

from .journal import scenario_status
from .models import Scenario

NAVIGATOR_VERSION = "5.3.2"
LAYER_VERSION = "4.5"
ATTACK_VERSION = "19.2"

STATUS_STYLE = {
    "passed": (100, "#22c55e"),
    "failed": (65, "#ef4444"),
    "blocked": (40, "#f59e0b"),
    "skipped": (20, "#64748b"),
    "pending": (0, "#334155"),
}


def build_navigator_layer(
    scenario: Scenario, entries: list[dict[str, str]]
) -> dict[str, object]:
    latest = {entry["step_id"]: entry for entry in entries}
    techniques = []
    for step in scenario.steps:
        status = latest.get(step.id, {}).get("status", "pending")
        score, color = STATUS_STYLE.get(status, STATUS_STYLE["pending"])
        techniques.append(
            {
                "techniqueID": step.technique,
                "tactic": tactic_slug(step.tactic),
                "score": score,
                "color": color,
                "comment": f"{step.name} — {status}",
                "enabled": True,
                "metadata": [
                    {"name": "Step", "value": step.id},
                    {"name": "Status", "value": status},
                    {"name": "Objective", "value": step.objective},
                ],
                "links": [
                    {
                        "label": "MITRE ATT&CK technique",
                        "url": attack_url(step.technique),
                    }
                ],
            }
        )
    return {
        "name": f"{scenario.name} — Red Team Lab",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": scenario.description,
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "aggregateFunction": "average",
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#334155", "#f59e0b", "#22c55e"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": label.title(), "color": style[1]}
            for label, style in STATUS_STYLE.items()
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0f172a",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
        "metadata": [
            {"name": "Scenario", "value": scenario.id},
            {"name": "Generator", "value": "Red Team Lab 0.3.0"},
        ],
    }


def write_navigator_layer(
    scenario: Scenario, entries: list[dict[str, str]], output: str | Path
) -> Path:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(build_navigator_layer(scenario, entries), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return destination


def render_dashboard(scenario: Scenario, entries: list[dict[str, str]]) -> str:
    statuses = [
        (step_id, status if status in STATUS_STYLE else "pending")
        for step_id, status in scenario_status(scenario, entries)
    ]
    status_by_step = dict(statuses)
    counts = Counter(value for _, value in statuses)
    total = len(scenario.steps)
    passed = counts["passed"]
    coverage = round((passed / total) * 100) if total else 0
    tactic_groups: dict[str, list[str]] = {}
    for step in scenario.steps:
        status = status_by_step[step.id]
        _, color = STATUS_STYLE[status]
        card = f"""
        <article class="step">
          <div class="step-head">
            <span class="status" style="--status:{color}">{html.escape(status)}</span>
            <a href="{attack_url(step.technique)}">{html.escape(step.technique)}</a>
          </div>
          <h3>{html.escape(step.name)}</h3>
          <p>{html.escape(step.objective)}</p>
          <code>{html.escape(step.id)}</code>
        </article>"""
        tactic_groups.setdefault(step.tactic, []).append(card)

    sections = "".join(
        f'<section><h2>{html.escape(tactic)}</h2><div class="grid">{"".join(cards)}</div></section>'
        for tactic, cards in tactic_groups.items()
    )
    targets = "".join(f"<li>{html.escape(target)}</li>" for target in scenario.targets)
    count_cards = "".join(
        f'<div class="metric"><strong>{counts[name]}</strong><span>{name}</span></div>'
        for name in STATUS_STYLE
    )
    css = f"""
    :root {{
      --bg:#070b12; --panel:#0d1420; --line:#1e293b;
      --text:#e2e8f0; --muted:#94a3b8; --green:#22c55e;
    }}
    * {{ box-sizing:border-box }}
    body {{
      margin:0; background:var(--bg); color:var(--text);
      font:15px/1.6 Inter,system-ui,sans-serif;
    }}
    main {{ max-width:1120px; margin:auto; padding:48px 24px }}
    header {{
      display:grid; grid-template-columns:1fr 240px; gap:32px; align-items:end;
    }}
    .eyebrow,.status,code {{
      font:12px ui-monospace,monospace; text-transform:uppercase; letter-spacing:.08em;
    }}
    .eyebrow {{ color:var(--green) }}
    h1 {{ font-size:clamp(36px,6vw,72px); line-height:1; margin:.2em 0 }}
    h2 {{ margin-top:48px; border-bottom:1px solid var(--line); padding-bottom:10px }}
    .muted,p,li {{ color:var(--muted) }}
    .coverage strong {{ font-size:54px; display:block }}
    .bar {{ height:8px; background:var(--line); border-radius:8px; overflow:hidden }}
    .bar i {{ display:block; width:{coverage}%; height:100%; background:var(--green) }}
    .metrics {{
      display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin:36px 0;
    }}
    .metric,.step {{
      background:var(--panel); border:1px solid var(--line);
      border-radius:12px; padding:18px;
    }}
    .metric strong {{ font-size:26px; display:block }}
    .metric span {{ color:var(--muted); text-transform:capitalize }}
    .grid {{ display:grid; grid-template-columns:repeat(2,1fr); gap:16px }}
    .step-head {{ display:flex; justify-content:space-between }}
    .status {{
      color:var(--status); border:1px solid var(--status);
      border-radius:99px; padding:2px 9px;
    }}
    a {{ color:#60a5fa; text-decoration:none }}
    code {{ color:#64748b }}
    footer {{
      margin-top:60px; color:#64748b;
      border-top:1px solid var(--line); padding-top:18px;
    }}
    @media(max-width:720px) {{
      header,.grid {{ grid-template-columns:1fr }}
      .metrics {{ grid-template-columns:repeat(2,1fr) }}
    }}
    """
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{html.escape(scenario.name)} — Red Team Lab</title>
  <style>{css}</style>
</head>
<body><main>
  <header><div>
    <span class="eyebrow">Red Team Lab / {html.escape(scenario.id)}</span>
    <h1>{html.escape(scenario.name)}</h1>
    <p>{html.escape(scenario.description)}</p>
  </div><div class="coverage">
    <strong>{coverage}%</strong><span class="muted">completed coverage</span>
    <div class="bar"><i></i></div>
  </div></header>
  <div class="metrics">{count_cards}</div>
  <section><h2>Scope</h2><ul>{targets}</ul></section>
  {sections}
  <footer>Generated from the append-only Red Team Lab evidence journal.</footer>
</main></body></html>"""


def write_dashboard(
    scenario: Scenario, entries: list[dict[str, str]], output: str | Path
) -> Path:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_dashboard(scenario, entries), encoding="utf-8")
    return destination


def tactic_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def attack_url(technique: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"
