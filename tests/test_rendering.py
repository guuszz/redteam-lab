from test_validation import valid_scenario

from redteam_lab.rendering import render_plan


def test_plan_contains_scope_attack_and_digest() -> None:
    plan = render_plan(valid_scenario(), "a" * 64)
    assert "`10.10.10.5`" in plan
    assert "`T1046` — Discovery" in plan
    assert "a" * 64 in plan

