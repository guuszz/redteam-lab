from redteam_lab.models import Scenario, Step
from redteam_lab.validation import is_lab_target, validate_scenario


def valid_scenario() -> Scenario:
    return Scenario(
        id="fixture-lab",
        name="Fixture",
        description="A deterministic lab fixture.",
        targets=["10.10.10.5", "api.target.test"],
        exclusions=[],
        stop_conditions=["Stop on instability."],
        steps=[
            Step(
                id="service-discovery",
                name="Discovery",
                technique="T1046",
                tactic="Discovery",
                objective="Inventory the fixture.",
                expected_evidence=["scan.txt"],
                cleanup="Delete temporary output.",
            )
        ],
    )


def test_private_and_reserved_targets_are_accepted() -> None:
    assert is_lab_target("127.0.0.1")
    assert is_lab_target("192.168.56.10")
    assert is_lab_target("lab.target.test")
    assert is_lab_target("service.localhost")


def test_public_and_unqualified_targets_are_rejected() -> None:
    assert not is_lab_target("8.8.8.8")
    assert not is_lab_target("example.com")


def test_valid_scenario_has_no_errors() -> None:
    assert validate_scenario(valid_scenario()) == []


def test_duplicate_step_and_invalid_technique_are_reported() -> None:
    scenario = valid_scenario()
    duplicate = Step(
        id="service-discovery",
        name="Again",
        technique="invalid",
        tactic="Discovery",
        objective="Repeat.",
        expected_evidence=["again.txt"],
        cleanup="Clean.",
    )
    changed = Scenario(**{**scenario.__dict__, "steps": [*scenario.steps, duplicate]})
    errors = validate_scenario(changed)
    assert any("duplicated" in error for error in errors)
    assert any("T1234" in error for error in errors)

