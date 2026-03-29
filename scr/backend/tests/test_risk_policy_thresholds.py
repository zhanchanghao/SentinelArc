from __future__ import annotations

from engine import pipeline


def _finding(*, fid: str, severity: str, category: str = "prompt_injection") -> pipeline.Finding:
    return pipeline.Finding(
        id=fid,
        rule_id=f"RULE-{fid}",
        category=category,
        severity=severity,
        confidence=0.9,
        file_path="SKILL.md",
        line_range="1",
        snippet_redacted=None,
        evidence={"attack_type": "policy_override"},
        recommendation="demo",
    )


def test_aggregate_fail_on_critical_when_enabled() -> None:
    findings = [_finding(fid="1", severity="Critical")]
    summary = pipeline.aggregate(
        findings,
        fail_on_critical=True,
        high_count_threshold=5,
        score_threshold=60,
    )
    assert summary["conclusion"] == "FAIL"
    assert summary["level"] == "Blocker"
    assert summary["score"] == 7.5


def test_aggregate_pass_on_critical_when_disabled_and_under_other_thresholds() -> None:
    findings = [_finding(fid="1", severity="Critical")]
    summary = pipeline.aggregate(
        findings,
        fail_on_critical=False,
        high_count_threshold=5,
        score_threshold=80,
    )
    # Critical still sets risk level to Blocker, but conclusion follows policy thresholds.
    assert summary["level"] == "Blocker"
    assert summary["conclusion"] == "PASS"
    assert summary["score"] == 7.5


def test_aggregate_fail_on_high_count_threshold() -> None:
    findings = [
        _finding(fid="1", severity="High"),
        _finding(fid="2", severity="High"),
    ]
    summary = pipeline.aggregate(
        findings,
        fail_on_critical=True,
        high_count_threshold=2,
        score_threshold=99,
    )
    assert summary["counts_by_severity"]["High"] == 2
    assert summary["conclusion"] == "FAIL"
    assert summary["score"] == 8.0


def test_aggregate_fail_on_score_threshold_even_without_critical() -> None:
    findings = [
        _finding(fid="1", severity="High"),
        _finding(fid="2", severity="High"),
        _finding(fid="3", severity="High"),
    ]
    summary = pipeline.aggregate(
        findings,
        fail_on_critical=True,
        high_count_threshold=10,
        score_threshold=25,
    )
    assert summary["score_raw"] >= 25
    assert summary["conclusion"] == "FAIL"
    assert summary["score"] == 7.0


def test_aggregate_full_pass_has_full_score() -> None:
    summary = pipeline.aggregate(
        [],
        fail_on_critical=True,
        high_count_threshold=5,
        score_threshold=60,
    )
    assert summary["conclusion"] == "PASS"
    assert summary["score_raw"] == 0
    assert summary["score"] == 10.0

