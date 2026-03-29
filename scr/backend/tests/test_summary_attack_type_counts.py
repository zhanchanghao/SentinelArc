from __future__ import annotations

from engine import pipeline


def test_aggregate_counts_by_attack_type() -> None:
    findings = [
        pipeline.Finding(
            id="f1",
            rule_id="PROMPT-INJ-IGNORE-SYSTEM",
            category="prompt_injection",
            severity="High",
            confidence=0.9,
            file_path="SKILL.md",
            line_range="1",
            snippet_redacted=None,
            evidence={"attack_type": "policy_override"},
            recommendation="rec1",
        ),
        pipeline.Finding(
            id="f2",
            rule_id="PROMPT-INJ-ROLE-HIJACK",
            category="prompt_injection",
            severity="High",
            confidence=0.9,
            file_path="SKILL.md",
            line_range="2",
            snippet_redacted=None,
            evidence={"attack_type": "role_hijack"},
            recommendation="rec2",
        ),
        pipeline.Finding(
            id="f3",
            rule_id="PROMPT-INJ-SECRET-EXFIL-INTENT",
            category="prompt_injection",
            severity="Critical",
            confidence=0.95,
            file_path="SKILL.md",
            line_range="3",
            snippet_redacted=None,
            evidence={"attack_type": "role_hijack"},
            recommendation="rec3",
        ),
    ]
    summary = pipeline.aggregate(
        findings,
        fail_on_critical=True,
        high_count_threshold=5,
        score_threshold=60,
    )
    attack_counts = summary.get("counts_by_attack_type")
    assert isinstance(attack_counts, dict)
    assert attack_counts.get("policy_override") == 1
    assert attack_counts.get("role_hijack") == 2
