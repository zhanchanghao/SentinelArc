from __future__ import annotations

from engine import pipeline


def _finding(*, fid: str, attack_type: str, recommendation: str) -> dict:
    return {
        "id": fid,
        "rule_id": "PROMPT-INJ-TEST",
        "category": "prompt_injection",
        "severity": "High",
        "confidence": 0.9,
        "file_path": "SKILL.md",
        "line_range": "1",
        "snippet_redacted": None,
        "evidence": {"attack_type": attack_type, "chain_evidence": ["prompt_injection_phrase"]},
        "recommendation": recommendation,
    }


def _base_report(findings: list[dict]) -> dict:
    return {
        "meta": {
            "task_id": "t-risk",
            "artifact_sha256": "sha",
            "created_at": "2026-03-29T00:00:00Z",
            "engine_version": "1.0.0",
            "ruleset_version": "1.0.0",
        },
        "conclusion": "FAIL",
        "summary": {
            "score": 88,
            "level": "High",
            "counts_by_severity": {"Critical": 0, "High": len(findings), "Medium": 0, "Low": 0, "Info": 0},
            "counts_by_category": {"prompt_injection": len(findings)},
            "checks": [
                {
                    "id": "prompt_injection",
                    "title": "Prompt 注入与越权指令",
                    "description": "desc",
                    "findings_count": len(findings),
                    "status": "fail",
                }
            ],
        },
        "findings": findings,
    }


def test_render_markdown_uses_default_guidance_for_attack_type_without_recommendation() -> None:
    report = _base_report(
        [
            _finding(fid="f1", attack_type="unknown_attack_type", recommendation=""),
        ]
    )
    md = pipeline.render_report_markdown(report)
    assert "## 分组处置建议" in md
    assert "建议按高风险提示词攻击流程进行人工复核" in md


def test_render_markdown_displays_correlated_attack_chain_label() -> None:
    report = _base_report(
        [
            _finding(fid="f1", attack_type="correlated_attack_chain", recommendation="立即阻断并人工复核。"),
        ]
    )
    md = pipeline.render_report_markdown(report)
    assert "关联攻击链" in md
    assert "立即阻断并人工复核" in md

