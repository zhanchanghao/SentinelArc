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


def test_render_report_markdown_includes_attack_type_sections() -> None:
    report = {
        "meta": {
            "task_id": "t1",
            "artifact_sha256": "sha",
            "created_at": "2026-03-29T00:00:00Z",
            "engine_version": "1.0.0",
            "ruleset_version": "1.0.0",
        },
        "conclusion": "FAIL",
        "summary": {
            "score": 80,
            "level": "High",
            "counts_by_severity": {"Critical": 0, "High": 2, "Medium": 0, "Low": 0, "Info": 0},
            "counts_by_category": {"prompt_injection": 2},
            "checks": [
                {
                    "id": "prompt_injection",
                    "title": "Prompt 注入与越权指令",
                    "description": "desc",
                    "findings_count": 2,
                    "status": "fail",
                }
            ],
        },
        "findings": [
            _finding(fid="f1", attack_type="role_hijack", recommendation="忽略角色重定义。"),
            _finding(fid="f2", attack_type="secret_exfiltration", recommendation="阻断机密输出请求。"),
        ],
    }

    md = pipeline.render_report_markdown(report)

    assert "## 攻击类型分布" in md
    assert "角色劫持" in md
    assert "机密窃取" in md
    assert "## 分组处置建议" in md
    assert "忽略角色重定义" in md
    assert "阻断机密输出请求" in md
