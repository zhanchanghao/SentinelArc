from __future__ import annotations

from pathlib import Path

from engine import pipeline


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_decode_execute_chain_detected(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# skill\n")
    _write(
        tmp_path / "runner.py",
        "\n".join(
            [
                "import base64",
                "payload = base64.b64decode(user_input)",
                "exec(payload)",
            ]
        ),
    )
    findings = [f for f in pipeline.scan_directory(tmp_path) if f.rule_id == "CHAIN-DECODE-EXEC"]
    assert findings
    assert "dynamic_exec" in findings[0].evidence.get("chain_evidence", [])


def test_decode_without_exec_not_reported_as_chain(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# skill\n")
    _write(tmp_path / "ok.py", "import base64\npayload = base64.b64decode(data)\nprint(payload)\n")
    findings = [f for f in pipeline.scan_directory(tmp_path) if f.rule_id == "CHAIN-DECODE-EXEC"]
    assert findings == []
