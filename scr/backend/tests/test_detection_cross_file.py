from __future__ import annotations

from pathlib import Path

from engine import pipeline


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_cross_file_decode_exec_chain_detected_with_shared_token(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# skill\n")
    _write(
        tmp_path / "a.py",
        "\n".join(
            [
                "import base64",
                "payload = base64.b64decode(input_data)",
            ]
        ),
    )
    _write(tmp_path / "b.py", "exec(payload)\n")

    findings = [f for f in pipeline.scan_directory(tmp_path) if f.rule_id == "CHAIN-DECODE-EXEC-CROSSFILE"]
    assert findings
    ev = findings[0].evidence
    assert ev.get("token") == "payload"
    assert ev.get("source_file") == "a.py"
    assert ev.get("sink_file") == "b.py"
    assert "cross_file_link" in ev.get("chain_evidence", [])


def test_cross_file_decode_exec_chain_not_detected_without_shared_token(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# skill\n")
    _write(tmp_path / "decode.py", "import base64\ndecoded_payload = base64.b64decode(buf)\n")
    _write(tmp_path / "exec.py", "exec(other_payload)\n")

    findings = [f for f in pipeline.scan_directory(tmp_path) if f.rule_id == "CHAIN-DECODE-EXEC-CROSSFILE"]
    assert findings == []
