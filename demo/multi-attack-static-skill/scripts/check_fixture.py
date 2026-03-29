#!/usr/bin/env python3
import json
from pathlib import Path
from scan import load_rules, scan_text


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    sample = (root / "fixtures" / "sample_input.txt").read_text(encoding="utf-8")
    expected = json.loads((root / "fixtures" / "expected_output.json").read_text(encoding="utf-8"))
    rules = load_rules(root / "data" / "rules.json")
    actual = scan_text(sample, rules)

    if actual != expected:
        print("Fixture mismatch.")
        print("Actual:")
        print(json.dumps(actual, ensure_ascii=False, indent=2))
        raise SystemExit(1)
    print("OK: fixture output matches expected baseline.")


if __name__ == "__main__":
    main()
