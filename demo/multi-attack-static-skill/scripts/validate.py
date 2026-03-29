#!/usr/bin/env python3
import json
import re
from pathlib import Path


def main() -> None:
    rules_path = Path(__file__).resolve().parents[1] / "data" / "rules.json"
    data = json.loads(rules_path.read_text(encoding="utf-8"))

    required_top = {"version", "risk_thresholds", "rules"}
    missing = required_top - set(data.keys())
    if missing:
        raise SystemExit(f"Missing top-level keys: {sorted(missing)}")

    seen = set()
    for i, rule in enumerate(data["rules"], start=1):
        for key in ("rule_id", "category", "type", "pattern", "score"):
            if key not in rule:
                raise SystemExit(f"Rule #{i} missing key: {key}")
        if rule["rule_id"] in seen:
            raise SystemExit(f"Duplicate rule_id: {rule['rule_id']}")
        seen.add(rule["rule_id"])
        if rule["type"] not in ("keyword", "regex"):
            raise SystemExit(f"Invalid rule type in {rule['rule_id']}: {rule['type']}")
        if not isinstance(rule["score"], int) or rule["score"] <= 0:
            raise SystemExit(f"Invalid score in {rule['rule_id']}: {rule['score']}")
        if rule["type"] == "regex":
            try:
                re.compile(rule["pattern"], flags=re.IGNORECASE)
            except re.error as exc:
                raise SystemExit(f"Regex compile failed in {rule['rule_id']}: {exc}") from exc

    b64 = data.get("base64_validation")
    if b64:
        for key in ("enabled", "rule_id", "category", "score", "candidate_regex", "decoded_indicators"):
            if key not in b64:
                raise SystemExit(f"base64_validation missing key: {key}")
        if not isinstance(b64["decoded_indicators"], list):
            raise SystemExit("base64_validation.decoded_indicators must be a list")
        try:
            re.compile(b64["candidate_regex"], flags=re.IGNORECASE)
        except re.error as exc:
            raise SystemExit(f"Invalid base64 candidate_regex: {exc}") from exc

    print(f"OK: {len(data['rules'])} rules validated.")


if __name__ == "__main__":
    main()
