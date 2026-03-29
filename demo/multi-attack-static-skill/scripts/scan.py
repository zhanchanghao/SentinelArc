#!/usr/bin/env python3
import argparse
import base64
import json
import re
from pathlib import Path


def normalize(text: str) -> str:
    return " ".join(text.lower().split())


def load_rules(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def level_from_score(score: int, thresholds: dict) -> str:
    for level, rng in thresholds.items():
        if rng[0] <= score <= rng[1]:
            return level
    return "high-risk-danger"


def scan_text(text: str, rule_data: dict) -> dict:
    content = normalize(text)
    raw_content = text
    hits = []
    seen = set()

    for rule in rule_data["rules"]:
        rid = rule["rule_id"]
        if rid in seen:
            continue
        matched_text = None
        if rule["type"] == "keyword":
            if rule["pattern"] in content:
                matched_text = rule["pattern"]
        else:
            m = re.search(rule["pattern"], content, flags=re.IGNORECASE)
            if m:
                matched_text = m.group(0)
        if matched_text:
            seen.add(rid)
            hits.append(
                {
                    "rule_id": rid,
                    "category": rule["category"],
                    "score": rule["score"],
                    "matched_text": matched_text,
                }
            )

    # Optional base64 validation stage: decode candidate blobs and
    # score only when decoded text contains risky indicators.
    b64 = rule_data.get("base64_validation", {})
    if b64.get("enabled", False):
        rid = b64["rule_id"]
        if rid not in seen:
            candidates = re.findall(b64["candidate_regex"], raw_content)
            indicators = [x.lower() for x in b64.get("decoded_indicators", [])]
            for blob in candidates:
                # Base64 payloads are typically length-aligned.
                if len(blob) % 4 != 0:
                    continue
                try:
                    decoded = base64.b64decode(blob, validate=True).decode(
                        "utf-8", errors="ignore"
                    )
                except Exception:
                    continue
                decoded_norm = normalize(decoded)
                if any(token in decoded_norm for token in indicators):
                    seen.add(rid)
                    hits.append(
                        {
                            "rule_id": rid,
                            "category": b64["category"],
                            "score": b64["score"],
                            "matched_text": f"base64:{blob[:32]}...",
                        }
                    )
                    break

    total = sum(x["score"] for x in hits)
    level = level_from_score(total, rule_data["risk_thresholds"])
    return {
        "risk_level": level,
        "total_score": total,
        "hits": hits,
        "reason": "Deterministic static rule matching only.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Static multi-attack scanner")
    parser.add_argument("--text", help="Raw text to scan")
    parser.add_argument("--input-file", help="Path to text file")
    parser.add_argument(
        "--rules",
        default=str(Path(__file__).resolve().parents[1] / "data" / "rules.json"),
        help="Path to rules.json",
    )
    args = parser.parse_args()

    if not args.text and not args.input_file:
        raise SystemExit("Provide --text or --input-file")

    raw = args.text if args.text else Path(args.input_file).read_text(encoding="utf-8")
    rule_data = load_rules(Path(args.rules))
    result = scan_text(raw, rule_data)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
