# multi-attack-static-skill

Static, deterministic multi-attack detection skill.

## Run

```bash
python3 scripts/validate.py
python3 scripts/scan.py --input-file fixtures/sample_input.txt
python3 scripts/check_fixture.py
```

## Files

- `data/rules.json`: canonical rules and score thresholds
- `scripts/scan.py`: performs scanning and prints JSON result
- `scripts/validate.py`: validates schema, duplicate IDs, and regex syntax
- `scripts/check_fixture.py`: regression check for sample baseline
- `fixtures/sample_input.txt`: demo input
- `fixtures/expected_output.json`: expected baseline output

## Notes

- Same `rule_id` is counted once per input.
- Matching is keyword/regex only, no semantic inference.
