---
name: multi-attack-static-skill
description: Static rule based detector for multiple attack patterns. Use when scanning prompts, scripts, or snippets for injection, bypass, destructive operations, exfiltration hints, and suspicious execution chains using deterministic keyword and regex rules.
---

# Multi Attack Static Skill

This skill detects multiple attack categories with static rules only.
It is deterministic, explainable, and suitable for rule-based pipelines.

## Quick Start

1. Normalize input (lowercase, collapse repeated whitespace).
2. Match all rules from `data/rules.json`.
3. Collect unique hits by `rule_id`.
4. Sum scores and map to severity.
5. Return structured result with hit evidence.

Run locally:

```bash
python3 scripts/validate.py
python3 scripts/scan.py --input-file fixtures/sample_input.txt
```

## Detection Categories

- 供应链脚本攻击
- 混淆与执行链路
- 依赖与供应链
- 配置与权限风险
- 危险调用与代码模式
- 敏感信息泄露
- Prompt injection and policy bypass
- Auth and validation bypass

## Evaluation Policy

1. Use static matching only (keyword and regex).
2. Do not add semantic guesses beyond matched content.
3. Same `rule_id` scores once per input.
4. Severity mapping:
   - `0`: safe
   - `1-3`: low-risk-danger
   - `4-7`: medium-risk-danger
   - `>=8`: high-risk-danger

## Output Template

```markdown
Risk level: <safe | low-risk-danger | medium-risk-danger | high-risk-danger>
Total score: <number>

Hits:
- [<rule_id>] <category> | score=<n> | matched="<text>"
- ...

Reason:
- Deterministic static rule matching only.
```

## Workflow Checklist

- [ ] Input normalized
- [ ] Rules scanned
- [ ] Hits deduplicated by rule_id
- [ ] Score calculated
- [ ] Risk level mapped
- [ ] Structured output returned

## Guardrails

- Never output actionable exploit payloads.
- Never fabricate hits.
- Prefer conservative regex that can be audited.
- Keep rule IDs stable for downstream systems.

## Package Structure

- `SKILL.md`: runtime behavior and output contract
- `reference.md`: human-readable rule catalog
- `examples.md`: expected detection examples
- `data/rules.json`: machine-readable rules and thresholds
- `scripts/scan.py`: scanner entry script
- `scripts/validate.py`: rules schema and regex validator
- `fixtures/`: sample input and expected output for regression checks

## Examples

See [examples.md](examples.md) for expected outputs.

## Validation

Before final output, verify:
- risk level and total score are present
- each hit includes rule_id, category, score, and matched text
- repeated same rule is not double-counted
- result is reproducible for the same input
