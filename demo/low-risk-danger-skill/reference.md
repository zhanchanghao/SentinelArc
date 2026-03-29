# Reference - Low Risk Danger Skill

## Static Rule Set

All rules are static and deterministic.
Match input after lowercasing.

### Category A - Auth / Validation Bypass

- `A01` keyword: `bypass`
  - score: 1
- `A02` keyword: `skip auth`
  - score: 2
- `A03` regex: `绕过(登录|鉴权|校验)`
  - score: 2

### Category B - Destructive Operations

- `B01` keyword: `force delete`
  - score: 2
- `B02` regex: `(drop|truncate)\s+table`
  - score: 3
- `B03` regex: `一键删除|不要备份`
  - score: 2

### Category C - Prompt Injection / Policy Bypass

- `C01` regex: `ignore (all )?(previous|prior) instructions`
  - score: 2
- `C02` keyword: `prompt injection`
  - score: 1
- `C03` keyword: `越权`
  - score: 2

### Category D - Suspicious Execution Chain

- `D01` regex: `(curl|wget).*(\||&&).*(sh|bash|powershell)`
  - score: 3
- `D02` keyword: `base64 -d`
  - score: 2
- `D03` keyword: `invoke-expression`
  - score: 3

### Category E - Exfiltration Hints

- `E01` keyword: `dump credentials`
  - score: 3
- `E02` regex: `导出.*(密钥|凭据|token)`
  - score: 2

## Scoring and Threshold

- `0`: safe
- `1-3`: low-risk-danger
- `>=4`: high-risk-danger

Notes:
- Same `rule_id` can only score once per input.
- Multiple different rules can accumulate.
- If both low and high indicators exist, use total score only.

## Output Fields

Each hit must return:
- `rule_id`
- `category`
- `score`
- `matched_text`

Final output must return:
- `risk_level`
- `total_score`
- `hits[]`

## Maintenance Rules

- Keep rule IDs stable after publication.
- Add new rules with incremental IDs (`A04`, `B04`, ...).
- Re-test examples when changing regex or thresholds.
