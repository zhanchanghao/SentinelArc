# Reference - Multi Attack Static Skill

## Rule Set

All rules run on normalized lowercase text.

### G. 供应链脚本攻击

- `G01` regex: `npm (preinstall|install|postinstall|prepare).*?(curl|wget|powershell|bash|sh)`
  - category: supply-chain-script-attack
  - score: 3
- `G02` regex: `(setup\.py|pyproject\.toml|setup\()... (os\.system|subprocess\.(run|popen|call)) ... (https?://|curl|wget)`
  - category: supply-chain-script-attack
  - score: 3
- `G03` keyword: `install hook remote exec`
  - category: supply-chain-script-attack
  - score: 2
- `G04` regex: `"(preinstall|install|postinstall|prepare)"\s*:\s*"...(curl|wget|invoke-webrequest|powershell|bash|sh)...(\||&&|;)..."`
  - category: supply-chain-script-attack
  - score: 3
- `G05` regex: `(setup\.py|pyproject\.toml|cmdclass|build_py|install)...(exec\(|eval\(|os\.system\(|subprocess\.)...(shell=true|+cmd|format|f-string)`
  - category: supply-chain-script-attack
  - score: 3

### H. 混淆与执行链路

- `H01` regex: `base64\s+-d.*(\||&&).*(sh|bash|python|powershell)`
  - category: obfuscation-exec-chain
  - score: 3
- `H02` regex: `(eval|exec)\s*\(`
  - category: obfuscation-exec-chain
  - score: 2
- `H03` regex: `fromcharcode|atob\(|decodeURIComponent\(`
  - category: obfuscation-exec-chain
  - score: 2
- `H04` validated-base64: decode candidate base64 blob and check decoded indicators
  - category: obfuscation-exec-chain
  - score: 3
  - indicators: `curl`, `wget`, `bash`, `powershell`, `invoke-expression`, `drop table`, `password=`

### I. 依赖与供应链

- `I01` regex: `pip install\s+git\+https?://`
  - category: dependency-supply-chain
  - score: 2
- `I02` regex: `npm install\s+.*(github\.com|raw\.githubusercontent\.com)`
  - category: dependency-supply-chain
  - score: 2
- `I03` keyword: `dependency confusion`
  - category: dependency-supply-chain
  - score: 2

### J. 配置与权限风险

- `J01` regex: `chmod\s+777`
  - category: config-permission-risk
  - score: 2
- `J02` regex: `allow_origins\s*=\s*\[\s*"\*"\s*\]|cors.*\*`
  - category: config-permission-risk
  - score: 2
- `J03` regex: `tls_verify\s*=\s*false|verify\s*=\s*false`
  - category: config-permission-risk
  - score: 2
- `J04` regex: `AKIA[0-9A-Z]{16}`
  - category: config-permission-risk
  - score: 3

### K. 危险调用与代码模式

- `K01` regex: `yaml\.load\s*\(.*loader\s*=\s*yaml\.loader`
  - category: dangerous-call-pattern
  - score: 3
- `K02` regex: `subprocess\.(popen|run|call)\s*\(.*shell\s*=\s*true`
  - category: dangerous-call-pattern
  - score: 3
- `K03` regex: `pickle\.loads\s*\(`
  - category: dangerous-call-pattern
  - score: 2
- `K04` regex: `md5\s*\(`
  - category: dangerous-call-pattern
  - score: 1

### L. 敏感信息泄露

- `L01` regex: `(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{6,}['\"]`
  - category: sensitive-info-leak
  - score: 3
- `L02` regex: `-----begin (rsa |ec )?private key-----`
  - category: sensitive-info-leak
  - score: 3
- `L03` regex: `(mysql|postgres|mongodb)://[^\\s]+:[^\\s]+@`
  - category: sensitive-info-leak
  - score: 3

### A. Prompt Injection / Policy Bypass

- `A01` regex: `ignore (all )?(previous|prior) instructions`
  - category: prompt-injection
  - score: 2
- `A02` keyword: `system prompt`
  - category: prompt-injection
  - score: 1
- `A03` regex: `越狱|绕过安全策略|关闭安全`
  - category: prompt-injection
  - score: 2

### B. Auth / Validation Bypass

- `B01` keyword: `bypass auth`
  - category: auth-bypass
  - score: 2
- `B02` regex: `绕过(登录|鉴权|校验)`
  - category: auth-bypass
  - score: 2
- `B03` keyword: `skip validation`
  - category: auth-bypass
  - score: 1

### C. Command Injection / Suspicious Chain

- `C01` regex: `(curl|wget).*(\||&&).*(sh|bash|powershell)`
  - category: command-chain
  - score: 3
- `C02` keyword: `invoke-expression`
  - category: command-chain
  - score: 3
- `C03` keyword: `base64 -d`
  - category: command-chain
  - score: 2

### D. Destructive Operations

- `D01` regex: `(drop|truncate)\s+table`
  - category: destructive-op
  - score: 3
- `D02` keyword: `force delete`
  - category: destructive-op
  - score: 2
- `D03` regex: `一键删除|不要备份`
  - category: destructive-op
  - score: 2

### E. Sensitive Data Exfiltration

- `E01` keyword: `dump credentials`
  - category: data-exfiltration
  - score: 3
- `E02` regex: `导出.*(密钥|凭据|token)`
  - category: data-exfiltration
  - score: 2
- `E03` keyword: `export secrets`
  - category: data-exfiltration
  - score: 3

### F. Supply Chain Execution Hints

- `F01` regex: `npm (preinstall|postinstall)`
  - category: supply-chain
  - score: 2
- `F02` regex: `pip install .*https?://`
  - category: supply-chain
  - score: 2
- `F03` keyword: `remote script execution`
  - category: supply-chain
  - score: 2

## Score to Risk Mapping

- `0`: safe
- `1-3`: low-risk-danger
- `4-7`: medium-risk-danger
- `>=8`: high-risk-danger

## Dedup Policy

- Same `rule_id` is counted once per input.
- Different rules in same category are cumulative.

## Output Schema

Each hit:
- `rule_id`
- `category`
- `score`
- `matched_text`

Final result:
- `risk_level`
- `total_score`
- `hits[]`

