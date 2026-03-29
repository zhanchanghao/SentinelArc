# Prompt Attack Detection Hardening Plan

## Objective

Build a stronger, explainable prompt-attack identification pipeline for the Skill security scanner by adding multi-signal detection (rule + semantic context + correlation), risk scoring, and policy-driven response outputs, while preserving existing report compatibility and category-based aggregation.

## Assumptions

- Existing scanning entrypoint and aggregation behavior remain the primary integration surface (`scr/backend/engine/pipeline.py:272`, `scr/backend/engine/pipeline.py:1030`).
- This phase focuses on detection and reporting quality; no runtime sandbox or tool-permission execution engine changes are included.
- Current users still need backward-compatible category IDs in summary/check tables (`scr/backend/engine/pipeline.py:980`).

## Implementation Plan

- [ ] 1. Define a normalized prompt-attack taxonomy and map it to current categories and rule IDs to reduce ambiguity in findings.
  - Why: Current prompt-injection logic uses a small set of regex signatures and lacks subtype normalization, which weakens triage precision (`scr/backend/engine/pipeline.py:583`).
  - Affected areas: detection constants and finding evidence fields in `scr/backend/engine/pipeline.py`.
  - Integration points: existing `Finding` schema and report detail table (`scr/backend/engine/pipeline.py:18`, `scr/backend/engine/pipeline.py:1089`).

- [ ] 2. Expand detection signatures from single-line phrase matching to layered indicators (override intent, role hijack, secret exfil intent, obfuscation markers, and indirect injection hints).
  - Why: Current signatures cover only three families and are vulnerable to paraphrase and multilingual bypass (`scr/backend/engine/pipeline.py:584`).
  - Affected areas: `_scan_prompt_injection_patterns` and shared text-candidate gating (`scr/backend/engine/pipeline.py:583`, `scr/backend/engine/pipeline.py:512`).
  - Integration points: evidence weighting and severity conversion (`scr/backend/engine/pipeline.py:543`, `scr/backend/engine/pipeline.py:555`).

- [ ] 3. Introduce contextual correlation across prompt, attack-chain, and exfiltration signals to produce higher-confidence composite findings.
  - Why: The code already supports chain-style reasoning in decode-exec and secret-exfil scans, but prompt attacks are not yet linked to these chain outcomes (`scr/backend/engine/pipeline.py:639`, `scr/backend/engine/pipeline.py:754`).
  - Affected areas: post-scan correlation stage after category scanners in `scan_directory` (`scr/backend/engine/pipeline.py:272`).
  - Integration points: unified `evidence.chain_evidence` format used by chain scanners (`scr/backend/engine/pipeline.py:700`, `scr/backend/engine/pipeline.py:793`).

- [ ] 4. Add a policy-driven risk score for prompt attack findings that supports hard-block conditions and downgrade rules for test/example contexts.
  - Why: Existing weighted scoring utilities are reusable, but prompt attack handling lacks explicit hard-block semantics for high-risk intents (`scr/backend/engine/pipeline.py:543`, `scr/backend/engine/pipeline.py:555`).
  - Affected areas: scoring helpers and prompt-related scanner outputs in `scr/backend/engine/pipeline.py`.
  - Integration points: aggregate conclusion thresholds and severity counts (`scr/backend/engine/pipeline.py:1030`).

- [ ] 5. Extend report metadata/check descriptions so downstream users can distinguish simple prompt hits from correlated attack campaigns.
  - Why: Current standard checks list broad categories but does not distinguish subtype maturity or composite risk classes (`scr/backend/engine/pipeline.py:980`).
  - Affected areas: `STANDARD_SCAN_CHECKS`, report JSON fields, and markdown rendering (`scr/backend/engine/pipeline.py:980`, `scr/backend/engine/pipeline.py:1179`).
  - Integration points: front-end/API consumers relying on current `checks` and finding fields (`README.md:85`).

- [ ] 6. Create regression fixtures and evaluation criteria for adversarial prompts (override, role hijack, encoded payloads, and mixed-language bypass).
  - Why: Detection tuning without reproducible fixtures risks unstable precision/recall and repeated regressions.
  - Affected areas: test fixtures and scanner regression test harness under backend test scope.
  - Integration points: scanner contract for category/severity/confidence and summary conclusion.

## Verification Criteria

- [ ] Given curated malicious prompt fixture sets, the scanner detects each target subtype with expected category and non-empty evidence chain.
- [ ] Benign instructional/test examples in fixture paths produce lower severity via weighting and do not trigger hard-block rules.
- [ ] Aggregation output remains backward-compatible: existing summary keys and checks structure remain available for API/UI consumers.
- [ ] Markdown and JSON report outputs include new prompt-attack evidence fields without breaking existing required fields.
- [ ] End-to-end scan runtime remains within acceptable baseline variance for similarly sized archives.

## Potential Risks and Mitigations

1. **False positives increase after signature expansion**
   Mitigation: Keep weighted downgrades for test/example/comment contexts, add fixture-based threshold tuning, and stage rollout with confidence telemetry.

2. **False negatives from paraphrased or multilingual prompt attacks**
   Mitigation: Use intent families and multi-indicator matching instead of exact phrase dependence, and continuously enrich fixtures from observed evasions.

3. **Breaking downstream consumers due to schema drift**
   Mitigation: Preserve current category/check fields and append optional evidence extensions rather than replacing existing report keys.

4. **Score inflation causing excessive FAIL conclusions**
   Mitigation: Calibrate prompt-attack scoring against baseline datasets and apply explicit hard-block criteria only to high-confidence critical subtypes.

## Alternative Approaches

1. **Rule-first incremental approach**: Expand regex/signature coverage only, with minimal architecture changes.
   - Trade-off: Fast to ship and easy to explain, but weaker against paraphrase/evasion and less resilient long-term.

2. **Classifier-assisted approach**: Add a lightweight semantic classifier for prompt-attack intents and use rules as guardrails.
   - Trade-off: Better robustness and multilingual handling, but adds model lifecycle overhead and calibration complexity.

3. **Policy-engine-first approach**: Keep detection mostly unchanged and improve only post-detection policy decisions.
   - Trade-off: Lower implementation risk, but limited uplift in actual attack identification quality.
