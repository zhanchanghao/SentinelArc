<template>
  <div v-if="task" class="report-root">
    <div class="grid">
      <div class="card">
        <div class="label">状态</div>
        <div class="value">
          <span :class="['badge', `st-${taskStatusMeta(task.status, task.conclusion).variant}`]">{{
            taskStatusMeta(task.status, task.conclusion).label
          }}</span>
        </div>
      </div>
      <div class="card">
        <div class="label">结论</div>
        <div class="value">
          <span :class="['badge', `cc-${conclusionMeta(task.conclusion).variant}`]">{{
            conclusionMeta(task.conclusion).label
          }}</span>
        </div>
      </div>
      <div class="card">
        <div class="label">威胁等级</div>
        <div class="value">
          <span :class="['badge', `rk-${riskLevelMeta(task.level).variant}`]">{{
            riskLevelMeta(task.level).label
          }}</span>
        </div>
      </div>
      <div class="card">
        <div class="label">评分</div>
        <div class="score-wrap">
          <div class="score-top">
            <span class="score-value">{{ formatScore10(task.score) }}/10</span>
            <span :class="['badge', 'score-intent', `sc-${scoreIntent.variant}`]">{{ scoreIntent.label }}</span>
          </div>
          <div class="score-bar" role="img" :aria-label="`安全评分 ${formatScore10(task.score)} / 10`">
            <div :class="['score-fill', `sc-${scoreIntent.variant}`]" :style="{ width: `${scoreIntent.percent}%` }"></div>
          </div>
          <div class="score-hint">{{ scoreIntent.hint }}</div>
        </div>
      </div>
    </div>

    <h2 class="section-title">检测范围与结果</h2>
    <p class="lede-report">
      每个检测项会明确给出结果态：通过、不通过、未检查。任务若在前置门禁失败，后续检测项会标记为未检查。
    </p>
    <div class="report-disclaimer" role="note" aria-label="检测能力说明">
      检测能力说明：本平台当前以静态规则与特征匹配为主，对【语义改写绕过、跨文件上下文关联、0day/未知攻击变种】等风险识别能力有限。请结合人工复核、灰度验证和动态测试综合判断。
    </div>
    <div class="table-wrap checks-wrap">
      <table class="data-table checks-table">
        <thead>
          <tr>
            <th class="th-check">检测项</th>
            <th class="th-desc">检查内容</th>
            <th class="th-result">本类结果</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in scanChecks" :key="row.id">
            <td class="cell cell-title">{{ row.title }}</td>
            <td class="cell cell-desc">{{ row.description }}</td>
            <td class="cell cell-result">
              <span v-if="row.status === 'pass'" class="badge ok-badge">通过</span>
              <span v-else-if="row.status === 'not_checked'" class="badge pending-badge">未检查</span>
              <div v-else class="cell-result-block">
                <span class="badge hit-badge">不通过</span>
                <span v-if="rowFindingsCount(row) > 0" class="badge count-badge"
                  >检出 {{ rowFindingsCount(row) }} 条</span
                >
                <div class="cell-detail-list">
                  <div
                    v-for="f in (findingsByCategory[row.id] || []).slice(0, 3)"
                    :key="f.id"
                    class="detail-line"
                  >
                    • {{ formatSeverityZh(f.severity) }} · {{ f.rule_id }} · {{ f.file_path }}
                  </div>
                  <div
                    v-if="(findingsByCategory[row.id] || []).length > 3"
                    class="detail-more"
                  >
                    其余 {{ (findingsByCategory[row.id] || []).length - 3 }} 条详见下方「命中明细」列表。
                  </div>
                </div>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">威胁等级分布</h2>
    <div class="sev-strip" role="list">
      <div v-for="item in severityStrip" :key="item.key" class="sev-item" role="listitem">
        <span class="sev-label">{{ item.label }}</span>
        <span :class="['badge', `sv-${item.variant}`]">{{ item.count }}</span>
      </div>
    </div>

    <h2 class="section-title">攻击类型分布</h2>
    <div v-if="attackTypeRows.length" class="table-wrap">
      <table class="data-table attack-table">
        <thead>
          <tr>
            <th>攻击类型</th>
            <th>命中数</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in attackTypeRows" :key="row.key">
            <td class="cell">{{ row.label }}</td>
            <td class="cell">{{ row.count }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="empty">暂无攻击类型统计</div>

    <h2 class="section-title">命中明细</h2>
    <div v-if="displayFindings.length" class="table-wrap">
      <table class="data-table">
        <colgroup>
          <col class="col-sev" />
          <col class="col-cat" />
          <col class="col-rule" />
          <col class="col-file" />
          <col class="col-attack" />
          <col class="col-rec" />
        </colgroup>
        <thead>
          <tr>
            <th>威胁等级</th>
            <th>类别</th>
            <th>规则</th>
            <th>文件</th>
            <th>攻击类型</th>
            <th class="th-rec">建议</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in displayFindings" :key="f.id">
            <td>
              <span :class="['badge', `sv-${severityVariant(f.severity)}`]">{{ formatSeverityZh(f.severity) }}</span>
            </td>
            <td class="cell">{{ formatCategoryZh(f.category) }}</td>
            <td class="cell mono">{{ f.rule_id }}</td>
            <td class="cell mono">{{ f.file_path }}</td>
            <td class="cell">{{ formatAttackTypeZh(f.evidence) }}</td>
            <td class="cell cell-rec">{{ f.recommendation }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="empty">暂无命中</div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { FindingItem, TaskDetail } from '../api/client'
import { resolveAttackTypeCounts, resolveScanChecks, resolveSeverityCounts } from '../utils/scanReport'
import {
  conclusionMeta,
  formatCategoryZh,
  formatScore10,
  formatSeverityZh,
  riskLevelMeta,
  taskStatusMeta,
} from '../utils/taskDisplay'

const props = defineProps<{
  task: TaskDetail | null
  findings: FindingItem[]
}>()

const scanChecks = computed(() => (props.task ? resolveScanChecks(props.task) : []))
const displayFindings = computed<FindingItem[]>(() => {
  if (props.findings.length > 0) return props.findings

  const summary = (props.task?.summary as Record<string, unknown> | undefined) ?? undefined
  const rawReason = summary?.reason
  const reason =
    typeof rawReason === 'string' && rawReason.trim()
      ? rawReason.trim()
      : typeof props.task?.error_message === 'string' && props.task.error_message.trim()
        ? props.task.error_message.trim()
        : ''

  if (!reason.startsWith('skill_layout_invalid_')) return []

  return [
    {
      id: 'synthetic-skill-layout-invalid',
      rule_id: reason,
      category: 'skill_layout',
      severity: 'Info',
      confidence: 1,
      file_path: 'SKILL.md',
      evidence: { attack_type: 'format_validation', reason },
      recommendation: formatSkillLayoutReasonZh(reason),
    },
  ]
})

const findingsByCategory = computed<Record<string, FindingItem[]>>(() => {
  const map: Record<string, FindingItem[]> = {}
  for (const f of displayFindings.value) {
    const key = f.category
    if (!map[key]) map[key] = []
    map[key].push(f)
  }
  return map
})

const severityStrip = computed(() => {
  const c = props.task ? resolveSeverityCounts(props.task.summary) : resolveSeverityCounts(undefined)
  const order: { key: string; label: string; variant: string }[] = [
    { key: 'Critical', label: '严重', variant: 'critical' },
    { key: 'High', label: '高', variant: 'high' },
    { key: 'Medium', label: '中', variant: 'medium' },
    { key: 'Low', label: '低', variant: 'low' },
    { key: 'Info', label: '无风险', variant: 'info' },
  ]
  return order.map((o) => ({
    ...o,
    count: c[o.key] ?? 0,
  }))
})

const attackTypeRows = computed(() => {
  const c = props.task ? resolveAttackTypeCounts(props.task.summary) : {}
  return Object.entries(c)
    .map(([k, count]) => ({ key: k, label: formatAttackTypeZh({ attack_type: k }), count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
})

const scoreIntent = computed(() => {
  const raw = props.task?.score
  const score = typeof raw === 'number' && !Number.isNaN(raw) ? Math.max(0, Math.min(10, raw)) : 0
  if (score >= 8) {
    return { variant: 'safe', label: '安全', hint: '风险较低，可按常规流程上线。', percent: score * 10 }
  }
  if (score >= 6) {
    return { variant: 'watch', label: '关注', hint: '存在一定风险，建议复核后再上线。', percent: score * 10 }
  }
  if (score >= 3) {
    return { variant: 'danger', label: '危险', hint: '风险较高，建议先修复关键问题。', percent: score * 10 }
  }
  return { variant: 'critical', label: '高危', hint: '高风险状态，需阻断并立即处置。', percent: score * 10 }
})

function severityVariant(severity: string): string {
  const k = severity.trim().toLowerCase()
  if (k === 'critical') return 'critical'
  if (k === 'high') return 'high'
  if (k === 'medium') return 'medium'
  if (k === 'low') return 'low'
  if (k === 'info') return 'info'
  return 'none'
}

function formatAttackTypeZh(evidence: unknown): string {
  if (!evidence || typeof evidence !== 'object') return '—'
  const attackType = (evidence as Record<string, unknown>).attack_type
  if (typeof attackType !== 'string' || !attackType.trim()) return '—'
  const k = attackType.trim().toLowerCase()
  const map: Record<string, string> = {
    format_validation: '格式校验',
    policy_override: '策略覆盖',
    tool_abuse: '工具滥用',
    safety_bypass: '绕过安全',
    role_hijack: '角色劫持',
    secret_exfiltration: '机密窃取',
    obfuscation: '混淆绕过',
    correlated_attack_chain: '关联攻击链',
  }
  return map[k] ?? attackType
}

function formatSkillLayoutReasonZh(reason: string): string {
  const map: Record<string, string> = {
    skill_layout_invalid_missing_skill_md: '缺少 SKILL.md，请在技能包中至少包含一处 SKILL.md 文件。',
    skill_layout_invalid_skill_md_depth: 'SKILL.md 所在层级不符合规范，请将其放在技能目录根层或约定层级。',
    skill_layout_invalid_skill_md_empty: 'SKILL.md 内容为空，请补充技能说明、触发条件和使用方式。',
    skill_layout_invalid_skill_md_not_utf8: 'SKILL.md 编码不是 UTF-8，请转换为 UTF-8 后重新上传。',
    skill_layout_invalid_package_structure: '技能包目录结构不符合规范，请按标准技能包结构重新打包。',
  }
  return map[reason] ?? `技能包格式校验不通过：${reason}`
}

function rowFindingsCount(row: { id: string; findingsCount: number }): number {
  const list = findingsByCategory.value[row.id] || []
  return Math.max(row.findingsCount, list.length)
}
</script>

<style scoped>
.report-root {
  margin-top: 8px;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-top: 16px;
}
.card {
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 10px;
  padding: 12px;
}
.label {
  color: rgba(255, 255, 255, 0.65);
  font-size: 12px;
}
.value {
  font-size: 16px;
  margin-top: 6px;
}
.score-wrap {
  margin-top: 6px;
}
.score-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.score-value {
  font-size: 18px;
  font-weight: 700;
  color: rgba(255, 255, 255, 0.94);
}
.score-intent {
  font-size: 12px;
  padding: 3px 8px;
}
.score-bar {
  margin-top: 8px;
  width: 100%;
  height: 8px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.1);
  overflow: hidden;
}
.score-fill {
  height: 100%;
  border-radius: inherit;
  transition: width 0.25s ease;
}
.score-hint {
  margin-top: 8px;
  font-size: 12px;
  line-height: 1.4;
  color: rgba(255, 255, 255, 0.7);
}
.sc-safe {
  background: rgba(34, 197, 94, 0.18);
  border-color: rgba(74, 222, 128, 0.48);
  color: #86efac;
}
.sc-watch {
  background: rgba(245, 158, 11, 0.16);
  border-color: rgba(251, 191, 36, 0.45);
  color: #fcd34d;
}
.sc-danger {
  background: rgba(249, 115, 22, 0.16);
  border-color: rgba(251, 146, 60, 0.45);
  color: #fdba74;
}
.sc-critical {
  background: rgba(239, 68, 68, 0.16);
  border-color: rgba(248, 113, 113, 0.5);
  color: #fca5a5;
}
.section-title {
  margin: 20px 0 10px;
  font-size: 16px;
}
.lede-report {
  margin: 0 0 12px;
  font-size: 13px;
  line-height: 1.55;
  color: rgba(255, 255, 255, 0.62);
}
.report-disclaimer {
  margin: 0 0 12px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid rgba(251, 191, 36, 0.35);
  background: rgba(245, 158, 11, 0.1);
  color: rgba(254, 243, 199, 0.95);
  font-size: 12px;
  line-height: 1.55;
}
.checks-wrap {
  margin-top: 8px;
}
.checks-table {
  min-width: 0;
  table-layout: auto;
}
.checks-table .th-check {
  width: 22%;
}
.checks-table .th-desc {
  width: 58%;
}
.checks-table .th-result {
  width: 20%;
}
.checks-table .cell-title {
  font-weight: 600;
  color: rgba(255, 255, 255, 0.92);
  white-space: normal;
}
.checks-table .cell-desc {
  white-space: normal;
  overflow: visible;
  text-overflow: clip;
  line-height: 1.45;
  color: rgba(255, 255, 255, 0.72);
  font-size: 13px;
}
.checks-table .cell-result {
  white-space: nowrap;
}
.ok-badge {
  background: rgba(34, 197, 94, 0.12);
  border-color: rgba(74, 222, 128, 0.45);
  color: #86efac;
}
.hit-badge {
  background: rgba(245, 158, 11, 0.14);
  border-color: rgba(251, 191, 36, 0.45);
  color: #fde68a;
}
.pending-badge {
  background: rgba(148, 163, 184, 0.12);
  border-color: rgba(148, 163, 184, 0.35);
  color: #cbd5e1;
}
.count-badge {
  background: rgba(168, 85, 247, 0.14);
  border-color: rgba(196, 181, 253, 0.4);
  color: #ddd6fe;
}
.sev-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 14px;
  margin-top: 8px;
  padding: 12px 14px;
  border-radius: 12px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  background: rgba(0, 0, 0, 0.14);
}
.sev-item {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.sev-label {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.55);
}
.cell-result-block {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
}
.cell-detail-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: 12px;
  color: rgba(255, 255, 255, 0.7);
}
.detail-line {
  white-space: normal;
  overflow: visible;
  text-overflow: clip;
}
.detail-more {
  color: rgba(148, 163, 184, 0.95);
}
.data-table {
  width: 100%;
  min-width: 860px;
  border-collapse: collapse;
  table-layout: fixed;
}
.attack-table {
  min-width: 420px;
}
.data-table th,
.data-table td {
  border-bottom: 1px solid rgba(255, 255, 255, 0.12);
  padding: 10px 8px;
  text-align: left;
  font-size: 14px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.data-table th {
  color: rgba(255, 255, 255, 0.65);
  font-size: 12px;
  letter-spacing: 0.2px;
  font-weight: 650;
  background: rgba(0, 0, 0, 0.12);
}
.data-table tbody tr:hover td {
  background: rgba(139, 92, 246, 0.08);
}
.data-table tbody td {
  vertical-align: top;
}
.data-table th.th-rec,
.data-table td.cell-rec {
  white-space: normal;
  overflow: visible;
  text-overflow: clip;
  word-break: break-word;
  overflow-wrap: anywhere;
  line-height: 1.45;
}
.cell {
  color: rgba(255, 255, 255, 0.85);
}
.table-wrap {
  margin-top: 10px;
  overflow: auto;
  border-radius: 12px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(0, 0, 0, 0.12);
  width: 100%;
}
.col-sev {
  width: 12%;
}
.col-cat {
  width: 16%;
}
.col-rule {
  width: 14%;
}
.col-file {
  width: 18%;
}
.col-attack {
  width: 14%;
}
.col-rec {
  width: 30%;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
}
.empty {
  margin-top: 8px;
  color: rgba(255, 255, 255, 0.7);
}
.badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.02em;
  border: 1px solid transparent;
  line-height: 1.2;
  transition:
    background 0.2s ease,
    border-color 0.2s ease,
    color 0.2s ease;
}
.st-running {
  background: rgba(56, 189, 248, 0.12);
  border-color: rgba(56, 189, 248, 0.45);
  color: #7dd3fc;
}
.st-done {
  background: rgba(34, 197, 94, 0.12);
  border-color: rgba(74, 222, 128, 0.45);
  color: #86efac;
}
.st-failed {
  background: rgba(239, 68, 68, 0.14);
  border-color: rgba(248, 113, 113, 0.5);
  color: #fecaca;
}
.st-queued {
  background: rgba(148, 163, 184, 0.12);
  border-color: rgba(148, 163, 184, 0.4);
  color: #cbd5e1;
}
.st-none {
  background: rgba(255, 255, 255, 0.06);
  border-color: rgba(255, 255, 255, 0.14);
  color: rgba(255, 255, 255, 0.82);
}
.cc-pass {
  background: rgba(34, 197, 94, 0.12);
  border-color: rgba(74, 222, 128, 0.45);
  color: #86efac;
}
.cc-fail {
  background: rgba(239, 68, 68, 0.14);
  border-color: rgba(248, 113, 113, 0.5);
  color: #fecaca;
}
.cc-warn {
  background: rgba(245, 158, 11, 0.14);
  border-color: rgba(251, 191, 36, 0.45);
  color: #fde68a;
}
.cc-neutral {
  background: rgba(255, 255, 255, 0.06);
  border-color: rgba(255, 255, 255, 0.14);
  color: rgba(255, 255, 255, 0.85);
}
.cc-none {
  background: transparent;
  border-color: rgba(255, 255, 255, 0.08);
  color: rgba(255, 255, 255, 0.45);
  font-weight: 500;
}
.rk-blocker {
  background: rgba(185, 28, 28, 0.22);
  border-color: rgba(252, 165, 165, 0.55);
  color: #fecaca;
}
.rk-high {
  background: rgba(220, 38, 38, 0.16);
  border-color: rgba(248, 113, 113, 0.48);
  color: #fca5a5;
}
.rk-medium {
  background: rgba(217, 119, 6, 0.16);
  border-color: rgba(251, 191, 36, 0.42);
  color: #fcd34d;
}
.rk-low {
  background: rgba(22, 163, 74, 0.14);
  border-color: rgba(74, 222, 128, 0.4);
  color: #86efac;
}
.rk-baseline {
  background: rgba(59, 130, 246, 0.14);
  border-color: rgba(147, 197, 253, 0.4);
  color: #bfdbfe;
}
.rk-none {
  background: transparent;
  border-color: rgba(255, 255, 255, 0.08);
  color: rgba(255, 255, 255, 0.45);
  font-weight: 500;
}
.sv-critical {
  background: rgba(185, 28, 28, 0.22);
  border-color: rgba(252, 165, 165, 0.55);
  color: #fecaca;
}
.sv-high {
  background: rgba(220, 38, 38, 0.16);
  border-color: rgba(248, 113, 113, 0.48);
  color: #fca5a5;
}
.sv-medium {
  background: rgba(217, 119, 6, 0.16);
  border-color: rgba(251, 191, 36, 0.42);
  color: #fcd34d;
}
.sv-low {
  background: rgba(22, 163, 74, 0.14);
  border-color: rgba(74, 222, 128, 0.4);
  color: #86efac;
}
.sv-info {
  background: rgba(59, 130, 246, 0.14);
  border-color: rgba(147, 197, 253, 0.4);
  color: #bfdbfe;
}
.sv-none {
  background: rgba(255, 255, 255, 0.06);
  border-color: rgba(255, 255, 255, 0.14);
  color: rgba(255, 255, 255, 0.82);
}
@media (max-width: 860px) {
  .grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
