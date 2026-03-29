/** Display helpers: Chinese labels, compact IDs, risk styling (UI copy layer only). */

function isAsciiOnly(s: string): boolean {
  return /^[\x00-\x7F]+$/.test(s)
}

export function shortTaskId(id: string, head = 8, tail = 4): string {
  if (!id) return '—'
  const minLen = head + tail + 1
  if (id.length <= minLen) return id
  return `${id.slice(0, head)}…${id.slice(-tail)}`
}

const STATUS_ZH: Record<string, string> = {
  queued: '排队中',
  pending: '等待中',
  running: '执行中',
  completed: '已完成',
  succeeded: '已完成',
  failed: '失败',
  cancelled: '已取消',
  canceled: '已取消',
}

export function formatTaskStatusZh(status: string): string {
  const k = status.trim().toLowerCase()
  if (STATUS_ZH[k]) return STATUS_ZH[k]
  if (isAsciiOnly(status)) return '未知状态'
  return status
}

export type StatusVariant = 'running' | 'done' | 'failed' | 'queued' | 'none'

export function taskStatusMeta(status: string, conclusion?: string | null): { label: string; variant: StatusVariant } {
  const c = conclusion?.trim().toUpperCase()
  if (c === 'PASS') return { label: '通过', variant: 'done' }
  if (c === 'FAIL') return { label: '不通过', variant: 'failed' }
  const k = status.trim().toLowerCase()
  const label = formatTaskStatusZh(status)
  if (k === 'running') return { label, variant: 'running' }
  if (k === 'completed' || k === 'succeeded') return { label, variant: 'done' }
  if (k === 'failed') return { label, variant: 'failed' }
  if (k === 'queued' || k === 'pending' || k === 'cancelled' || k === 'canceled') return { label, variant: 'queued' }
  return { label, variant: 'none' }
}

const CONCLUSION_ZH: Record<string, string> = {
  PASS: '通过',
  FAIL: '未通过',
  WARN: '警告',
  WARNING: '警告',
  ERROR: '错误',
  SKIPPED: '已跳过',
  UNKNOWN: '未知',
  INCONCLUSIVE: '无结论',
  NONE: '—',
}

export function formatConclusionZh(conclusion: string | null | undefined): string {
  if (conclusion == null || String(conclusion).trim() === '') return '—'
  const raw = String(conclusion).trim()
  const key = raw.toUpperCase()
  if (CONCLUSION_ZH[key]) return CONCLUSION_ZH[key]
  if (isAsciiOnly(raw)) return '未知'
  return raw
}

export type ConclusionVariant = 'pass' | 'fail' | 'warn' | 'neutral' | 'none'

export function conclusionMeta(conclusion: string | null | undefined): { label: string; variant: ConclusionVariant } {
  if (conclusion == null || String(conclusion).trim() === '') {
    return { label: '—', variant: 'none' }
  }
  const key = String(conclusion).trim().toUpperCase()
  const label = formatConclusionZh(conclusion)
  if (key === 'PASS') return { label, variant: 'pass' }
  if (key === 'FAIL' || key === 'ERROR') return { label, variant: 'fail' }
  if (key === 'WARN' || key === 'WARNING') return { label, variant: 'warn' }
  return { label, variant: 'neutral' }
}

export type RiskVariant = 'blocker' | 'high' | 'medium' | 'low' | 'baseline' | 'none'

export function riskLevelMeta(level: string | null | undefined): { label: string; variant: RiskVariant } {
  if (level == null || String(level).trim() === '') {
    return { label: '—', variant: 'none' }
  }
  const key = String(level).trim().toLowerCase()
  const map: Record<string, { label: string; variant: RiskVariant }> = {
    blocker: { label: '严重', variant: 'blocker' },
    high: { label: '高', variant: 'high' },
    medium: { label: '中', variant: 'medium' },
    low: { label: '低', variant: 'low' },
    baseline: { label: '无风险', variant: 'baseline' },
    // backward compatibility for historical tasks
    critical: { label: '严重', variant: 'blocker' },
    info: { label: '无风险', variant: 'baseline' },
  }
  if (map[key]) return map[key]
  if (isAsciiOnly(String(level))) return { label: '未知', variant: 'none' }
  return { label: String(level).trim(), variant: 'none' }
}

export function formatDateTimeZh(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(d)
}

const SEVERITY_ZH: Record<string, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
  info: '无风险',
}

export function formatSeverityZh(severity: string): string {
  const k = severity.trim().toLowerCase()
  if (SEVERITY_ZH[k]) return SEVERITY_ZH[k]
  if (isAsciiOnly(severity)) return '未知'
  return severity
}

export function formatScore10(score: number | null | undefined): string {
  if (score == null || Number.isNaN(score)) return '-'
  const clamped = Math.max(0, Math.min(10, score))
  const fixed = clamped.toFixed(2)
  return fixed.replace(/\.?0+$/, '')
}

const CATEGORY_ZH: Record<string, string> = {
  skill_layout: 'Skill 包结构（前置）',
  secrets: '敏感信息',
  sast: '危险调用 / SAST',
  config: '配置风险',
  malicious: '恶意特征',
  dependency: '依赖与供应链',
  prompt_injection: 'Prompt 注入',
  attack_chain: '攻击链路',
  exfiltration: '数据外传',
  supplychain: '供应链脚本风险',
}

export function formatCategoryZh(category: string): string {
  const k = category.trim().toLowerCase()
  if (CATEGORY_ZH[k]) return CATEGORY_ZH[k]
  if (isAsciiOnly(category)) return category
  return category
}
