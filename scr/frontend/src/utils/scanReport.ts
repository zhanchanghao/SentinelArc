/** 与后端 pipeline.STANDARD_SCAN_CHECKS 对齐，用于旧任务或无 checks 字段时的回退展示 */

export type ScanCheckRow = {
  id: string
  title: string
  description: string
  findingsCount: number
  status: 'pass' | 'fail' | 'not_checked'
}

export const SCAN_CHECK_DEFINITIONS: ReadonlyArray<Omit<ScanCheckRow, 'findingsCount' | 'status'>> = [
  {
    id: 'skill_layout',
    title: 'Skill 包结构（前置）',
    description:
      '校验是否符合 Agent Skill 约定：解压后至少包含一处 SKILL.md；非标准结构将记为命中并判定不通过。',
  },
  {
    id: 'secrets',
    title: '敏感信息泄露',
    description: '基于正则匹配检测私钥、云访问密钥、令牌等敏感内容。',
  },
  {
    id: 'sast',
    title: '危险调用与代码模式（SAST）',
    description: '对源码脚本扫描 eval/exec、子进程、反序列化、非安全 YAML 等风险模式。',
  },
  {
    id: 'config',
    title: '配置与权限风险',
    description: '检查 .env、yaml/json 等常见配置中的调试开关、CORS 过宽、TLS 校验关闭等。',
  },
  {
    id: 'malicious',
    title: '恶意特征与可疑行为',
    description: '启发式检测下载并执行、可疑 PowerShell、挖矿关键字、异常长 Base64 等。',
  },
  {
    id: 'dependency',
    title: '依赖与供应链',
    description: '识别依赖清单（requirements.txt、package.json 等）；对 Python 固定版本依赖查询 OSV 公开漏洞库。',
  },
  {
    id: 'prompt_injection',
    title: 'Prompt 注入与越权指令',
    description: '检测忽略系统指令、角色劫持、机密外传意图、混淆绕过等提示词攻击模式。',
  },
  {
    id: 'attack_chain',
    title: '混淆与执行链路',
    description: '检测解码后执行、输入到动态执行等组合攻击链路并进行证据加权。',
  },
  {
    id: 'exfiltration',
    title: '敏感信息外传行为',
    description: '检测敏感读取与网络外发组合行为，识别疑似数据泄露链路。',
  },
  {
    id: 'supplychain',
    title: '供应链脚本攻击',
    description: '检测 npm 安装钩子和 Python 构建脚本中的远程下载执行与动态命令。',
  },
]

const DEFAULT_SEVERITY: Record<string, number> = {
  Critical: 0,
  High: 0,
  Medium: 0,
  Low: 0,
  Info: 0,
}

export type SeverityCounts = Record<string, number>
export type AttackTypeCounts = Record<string, number>

export function resolveSeverityCounts(summary: unknown): SeverityCounts {
  const s = summary as Record<string, unknown> | undefined
  const raw = s?.counts_by_severity
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return { ...DEFAULT_SEVERITY, ...(raw as Record<string, number>) }
  }
  return { ...DEFAULT_SEVERITY }
}

export function resolveAttackTypeCounts(summary: unknown): AttackTypeCounts {
  const s = summary as Record<string, unknown> | undefined
  const raw = s?.counts_by_attack_type
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as AttackTypeCounts
  }
  return {}
}

type TaskLike = {
  status?: string | null
  summary?: unknown
  error_message?: string | null
}

function toCheckStatus(raw: unknown, findingsCount: number): ScanCheckRow['status'] {
  if (raw === 'pass' || raw === 'fail' || raw === 'not_checked') return raw
  if (raw === 'issue') return 'fail'
  if (raw === 'clear') return 'pass'
  return findingsCount > 0 ? 'fail' : 'pass'
}

function isSkillLayoutError(errorMessage: string | null | undefined): boolean {
  if (!errorMessage) return false
  return errorMessage.startsWith('skill_layout_invalid_')
}

export function resolveScanChecks(task: TaskLike | null | undefined): ScanCheckRow[] {
  const s = (task?.summary ?? undefined) as Record<string, unknown> | undefined
  const raw = s?.checks
  const counts = (s?.counts_by_category as Record<string, number> | undefined) ?? {}

  if (Array.isArray(raw) && raw.length > 0) {
    return raw.map((item) => {
      const x = item as Record<string, unknown>
      const n = Number(x.findings_count ?? 0)
      const st = toCheckStatus(x.status, n)
      return {
        id: String(x.id ?? ''),
        title: String(x.title ?? ''),
        description: String(x.description ?? ''),
        findingsCount: n,
        status: st,
      }
    })
  }

  const isFailed = (task?.status ?? '').toLowerCase() === 'failed'
  const layoutFailed = isFailed && isSkillLayoutError(task?.error_message)

  return SCAN_CHECK_DEFINITIONS.map((d) => {
    if (layoutFailed) {
      if (d.id === 'skill_layout') {
        return {
          ...d,
          findingsCount: 1,
          status: 'fail',
        }
      }
      return {
        ...d,
        findingsCount: 0,
        status: 'not_checked',
      }
    }

    if (isFailed) {
      return {
        ...d,
        findingsCount: 0,
        status: 'not_checked',
      }
    }

    const n = counts[d.id] ?? 0
    return {
      ...d,
      findingsCount: n,
      status: n > 0 ? 'fail' : 'pass',
    }
  })
}
