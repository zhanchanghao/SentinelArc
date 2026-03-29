/** API base without trailing slash. Empty = same origin (use Vite proxy `/api` → backend). */
export function apiBase(): string {
  const raw = import.meta.env.VITE_API_BASE?.trim()
  return raw ?? ''
}

async function parseErrorMessage(res: Response): Promise<string> {
  const text = await res.text()
  try {
    const j = JSON.parse(text) as { detail?: unknown }
    if (j.detail !== undefined) {
      if (typeof j.detail === 'string') return j.detail
      return JSON.stringify(j.detail)
    }
  } catch {
    /* ignore */
  }
  return text || `${res.status} ${res.statusText}`
}

export async function apiFetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${apiBase()}${path.startsWith('/') ? path : `/${path}`}`
  const res = await fetch(url, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...init?.headers,
    },
  })
  if (!res.ok) {
    throw new Error(await parseErrorMessage(res))
  }
  return res.json() as Promise<T>
}

export type CreateTaskResponse = {
  task_id: string
  artifact_sha256: string
  status: string
}

export async function createTask(file: File): Promise<CreateTaskResponse> {
  const body = new FormData()
  body.append('file', file)
  return apiFetchJson<CreateTaskResponse>('/api/tasks', {
    method: 'POST',
    body,
  })
}

export type TaskListItem = {
  id: string
  status: string
  created_at: string
  conclusion?: string | null
  level?: string | null
}

export type ListTasksResponse = {
  items: TaskListItem[]
  limit: number
  offset: number
}

export async function listTasks(limit = 50, offset = 0): Promise<ListTasksResponse> {
  const q = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  return apiFetchJson<ListTasksResponse>(`/api/tasks?${q.toString()}`)
}

export type TaskDetail = {
  id: string
  status: string
  created_at: string
  started_at?: string | null
  finished_at?: string | null
  engine_version: string
  ruleset_version: string
  conclusion?: string | null
  level?: string | null
  score?: number | null
  summary?: unknown
  error_message?: string | null
}

export async function getTask(taskId: string): Promise<TaskDetail> {
  return apiFetchJson<TaskDetail>(`/api/tasks/${encodeURIComponent(taskId)}`)
}

export type FindingItem = {
  id: string
  rule_id: string
  category: string
  severity: string
  confidence: number
  file_path: string
  line_range?: string | null
  snippet_redacted?: string | null
  evidence: unknown
  recommendation: string
}

export type ListFindingsResponse = {
  items: FindingItem[]
  limit: number
  offset: number
}

export async function listFindings(taskId: string, limit = 500, offset = 0): Promise<ListFindingsResponse> {
  const q = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  return apiFetchJson<ListFindingsResponse>(
    `/api/tasks/${encodeURIComponent(taskId)}/findings?${q.toString()}`,
  )
}

/** 原始 JSON 报告（机器可读） */
export function taskReportJsonUrl(taskId: string): string {
  return `${apiBase()}/api/tasks/${encodeURIComponent(taskId)}/report.json`
}

/** Markdown 报告（默认下载） */
export function taskReportMarkdownUrl(taskId: string): string {
  return `${apiBase()}/api/tasks/${encodeURIComponent(taskId)}/report.md`
}
