<template>
  <section class="panel">
    <h1 class="title">Skill 哨卫安全检查 · Sentinel</h1>
    <p class="lede">选择或拖入文件后将自动上传并开始分析，完成后在本页展示报告。</p>
    <div class="disclaimer" role="note" aria-label="检测免责声明">
      免责声明：当前检测基于静态规则与特征匹配，结果用于风险提示与辅助排查，不等同于完整安全结论。对【语义改写绕过、跨文件攻击链、0day/未知变种】等风险的检测能力有限，建议结合人工复核与动态安全测试。
    </div>

    <input
      id="upload-skill-input"
      ref="fileInputRef"
      type="file"
      class="visually-hidden"
      accept=".zip,.tar.gz,.tgz"
      :aria-label="fileInputAriaLabel"
      @change="onFileChange"
    />

    <div
      class="dropzone"
      :class="{ 'is-dragging': isDragging, 'has-file': !!file }"
      role="button"
      tabindex="0"
      :aria-label="dropzoneAriaLabel"
      @click="openFilePicker"
      @keydown.enter.prevent="openFilePicker"
      @keydown.space.prevent="openFilePicker"
      @dragenter.prevent="onDragEnter"
      @dragover.prevent="onDragOver"
      @dragleave="onDragLeave"
      @drop.prevent="onDrop"
    >
      <div class="dropzone-inner">
        <div class="icon-wrap" aria-hidden="true">
          <svg class="upload-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
            <path
              stroke="currentColor"
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="1.5"
              d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 7.5M12 3v13.5"
            />
          </svg>
        </div>
        <div class="dropzone-copy">
          <span class="dropzone-title">{{ file ? '已选择文件' : '将文件拖到此处' }}</span>
          <span class="dropzone-sub">{{ file ? file.name : '或点击此区域从本机选择' }}</span>
        </div>
        <span class="hint">.zip、.tar.gz、.tgz</span>
      </div>
    </div>

    <div v-if="file" class="file-meta">
      <span class="file-name mono" :title="file.name">{{ file.name }}</span>
      <span class="file-size muted">{{ formatBytes(file.size) }}</span>
      <button type="button" class="btn-text" @click.stop="clearFile">更换</button>
    </div>

    <div v-if="file && (uploading || analyzing)" class="status-line" role="status" aria-live="polite">
      <span class="status-dot" aria-hidden="true" />
      {{ uploading ? '正在上传…' : '正在分析，请稍候…' }}
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="taskId && task && !uploading && !analyzing" class="report-toolbar">
      <template v-if="task.status === 'completed'">
        <a class="link" :href="reportMdUrl" :download="`report_${taskId}.md`">下载报告 (Markdown)</a>
        <a class="link link-muted" :href="reportJsonUrl" :download="`report_${taskId}.json`">JSON</a>
      </template>
    </div>

    <TaskReportView v-if="task && !uploading && !analyzing" :task="task" :findings="findings" />
  </section>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import TaskReportView from '../components/TaskReportView.vue'
import {
  createTask,
  getTask,
  listFindings,
  taskReportJsonUrl,
  taskReportMarkdownUrl,
  type FindingItem,
  type TaskDetail,
} from '../api/client'

const POLL_MS = 900

const fileInputRef = ref<HTMLInputElement | null>(null)
const file = ref<File | null>(null)
const uploading = ref(false)
const analyzing = ref(false)
const error = ref<string | null>(null)
const taskId = ref<string | null>(null)
const task = ref<TaskDetail | null>(null)
const findings = ref<FindingItem[]>([])
const isDragging = ref(false)

let runGeneration = 0

const fileInputAriaLabel = '选择 Skill 压缩包，格式 zip、tar.gz、tgz'

const dropzoneAriaLabel = computed(() =>
  file.value
    ? `已选择 ${file.value.name}，按 Enter 或空格可重新选择文件`
    : '将压缩包拖放到此处或按 Enter 选择文件',
)

const reportMdUrl = computed(() => (taskId.value ? taskReportMarkdownUrl(taskId.value) : ''))
const reportJsonUrl = computed(() => (taskId.value ? taskReportJsonUrl(taskId.value) : ''))

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function acceptedFile(f: File): boolean {
  const n = f.name.toLowerCase()
  return n.endsWith('.zip') || n.endsWith('.tar.gz') || n.endsWith('.tgz')
}

function setFile(next: File | null) {
  if (next && !acceptedFile(next)) {
    error.value = '仅支持 .zip、.tar.gz、.tgz 格式'
    return
  }
  runGeneration++
  file.value = next
  error.value = null
  taskId.value = null
  task.value = null
  findings.value = []
  uploading.value = false
  analyzing.value = false
  if (next) {
    void runUploadAndAnalyze(next)
  }
}

function onFileChange(event: Event) {
  const target = event.target as HTMLInputElement
  const f = target.files?.[0] ?? null
  setFile(f)
}

function openFilePicker() {
  fileInputRef.value?.click()
}

function clearFile() {
  setFile(null)
  if (fileInputRef.value) fileInputRef.value.value = ''
  openFilePicker()
}

function onDragEnter() {
  isDragging.value = true
}

function onDragOver() {
  isDragging.value = true
}

function onDragLeave(e: DragEvent) {
  const el = e.currentTarget as HTMLElement
  const related = e.relatedTarget as Node | null
  if (related && el.contains(related)) return
  isDragging.value = false
}

function onDrop(e: DragEvent) {
  isDragging.value = false
  const f = e.dataTransfer?.files?.[0]
  if (f) setFile(f)
  if (fileInputRef.value) fileInputRef.value.value = ''
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

async function runUploadAndAnalyze(f: File) {
  const run = runGeneration
  uploading.value = true
  analyzing.value = false
  error.value = null

  try {
    const res = await createTask(f)
    if (run !== runGeneration) return
    taskId.value = res.task_id
    uploading.value = false
    analyzing.value = true

    let t: TaskDetail
    for (;;) {
      if (run !== runGeneration) return
      t = await getTask(res.task_id)
      if (t.status === 'completed' || t.status === 'failed') break
      await delay(POLL_MS)
      if (run !== runGeneration) return
    }

    analyzing.value = false
    if (run !== runGeneration) return

    if (t.status === 'failed') {
      task.value = t
      findings.value = []
      error.value = t.error_message || '分析失败'
      return
    }

    const { items } = await listFindings(res.task_id)
    if (run !== runGeneration) return
    task.value = t
    findings.value = items
  } catch (e) {
    if (run !== runGeneration) return
    analyzing.value = false
    uploading.value = false
    task.value = null
    findings.value = []
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    if (run === runGeneration) {
      uploading.value = false
      analyzing.value = false
    }
  }
}
</script>

<style scoped>
.panel {
  max-width: 960px;
  margin: 0 auto;
  padding: 20px;
}
.title {
  margin: 0 0 8px;
  font-size: 1.35rem;
  font-weight: 650;
  letter-spacing: 0.02em;
}
.lede {
  margin: 0 0 18px;
  font-size: 14px;
  color: rgba(255, 255, 255, 0.62);
  line-height: 1.5;
}
.disclaimer {
  margin: 0 0 16px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid rgba(251, 191, 36, 0.35);
  background: rgba(245, 158, 11, 0.1);
  color: rgba(254, 243, 199, 0.95);
  font-size: 12px;
  line-height: 1.55;
}

.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.dropzone {
  border-radius: 14px;
  border: 1px dashed rgba(255, 255, 255, 0.22);
  background: linear-gradient(180deg, rgba(139, 92, 246, 0.08), rgba(0, 0, 0, 0.12));
  cursor: pointer;
  outline: none;
  transition:
    border-color 0.2s ease,
    background 0.2s ease,
    box-shadow 0.2s ease;
}
.dropzone:hover {
  border-color: rgba(139, 92, 246, 0.45);
  background: linear-gradient(180deg, rgba(139, 92, 246, 0.12), rgba(0, 0, 0, 0.14));
}
.dropzone:focus-visible {
  border-color: rgba(167, 139, 250, 0.85);
  box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.35);
}
.dropzone.is-dragging {
  border-color: rgba(139, 92, 246, 0.75);
  border-style: solid;
  background: linear-gradient(180deg, rgba(139, 92, 246, 0.18), rgba(0, 0, 0, 0.16));
  box-shadow: 0 12px 40px rgba(139, 92, 246, 0.12);
}
.dropzone.has-file {
  border-style: solid;
  border-color: rgba(34, 197, 94, 0.35);
}

.dropzone-inner {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 28px 20px;
  text-align: center;
}

.icon-wrap {
  width: 48px;
  height: 48px;
  border-radius: 14px;
  display: grid;
  place-items: center;
  background: rgba(139, 92, 246, 0.14);
  border: 1px solid rgba(139, 92, 246, 0.28);
  color: rgba(196, 181, 253, 0.95);
}
.upload-icon {
  width: 26px;
  height: 26px;
}

.dropzone-copy {
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-width: 420px;
}
.dropzone-title {
  font-size: 15px;
  font-weight: 600;
  color: rgba(255, 255, 255, 0.92);
}
.dropzone-sub {
  font-size: 13px;
  color: rgba(255, 255, 255, 0.58);
  word-break: break-all;
}

.hint {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.45);
  letter-spacing: 0.03em;
}

.file-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px 14px;
  margin-top: 14px;
  padding: 12px 14px;
  border-radius: 12px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  background: rgba(0, 0, 0, 0.2);
}
.file-name {
  flex: 1 1 200px;
  font-size: 13px;
  color: rgba(255, 255, 255, 0.88);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
}
.file-size {
  font-size: 12px;
}
.muted {
  color: rgba(255, 255, 255, 0.5);
}
.btn-text {
  margin-left: auto;
  padding: 6px 10px;
  border-radius: 8px;
  border: 1px solid rgba(255, 255, 255, 0.14);
  background: rgba(255, 255, 255, 0.04);
  color: rgba(255, 255, 255, 0.85);
  font-size: 13px;
  cursor: pointer;
  transition:
    background 0.2s ease,
    border-color 0.2s ease;
}
.btn-text:hover {
  background: rgba(139, 92, 246, 0.12);
  border-color: rgba(139, 92, 246, 0.35);
}

.status-line {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 14px;
  font-size: 14px;
  color: rgba(196, 181, 253, 0.95);
}
.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: rgba(139, 92, 246, 0.9);
  animation: pulse 1.1s ease-in-out infinite;
}
@keyframes pulse {
  0%,
  100% {
    opacity: 0.45;
  }
  50% {
    opacity: 1;
  }
}

.report-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  margin-top: 18px;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
}
.link {
  color: rgba(255, 255, 255, 0.9);
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  border-radius: 999px;
  border: 1px solid rgba(255, 255, 255, 0.14);
  background: rgba(255, 255, 255, 0.06);
  transition:
    background 0.2s,
    border-color 0.2s,
    transform 0.06s;
}
.link:hover {
  background: rgba(139, 92, 246, 0.14);
  border-color: rgba(139, 92, 246, 0.35);
}
.link:active {
  transform: translateY(1px);
}
.link-muted {
  font-size: 13px;
  color: rgba(255, 255, 255, 0.65);
  border-color: rgba(255, 255, 255, 0.1);
  background: transparent;
}
.link-muted:hover {
  color: rgba(255, 255, 255, 0.88);
  border-color: rgba(255, 255, 255, 0.18);
}
.error {
  margin-top: 14px;
  color: rgba(239, 68, 68, 0.95);
  font-size: 14px;
}

@media (prefers-reduced-motion: reduce) {
  .dropzone,
  .btn-text,
  .link {
    transition: none;
  }
  .status-dot {
    animation: none;
  }
}
</style>
