/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** e.g. http://127.0.0.1:8000 — omit to use same-origin / Vite proxy */
  readonly VITE_API_BASE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
