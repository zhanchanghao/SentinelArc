#!/usr/bin/env bash
# 方案 B：不执行 source .venv/bin/activate，直接用项目内 Python 以模块方式启动 uvicorn
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x .venv/bin/python ]] && [[ ! -x .venv/bin/python3 ]]; then
  echo "未找到 .venv。请先执行：" >&2
  echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

PY=.venv/bin/python
[[ -x "$PY" ]] || PY=.venv/bin/python3

exec "$PY" -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
