# Skill 哨卫 安全检查· SentinelArc

> 中文名 哨卫 ——以静态规则做Skill安全审查。  
> 英文名 Sentinel

面向 **Agent Skill、插件包与源码归档** 的轻量安全检测平台：上传压缩包，自动解压（带路径与大小限制）、静态规则扫描、生成结构化报告，并在 Web 端查看任务与发现项。

---

## 功能概览


| 能力        | 说明                                                                        |
| --------- | ------------------------------------------------------------------------- |
| **制品上传**  | 支持 `.zip`、`.tar.gz` / `.tgz`，按 SHA-256 去重存储                               |
| **安全解压**  | 限制解压体积、文件数量、目录深度，阻断路径穿越与危险条目                                              |
| **多类扫描**  | 敏感信息、危险代码模式（SAST）、配置风险、恶意启发式、依赖清单与漏洞（Python 依赖对接 [OSV](https://osv.dev/)） |
| **报告与结论** | 风险评分、严重级别、PASS/FAIL 策略；可下载 JSON 报告                                        |
| **任务队列**  | 异步执行任务，SQLite 持久化任务与发现项                                                   |


---

## 技术栈


| 层级   | 技术                                         |
| ---- | ------------------------------------------ |
| 后端   | Python 3、FastAPI、Uvicorn、SQLite、httpx      |
| 前端   | Vue 3、TypeScript、Vite、Vue Router           |
| 扫描引擎 | `scr/backend/engine/pipeline.py`（规则集版本见配置） |


---

## 仓库结构

```
skill/
├── README.md                 # 本说明
└── scr/
    ├── backend/              # FastAPI 服务与扫描引擎
    │   ├── app/              # 路由、配置、存储、数据库
    │   ├── worker/           # 异步任务执行
    │   ├── engine/           # 解压与扫描管线
    │   ├── requirements.txt
    │   └── run.sh            # 本地启动脚本
    └── frontend/             # Vue 管理界面
        └── src/
```

运行时数据（数据库、制品、工作目录、报告）默认位于 `scr/backend/storage/runtime/`。

补充目录说明：

- `demo/`：演示样例与规则相关实验素材
- `docs/`：项目说明文档与风险处置文档
- `plans/`：阶段性计划或任务拆解记录

---

## 快速开始

### 环境要求

- Python `3.10+`（建议 3.11）
- Node.js `18+`（建议 20 LTS）
- npm `9+`

可选但推荐：

- `curl` / `jq`（用于脚本化调试 API）
- `tree`（查看目录结构）

### 1. 后端

```bash
cd scr/backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
./run.sh
```

默认监听 `http://127.0.0.1:8000`。也可手动执行：

```bash
.venv/bin/python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 2. 前端

```bash
cd scr/frontend
npm install
npm run dev
```

开发时 Vite 将 `/api` 代理到 `http://127.0.0.1:8000`，浏览器访问终端中提示的本地地址（一般为 `http://localhost:5173`）。

生产构建：`npm run build`，若前后端不同源，可通过环境变量 `VITE_API_BASE` 指定后端根地址。

### 3. 最小可用验证

后端与前端均启动后，按以下顺序验证：

1. 打开前端首页，确认任务列表可加载。
2. 上传一个 `.zip` 或 `.tgz` 压缩包创建任务。
3. 等待任务状态从 `queued/running` 变为 `done/failed`。
4. 进入任务详情查看发现项，确认可下载 `report.json`。

---

## API 摘要


| 方法     | 路径                                 | 说明           |
| ------ | ---------------------------------- | ------------ |
| `POST` | `/api/tasks`                       | 上传压缩包，创建扫描任务 |
| `GET`  | `/api/tasks`                       | 分页列出任务       |
| `GET`  | `/api/tasks/{task_id}`             | 任务详情与摘要      |
| `GET`  | `/api/tasks/{task_id}/findings`    | 分页列出发现项      |
| `GET`  | `/api/tasks/{task_id}/report.json` | 下载完整 JSON 报告 |


交互式文档：服务启动后访问 `/docs`（Swagger UI）。

---

## 配置说明

主要参数在 `scr/backend/app/core/config.py` 的 `Settings` 中，例如：

- 上传与解压上限（`max_upload_bytes`、`max_unpacked_bytes` 等）
- 引擎与规则集版本号（`engine_version`、`ruleset_version`）
- 失败策略（如 `fail_on_critical`、`high_count_threshold`、`score_threshold`）

修改后需重启后端进程生效。

---

## 常见问题

### 1) 前端请求失败（`/api` 404 或跨域）

- 确认后端监听在 `127.0.0.1:8000`。
- 确认前端使用 `npm run dev` 启动，并由 Vite 代理 `/api`。
- 若前后端分离部署，设置 `VITE_API_BASE` 指向后端地址后重新构建。

### 2) 上传后任务长时间不结束

- 检查后端日志是否出现解压限制触发（体积/文件数/目录深度）。
- 检查压缩包是否包含异常条目（路径穿越、软链接、超大二进制）。
- 检查 `scr/backend/storage/runtime/` 是否有写入权限与足够磁盘空间。

### 3) 依赖漏洞扫描结果为空

- Python 依赖扫描依赖清单识别与 OSV 查询。
- 若项目不含可识别依赖清单，或网络无法访问 `osv.dev`，结果可能为空。

---

## 免责声明

本工具基于**启发式规则与公开漏洞情报**辅助排查风险，**不能替代**专业渗透测试、代码审计或正式合规认证。报告中的「命中」可能存在误报，请结合业务上下文人工复核。

---

## 许可证

若仓库未单独声明许可证，以项目根目录或各子模块实际附带的开源协议为准。