## 1. 落地目标与交付物

### 1.1 MVP 交付物
- Web 前端：压缩包上传、任务列表、任务详情（总览 + 命中明细）、报告下载
- Python 后端：上传接收与校验、安全解包、异步扫描任务、结果存储、报告生成与导出（JSON）
- 扫描引擎：覆盖 5 类检测（依赖漏洞、敏感信息、危险能力调用、配置风险、恶意特征启发式）
- 可复现：报告中包含 engine_version / ruleset_version / artifact sha256

### 1.2 MVP 的“最小可用”判定
- 用户上传一个合法 Skill 包即可得到可下载的 JSON 报告
- 任务可查询（状态可追溯、失败可定位原因）
- 明细证据可追溯到具体文件路径（行号/片段可选）

## 2. 总体架构（简单可落地）

### 2.1 模块划分
- 前端（Web）：上传/查询/展示/下载
- API 服务（Python）：鉴权（可先无登录，预留扩展点）、任务与结果接口、文件存储与访问控制
- Worker（Python）：执行解包与扫描，写回结果
- 存储：
  - 任务与结果：SQLite（单机）或 Postgres（后续扩展）
  - Artifact 与解包目录：本地文件系统（MVP）或对象存储（后续扩展）

### 2.2 异步方案（选型建议）
- 优先：API 服务提交任务到队列，Worker 异步执行（推荐 Celery/RQ/Arq 之一）
- 备选（极简单机）：API 内置后台线程/进程队列（仅用于开发与小流量演示，不建议生产）

## 3. 数据模型（MVP 必需字段）
- Artifact：id、sha256、original_filename、size_bytes、uploaded_at、storage_path
- ScanTask：id、artifact_id、status、created_at、started_at、finished_at、engine_version、ruleset_version、summary_json、error_message
- Finding：id、task_id、rule_id、category、severity、confidence、file_path、line_range、snippet_redacted、evidence_json、recommendation
- Rule：rule_id、name、category、severity、confidence_default、enabled、version、definition_json

## 4. 接口规划（MVP API）

### 4.1 上传与创建任务
- POST /api/tasks
  - form-data：file（zip/tar.gz）
  - 返回：task_id、artifact_sha256、status

### 4.2 任务查询
- GET /api/tasks
  - query：status（可选）、from/to（可选）、severity（可选）
  - 返回：分页列表（task_id、created_at、status、summary）
- GET /api/tasks/{task_id}
  - 返回：任务详情（阶段时间、summary、findings 概览）
- GET /api/tasks/{task_id}/findings
  - 返回：findings 列表（可分页）

### 4.3 报告导出
- GET /api/tasks/{task_id}/report.json
  - 返回：JSON 报告（见第 6 节格式）

## 5. 关键工程实现点（MVP 必做）

### 5.1 上传校验与安全解包
- 格式白名单：zip、tar.gz（可配置）
- 限制项：上传大小、解压后总大小、文件数量、目录深度
- 防护点：
  - Zip Slip：拒绝包含 ../ 或绝对路径的条目
  - 符号链接：解包时不跟随，或直接拒绝 link 条目
  - 压缩炸弹：按解压后累计大小与文件数阈值中止
  - 统一落盘：artifact 与解包目录放到受控根目录，按 task_id/sha256 分区

### 5.2 扫描引擎组织方式
- 输入：解包后的根目录 + ruleset_version + 配置
- 输出：summary + findings（结构化）
- 执行策略：
  - 先做文件清单与类型识别（后续规则按文件类型分发）
  - 各类扫描独立实现，最后统一聚合与评分

### 5.3 5 类检测的 MVP 实现建议
1) 依赖与供应链
   - 识别依赖清单（例如 requirements.txt / poetry.lock / package.json 等）
   - 漏洞库匹配（优先接 OSV API；如需离线则落本地镜像或定期同步）
2) 敏感信息泄露
   - 正则规则 + 熵检测（可先正则 MVP）
   - 高风险文件后缀/目录命中（如 .pem/.key/.p12）
3) 危险能力与调用
   - 基于文本/AST 的规则（MVP 可先文本规则：subprocess、eval、exec、pickle 等）
4) 配置与权限风险
   - 识别典型配置文件并做关键项检测（MVP 先覆盖常见键：debug、cors、tls verify）
5) 恶意特征与可疑行为
   - 可疑域名/矿池关键字/下载器命令/混淆痕迹（MVP 先字符串与文件特征）

### 5.4 风险聚合与判定
- 输入：findings（severity、confidence）
- 输出：
  - summary：score、level、各类别统计、top findings
  - conclusion：PASS / FAIL（按阈值配置）
- 阈值配置最小集：
  - fail_on_critical（bool）
  - high_count_threshold（int）
  - score_threshold（int）

## 6. 报告格式（JSON，MVP 标准）
- meta：task_id、artifact_sha256、created_at、engine_version、ruleset_version
- conclusion：PASS/FAIL
- summary：
  - score、level
  - counts_by_severity、counts_by_category
  - top_findings（可选）
- findings：数组
  - rule_id、category、severity、confidence
  - file_path、line_range（可选）、snippet_redacted（可选）
  - evidence（结构化）、recommendation

## 7. 前端页面规划（最小页面集）
- /upload：上传压缩包、展示当前上传进度与任务创建结果
- /tasks：任务列表（状态、创建时间、结论/等级）
- /tasks/{id}：任务详情（总览、命中明细、下载报告）

## 8. 里程碑规划（从 0 到 MVP）

### M0：工程骨架与跑通
- 初始化前端与后端工程
- 上传接口 + 本地落盘 + task_id 返回
- Worker 执行“空扫描”，能生成基础 JSON 报告

### M1：安全解包与任务状态闭环
- 上传校验、解包防护、阶段化状态与错误信息
- 前端任务列表/详情接通，支持轮询刷新状态

### M2：5 类检测 MVP 与评分判定
- 每类至少 1-3 条高价值规则可命中并输出证据
- 风险聚合、阈值判定、报告导出稳定

### M3：可用性增强（仍保持简单）
- 基础去重（sha256）与历史复用策略（可选）
- 规则启停与阈值配置方式固定（配置文件或简易管理页）
- 扫描性能与稳定性优化（并发、超时、资源限制）

## 9. 质量与验证（MVP 要求）
- 单元测试：解包防护、规则匹配、评分判定、报告结构校验
- 集成测试：上传一个样例包能完整跑通并下载报告
- 回归基线：固定样例包 + 固定 ruleset_version，输出可复现

## 10. 风险与取舍（以“简单可落地”为准）
- Skill 语言/生态多样会导致规则体系膨胀：MVP 先按“文件类型 + 规则集”渐进扩展
- 漏洞库数据源依赖外部：优先 OSV 在线；如需离线再引入同步机制
- 误报不可避免：MVP 先提供证据与建议，复核流程不作为主干
