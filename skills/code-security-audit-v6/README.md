# Code Security Audit V6

> **一句话**：轻量机器枚举（rg + ast-grep）驱动 RECON，LLM 语义侦察补盲，3 个专用 scanner droid 并行深挖，Master 逐条验证 + 攻击链合成，机器化 HARDEN 交付。用户驱动审计节奏。

---

## 目录

- [设计哲学](#设计哲学)
- [适用场景](#适用场景)
- [快速开始](#快速开始)
- [三阶段架构](#三阶段架构)
  - [Phase 0: RECON](#phase-0-recon)
  - [Phase 1: AUDIT](#phase-1-audit)
  - [Phase 2: HARDEN](#phase-2-harden)
- [目录结构](#目录结构)
- [脚本清单](#脚本清单)
- [Prompt 清单](#prompt-清单)
- [Droid 子代理](#droid-子代理)
- [Schema 与规则](#schema-与规则)
- [审计维度（D1–D13）](#审计维度d1d13)
- [产物清单](#产物清单)
- [Gate 门禁](#gate-门禁)
- [用户驱动补扫](#用户驱动补扫)
- [不可违反规则](#不可违反规则)
- [环境要求](#环境要求)
- [常见问题](#常见问题)

---

## 设计哲学

V6 的核心设计基于对 V1–V5 五代演化的根因分析。历史上所有失败模式的本质不是"模型不够聪明"，而是 **执行控制失败（Execution Control Failure）**——信任 LLM 非结构化输出，导致数据在阶段间丢失或变形。

V6 通过三个结构性决策解决这一根因：

| 决策 | 原则 | 实现 |
|------|------|------|
| **证据类型化管道** | 阶段间数据必须是结构化的 `file:line`，不是自由文本 | 所有 JSONL/JSON 产物有 JSON Schema 校验；findings 使用中文标签模板强制格式 |
| **覆盖率核算** | 每个阶段都计算覆盖率差值，不只在最后看 | G0 gate 验证 RECON 覆盖率；coverage.json 计算 AUDIT 覆盖率；progress.md 呈现全局进度 |
| **链 = 约束满足** | 攻击链只能从已验证的边构建，不是自由叙事 | chain-synthesizer 只能引用已有 F-XXX；每步需要 `file:line` 证据 |

其他关键设计选择：
- **零新依赖**：仅使用环境已有的 `rg`、`ast-grep`、TypeScript LSP
- **语言无关**：rg + ast-grep 支持 25+ 语言，不为单一框架写专用脚本
- **机器做确定性工作，LLM 做语义判断**：RECON 枚举和 HARDEN 提取由脚本完成；语义侦察、深度审计、攻击链推理由 LLM 完成
- **用户驱动审计节奏**：不自动回补，通过 `progress.md` 让用户决定是否继续

---

## 适用场景

- 大规模白盒安全审计（已在大型代码库验证，RECON 通常为数十秒级）
- 需要兼顾"发现能力 + 可验证交付"
- 需要降低单 LLM 自由审计的漏报风险
- 支持多语言项目（Python / Java / Go / PHP / Node.js / Ruby / Rust / C# 等）

---

## 快速开始

### 一键启动（推荐）

```bash
# 控制面脚本，强制阶段流转
bash scripts/run_audit_cycle.sh <project_root> <api_root> <audit_dir> 1
```

### 分步执行（调试用）

```bash
PROJECT_ROOT="<repo_root>"
SKILL_ROOT="$PROJECT_ROOT/.opencode/skills/code-security-audit-v6"
AUDIT_DIR="$PROJECT_ROOT/audit"

# 1. RECON：机器枚举 + schema 校验 + gate
bash "$SKILL_ROOT/scripts/phase0_recon_v6.sh" "$PROJECT_ROOT/<api_root>" "$AUDIT_DIR"

# 2. RECON（LLM）：语义侦察（按提示执行 prompts/recon-semantic-v6.md）

# 3. AUDIT：按 droid_dispatch 委派 3 个 scanner + chain-synthesizer + master verify
#    → 产出 audit/findings.md + audit/verification.md

# 4. HARDEN：校验 → 提取 → Judge → 交付
python3 "$SKILL_ROOT/scripts/validate_findings_md.py" --audit-dir "$AUDIT_DIR"
python3 "$SKILL_ROOT/scripts/extract_findings.py" "$AUDIT_DIR"
# Judge pass1 + pass2 → audit/verdict.json
bash "$SKILL_ROOT/scripts/harden_delivery.sh" "$AUDIT_DIR" 1
```

### 退出码

| 码 | 含义 |
|----|------|
| `0` | 审计完成，`progress.md` 已生成 |
| `2` | 覆盖率缺口，查看 `progress.md` 决定是否补扫 |
| `3` | 需要 Judge 介入，先完成 `verdict.json` 再重跑 |
| `10` | `findings.md` 缺失，需先执行 AUDIT |
| `1` | 其他错误 |

---

## 三阶段架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Phase 0: RECON                             │
│  ┌──────────────┐   ┌──────────────────┐   ┌───────────────────┐   │
│  │ phase0_recon  │──>│ recon_lite.py    │──>│ gate.py G0       │   │
│  │ _v6.sh       │   │ (rg + ast-grep)  │   │ (coverage check) │   │
│  └──────────────┘   └──────────────────┘   └───────────────────┘   │
│         │                    │                       │              │
│         v                    v                       v              │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ 9+ artifacts: inventory.jsonl, attack-surface.jsonl,        │   │
│  │ audit_targets.md, audit_target_shards.json, droid_dispatch/ │   │
│  └──────────────────────────────────────────────────────────────┘   │
│         │                                                           │
│         v                                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ LLM: recon-semantic-v6.md → audit/recon-semantic-v6.md      │   │
│  │ (路由发现 / 认证检测 / 框架识别 / 业务语义)                   │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              v
┌─────────────────────────────────────────────────────────────────────┐
│                          Phase 1: AUDIT                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │ access-     │  │ injection-  │  │ infra-      │  ← 并行委派      │
│  │ scanner     │  │ scanner     │  │ scanner     │                 │
│  │ (D2/D3/D11) │  │ (D1/D4)    │  │ (D5-10/D13) │                 │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                 │
│         └────────────────┼────────────────┘                         │
│                          v                                          │
│               ┌─────────────────────┐                               │
│               │ chain-synthesizer   │ ← 串行                        │
│               │ → attack-graph.md   │                               │
│               └─────────┬───────────┘                               │
│                         v                                           │
│               ┌─────────────────────┐                               │
│               │ Master L1 验证      │ ← 强制步骤                     │
│               │ → verification.md   │                               │
│               └─────────┬───────────┘                               │
│                         v                                           │
│               ┌─────────────────────┐                               │
│               │ → findings.md       │                               │
│               └─────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              v
┌─────────────────────────────────────────────────────────────────────┐
│                         Phase 2: HARDEN                             │
│  validate_findings_md → extract_findings → Judge(pass1+pass2)      │
│  → verdict.json → build_coverage → harden_delivery                 │
│  → chains.json → coverage.json → report.md → progress.md          │
│                                                                     │
│  gate.py all → 最终验收                                              │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 0: RECON

**目标**：用机器确定性地枚举代码库，生成结构化审计靶标。

| 步骤 | 执行者 | 工具 | 产出 |
|------|--------|------|------|
| Step 1: 机器枚举 | `phase0_recon_v6.sh` + `recon_lite.py` | `rg --files` + `rg` 模式匹配 + `ast-grep` AST 匹配 | `inventory.jsonl`, `attack-surface.jsonl`, `scope_stats.json`, `batches.json`, `attack_surface_stats.json`, `anomalies.jsonl`, `must_investigate.jsonl`, `audit_targets.md`, `audit_target_shards.json`, `droid_dispatch/*.md` |
| Step 2: 语义侦察 | LLM | `Grep`, `ast_grep_search`, `Read` | `recon-semantic-v6.md`（路由发现、认证检测、框架识别、业务语义） |
| Step 3: G0 Gate | `gate.py g0` | Schema 校验 + 覆盖率计算 | `status.json`（PASS/FAIL） |

**回退机制**：若脚本失败或 G0 FAIL，执行 `prompts/recon-fallback.md` 手动枚举后重跑 G0。

**recon_lite.py 核心逻辑**（1318 行）：
1. `rg --files` 枚举所有源码文件，按后缀识别语言
2. 文件分层（S1–S7 stratum）：基于路径特征和信号强度
3. 加载 `rules/patterns/*.yml`（11 条规则），用 `rg` 和 `ast-grep` 执行信号检测
4. 聚合信号生成 `attack-surface.jsonl`
5. 从高风险信号推导 `anomalies.jsonl` 和 `must_investigate.jsonl`
6. 生成 `audit_targets.md`（P0/P1 分级）和分片计划

### Phase 1: AUDIT

**目标**：3 个专用 droid 并行深挖 + Master 逐条验证 + 攻击链合成。

**关键约束**：
- Master 不做 bulk scanning，只做编排、验证、合成
- 每个 droid 必须使用 `droid_dispatch/<shard_id>.md` 中的明确文件列表
- 所有 droid 必须使用 LSP 工具（`lsp_goto_definition` / `lsp_find_references`）+ fallback 协议
- scanner 完成后 Master 必须执行 `prompts/master-verify.md` 对每个 L1 ALERT 逐条复核

**AUDIT 输出**：
- `findings.md`：中文标签模板，含 `F-XXX` 编号、`file:line` 证据、攻击链、已检查文件表、LSP 证据覆盖表
- `verification.md`：Master 独立验证结论（CONFIRMED / DISPUTED / NEEDS_DEEPER）

### Phase 2: HARDEN

**目标**：机器化提取 + 对抗性裁决 + 覆盖率交付。

| 步骤 | 脚本/Prompt | 产出 |
|------|-------------|------|
| 1. 格式校验 | `validate_findings_md.py` | 校验 findings.md 中文标签和 MI-ID |
| 2. 结构化提取 | `extract_findings.py` | `findings.jsonl` |
| 3. Judge Pass 1 | `judge-pass1.md` | 对抗性反证（≥2 策略/finding） |
| 4. Judge Pass 2 | `judge-pass2.md` + `compile_verdict.py` | `verdict.json` |
| 5. 攻击链导出 | `export_chains_from_attack_graph.py` | `chains.json` |
| 6. 覆盖率计算 | `build_coverage.py` | `coverage.json` |
| 7. 报告编译 | `compile_report.py` | `report.md` |
| 8. 最终验收 | `gate.py all` | `status.json` |
| 9. 进度报告 | `build_progress.py` | `progress.md` |

---

## 目录结构

```
.opencode/skills/code-security-audit/
├── SKILL.md                    # Skill 入口（OpenCode 加载点）
├── USAGE.md                    # 快速用法参考
├── README.md                   # 本文档
│
├── scripts/                    # 16 个脚本（~6.7K 行）
│   ├── phase0_recon_v6.sh      #   RECON 入口（调用 recon_lite.py + validate + gate）
│   ├── recon_lite.py           #   V6 核心：rg+sg → 9+ 产物（1318 行）
│   ├── run_audit_cycle.sh      #   控制面：强制 RECON→AUDIT→HARDEN 状态机
│   ├── gate.py                 #   G0/G1 门禁（覆盖率 + schema + artifact 校验）
│   ├── build_droid_dispatch.py #   从 shards 生成 droid_dispatch/*.md
│   ├── validate_findings_md.py #   校验 findings.md 格式（中文标签、MI-ID）
│   ├── extract_findings.py     #   findings.md → findings.jsonl
│   ├── compile_verdict.py      #   verdict_draft.md → verdict.json
│   ├── generate_verdict_skeleton.py  # 生成 verdict skeleton
│   ├── export_chains_from_attack_graph.py  # attack-graph.md → chains.json
│   ├── build_coverage.py       #   计算覆盖率 → coverage.json
│   ├── build_progress.py       #   生成进度报告 → progress.md
│   ├── compile_report.py       #   编译最终报告 → report.md
│   ├── harden_delivery.sh      #   HARDEN 流水线（chains + gate + report）
│   ├── shared_utils.py         #   公共工具函数
│   └── validate_schema.py      #   JSON Schema 校验器
│
├── prompts/                    # 7 个 LLM prompt
│   ├── recon-semantic-v6.md    #   语义侦察（Phase 0.5）
│   ├── recon-fallback.md       #   RECON 回退（脚本失败时手动枚举）
│   ├── audit.md                #   AUDIT master 合成 prompt
│   ├── master-verify.md        #   L1 ALERT 逐条复核 prompt
│   ├── judge-pass1.md          #   对抗性反证 prompt
│   ├── judge-pass2.md          #   最终裁决 prompt
│   └── report.md               #   报告生成 prompt
│
├── droids/                     # 4 个子代理 prompt
│   ├── access-scanner.md       #   D2 认证 / D3 授权 / D11 信息泄露
│   ├── injection-scanner.md    #   D1 注入 / D4 反序列化
│   ├── infra-scanner.md        #   D5–D10 基础设施 / D13 非运行时资产
│   └── chain-synthesizer.md    #   攻击链合成（仅引用已有 F-XXX）
│
├── schemas/                    # 9 个 JSON Schema
│   ├── inventory.schema.json
│   ├── attack-surface.schema.json
│   ├── finding.schema.json
│   ├── verdict.schema.json
│   ├── verification.schema.json
│   ├── chains.schema.json
│   ├── coverage.schema.json
│   ├── cycle_state.schema.json
│   └── work_queue.schema.json
│
├── rules/                      # 审计规则
│   ├── dimensions.md           #   13 个审计维度定义（D1–D13）
│   ├── scope.md                #   支持的语言和扫描面
│   ├── constraints.md          #   代理约束规则
│   ├── global-rules.md         #   全局规则
│   ├── universal-questions.md  #   8 个通用安全问题
│   └── patterns/               #   11 条 rg/ast-grep 检测规则
│       ├── 01-sql-sinks-rg.yml
│       ├── 01-sql-sinks-go-rg.yml
│       ├── 02-sql-literal-ast.yml
│       ├── 03-public-write.yml
│       ├── 04-auth-logic.yml
│       ├── 05-config-exposure.yml
│       ├── 06-pii-exposure.yml
│       ├── 07-non-runtime-secrets.yml
│       ├── 08-command-exec.yml
│       ├── 09-hardcoded-credentials.yml
│       └── 10-semantic-contradiction.yml
│
├── templates/                  # 运行时模板（仅保留被脚本加载的）
│   ├── repo_overview.md        #   仓库安全概览模板（recon_lite.py 加载）
│   └── progress-report.md      #   进度报告模板（build_progress.py 加载）
│
├── opencode/                   # OpenCode 运行时配置
│   ├── SYSTEM-PROMPT.md        #   系统 prompt（角色定义 + 规则）
│   ├── MASTER-ORCHESTRATOR.md  #   详细编排流程（270 行）
│   ├── RUNBOOK.md              #   分步操作手册
│   └── QUICKSTART.md           #   快速参考
│
└── tests/
    └── fixtures/               # 多语言测试用例
        ├── ts-express/         #   TypeScript + Express
        ├── py-django/          #   Python + Django
        └── go-gin/             #   Go + Gin
```

---

## 脚本清单

### RECON 脚本（2 个）

| 脚本 | 行数 | 职责 |
|------|------|------|
| `phase0_recon_v6.sh` | 60 | RECON 入口：解析参数 → 调用 `recon_lite.py` → schema 校验 → 生成 droid dispatch → G0 gate |
| `recon_lite.py` | 1318 | V6 核心引擎：`rg --files` 枚举 → 文件分层 → 加载 11 条规则 → rg/sg 信号扫描 → 聚合为 9+ 产物 |

### HARDEN 脚本（11 个）

| 脚本 | 职责 |
|------|------|
| `validate_findings_md.py` | 校验 `findings.md` 格式：中文标签、F-XXX 编号、MI-ID 覆盖 |
| `extract_findings.py` | `findings.md` → `findings.jsonl`（结构化提取） |
| `generate_verdict_skeleton.py` | 生成 `verdict.skeleton.json`（Judge 输入） |
| `compile_verdict.py` | `verdict_draft.md` → `verdict.json` |
| `export_chains_from_attack_graph.py` | `attack-graph.md` → `chains.json`（优先 attack-graph，fallback findings） |
| `build_coverage.py` | 计算覆盖率 → `coverage.json` |
| `build_progress.py` | 生成进度报告 → `progress.md` |
| `compile_report.py` | 编译最终中文报告 → `report.md` |
| `harden_delivery.sh` | HARDEN 流水线编排（chains + gate + report） |
| `gate.py` | G0（RECON 验收）+ G1（交付验收）门禁 |
| `build_droid_dispatch.py` | 从 `audit_target_shards.json` 生成 `droid_dispatch/*.md` + `.json` |

### 工具脚本（3 个）

| 脚本 | 职责 |
|------|------|
| `run_audit_cycle.sh` | 控制面：强制 RECON→AUDIT→HARDEN 状态机，管理退出码 |
| `shared_utils.py` | 公共工具（时间戳、路径归一化、常量） |
| `validate_schema.py` | JSON Schema 校验器 |

---

## Prompt 清单

| Prompt | 阶段 | 执行者 | 核心约束 |
|--------|------|--------|---------|
| `recon-semantic-v6.md` | RECON | LLM | 必须消费 Phase 0 产物 → 3stone 方法 → 输出结构化模块地图 + AUDIT 聚焦建议 |
| `recon-fallback.md` | RECON | LLM | 脚本失败时手动枚举 → 重建 `audit_targets.md` + 分片 + droid dispatch → 重跑 G0 |
| `audit.md` | AUDIT | Master | 6 步合成：读语义侦察 → 验证 L1 → 抽样 L2 → 扩散搜索 → 攻击链 → 覆盖率自检 |
| `master-verify.md` | AUDIT | Master | 对每个 L1 ALERT 执行 4 步复核：数据流追踪 → 认证边界 → 业务逻辑 → 独立判定 |
| `judge-pass1.md` | HARDEN | Master（切换防御视角） | 对每个 finding 选 ≥2 种反证策略，Read 代码验证 |
| `judge-pass2.md` | HARDEN | Master | 消费 Pass 1 结果，输出 `verdict.json` |
| `report.md` | HARDEN | LLM | 生成中文复现报告，含 PoC |

---

## Droid 子代理

V6 固定 4 个子代理（不可动态增减），需在 `opencode.json` 中注册：

| Droid | 覆盖维度 | 扫描重点 | LSP 工具 |
|-------|---------|---------|---------|
| `access-scanner` | D2 认证 / D3 授权 / D11 信息泄露 | 公开写操作、无认证端点、PII 泄露、语义矛盾 | `lsp_goto_definition` + `lsp_find_references` + `ast_grep_search` + `Grep` |
| `injection-scanner` | D1 注入 / D4 反序列化 | SQL/CMD/SSTI sink、动态查询构建、参数到 sink 的数据流 | 同上 |
| `infra-scanner` | D5–D10 / D13 非运行时资产 | 硬编码凭据、敏感配置暴露、seeder/migration 中的默认密码 | 同上 |
| `chain-synthesizer` | 跨维度 | 仅引用已有 F-XXX 构建攻击链（禁止创造新 finding） | 同上 |

**LSP Fallback 协议**：当 LSP 不可用（非 TS/JS 语言、超时、服务异常），droid 必须：
1. 记录 `LSP_UNAVAILABLE: <reason>`
2. 使用 `Grep` + `Read` 完成等效验证
3. 在 `LSP_EVIDENCE` 表中标注 `RG_FALLBACK`

---

## Schema 与规则

### 9 个 JSON Schema

确保所有产物格式一致，由 `validate_schema.py` 在 pipeline 中自动校验：

| Schema | 校验对象 | 关键字段 |
|--------|---------|---------|
| `inventory.schema.json` | `inventory.jsonl` | `file`, `language`, `stratum`(S1–S7), `risk_score`, `lines` |
| `attack-surface.schema.json` | `attack-surface.jsonl` | `signal_id`, `category`, `source`(RG/AST_GREP), `file`, `line` |
| `finding.schema.json` | `findings.jsonl` | `finding_id`(F-XXX), `severity`, `file`, `line` |
| `verdict.schema.json` | `verdict.json` | `verdicts[]`, `validity_verdict`, `disproof_attempts`(≥2) |
| `verification.schema.json` | `verification.md` 结构 | V-XXX 条目、CONFIRMED/DISPUTED/NEEDS_DEEPER |
| `chains.schema.json` | `chains.json` | `chains[]`, `finding_refs`, `evidence_refs` |
| `coverage.schema.json` | `coverage.json` | `coverage_gap`, `audited_files`, `uncovered_targets` |
| `cycle_state.schema.json` | `cycle_state.json` | `phase`, `iteration`, `last_status` |
| `work_queue.schema.json` | `work_queue.json` | `queue[]`, `target`, `priority` |

### 11 条检测规则

存放在 `rules/patterns/` 中，被 `recon_lite.py` 加载并用 `rg` / `ast-grep` 执行：

| 规则 | 引擎 | 检测目标 |
|------|------|------|
| `01-sql-sinks-rg` | RG | Sequelize.literal / .query / .raw / createQueryBuilder |
| `01-sql-sinks-go-rg` | RG | Go SQL sink 模式 |
| `02-sql-literal-ast` | AST_GREP | Sequelize.literal($$$) 结构化匹配 |
| `03-public-write` | RG | requiresAuth:false / @PermitAll |
| `04-auth-logic` | RG | 认证/授权逻辑弱点模式 |
| `05-config-exposure` | RG | 配置暴露模式 |
| `06-pii-exposure` | RG | PII 泄露模式 |
| `07-non-runtime-secrets` | RG | 非运行时 secret 检测 |
| `08-command-exec` | RG | 命令执行 sink 检测 |
| `09-hardcoded-credentials` | RG | 硬编码凭据检测 |
| `10-semantic-contradiction` | RG | 语义矛盾（声明权限但实际公开） |

---

## 审计维度（D1–D13）

| ID | 维度 | 定义 | 负责 Droid |
|----|------|------|-----------|
| D1 | Injection | 用户输入到达 SQL/CMD/LDAP/SSTI 执行点 | injection-scanner |
| D2 | Authentication | Token 生成、验证、过期完整性 | access-scanner |
| D3 | Authorization | 敏感操作验证所有权/权限 | access-scanner |
| D4 | Deserialization | 不可信数据反序列化 | injection-scanner |
| D5 | File Operations | 上传/下载路径用户可控 | infra-scanner |
| D6 | SSRF | 服务端 HTTP 请求 URL 用户可控 | infra-scanner |
| D7 | Cryptography | 硬编码密钥、弱算法、不安全随机 | infra-scanner |
| D8 | Configuration | 调试端点、CORS、详细错误、DoS/ReDoS | infra-scanner |
| D9 | Business Logic | 竞态条件、流程绕过、价格操纵 | infra-scanner |
| D10 | Supply Chain | 已知 CVE 依赖 | infra-scanner |
| D11 | Info Disclosure | 公开端点暴露 PII/配置/内部状态 | access-scanner |
| D12 | Data Exposure | 非管理员响应包含不必要的敏感字段 | access-scanner |
| D13 | Non-Runtime Assets | .env/SQL/seeder/migration 中的可利用凭据 | infra-scanner |

---

## 产物清单

审计全程产物写入 `<project_root>/audit/`（禁止写入 skill 目录）。

### RECON 产物

| 产物 | 格式 | 生产者 | 消费者 |
|------|------|--------|--------|
| `inventory.jsonl` | JSONL | `recon_lite.py` | gate, extract_findings, build_coverage, build_progress |
| `attack-surface.jsonl` | JSONL | `recon_lite.py` | gate, extract_findings, build_coverage, droids |
| `scope_stats.json` | JSON | `recon_lite.py` | gate, build_coverage |
| `batches.json` | JSON | `recon_lite.py` | gate |
| `attack_surface_stats.json` | JSON | `recon_lite.py` | gate |
| `anomalies.jsonl` | JSONL | `recon_lite.py` | gate |
| `must_investigate.jsonl` | JSONL | `recon_lite.py` | validate_findings_md, extract_findings, gate, build_droid_dispatch |
| `audit_targets.md` | Markdown | `recon_lite.py` | validate_findings_md, gate, build_progress, droids |
| `audit_target_shards.json` | JSON | `recon_lite.py` | build_droid_dispatch, run_audit_cycle |
| `droid_dispatch/*.md` | Markdown | `build_droid_dispatch.py` | scanner droids（明确文件列表） |
| `repo_overview.md` | Markdown | `recon_lite.py` | chain-synthesizer, Master 全局认知 |
| `recon-semantic-v6.md` | Markdown | LLM | droids, audit.md, master-verify.md |

### AUDIT 产物

| 产物 | 格式 | 生产者 | 消费者 |
|------|------|--------|--------|
| `findings.md` | Markdown（中文标签） | Master | validate_findings_md, extract_findings |
| `verification.md` | Markdown | Master | harden_delivery（存在性检查） |
| `attack-graph.md` | Markdown | chain-synthesizer | export_chains_from_attack_graph |

### HARDEN 产物

| 产物 | 格式 | 生产者 | 消费者 |
|------|------|--------|--------|
| `findings.jsonl` | JSONL | `extract_findings.py` | Judge, build_coverage |
| `verdict.json` | JSON | `compile_verdict.py` | compile_report, gate |
| `chains.json` | JSON | `export_chains_from_attack_graph.py` | compile_report, gate |
| `coverage.json` | JSON | `build_coverage.py` | compile_report, gate, progress |
| `report.md` | Markdown | `compile_report.py` | 最终交付 |
| `progress.md` | Markdown | `build_progress.py` | 用户决策 |
| `status.json` | JSON | `gate.py` | run_audit_cycle 状态判断 |

---

## Gate 门禁

两级门禁，由 `gate.py` 执行：

### G0（RECON 后）

- 校验 `inventory.jsonl` 和 `attack-surface.jsonl` 的 schema 合法性
- 计算信号覆盖率（trusted_critical_coverage）
- `--mode strict`：覆盖率必须 ≥ 阈值才能 PASS
- `--mode advisory`：警告但不阻断

### G1（交付前）

- 校验 `findings.jsonl`, `verdict.json`, `chains.json`, `coverage.json` 存在且合法
- 校验 findings 与 verdict 的 finding_id 一致性
- 校验 MI-ID 覆盖率

### 运行方式

```bash
# RECON 后
python3 scripts/gate.py g0 <audit_dir> --mode strict

# 交付前
python3 scripts/gate.py all <audit_dir> --mode advisory   # 默认
python3 scripts/gate.py all <audit_dir> --mode strict      # CI/最终交付
```

---

## 用户驱动补扫

V6 不自动回补。HARDEN 完成后查看 `audit/progress.md` 了解覆盖状态：

```bash
# 查看进度
cat audit/progress.md

# 定向补扫特定文件
AUDIT_TARGETS="<path1>,<path2>" \
  bash scripts/run_audit_cycle.sh <project_root> <api_root> <audit_dir> 2

# 跳过 RECON 直接补扫
SKIP_RECON=1 bash scripts/run_audit_cycle.sh <project_root> <api_root> <audit_dir> 2
```

---

## 不可违反规则

1. **阶段顺序**：必须 `RECON → AUDIT → HARDEN`，不可跳步
2. **AUDIT 委派**：必须委派 3 个 scanner droid，不可退化为单 LLM 自由扫库
3. **文件列表**：droid 委派必须使用 `droid_dispatch/<shard_id>.md` 的明确文件列表
4. **chain-synthesizer**：只能引用已有 F-XXX，不可创造新 finding
5. **Master 验证**：scanner 完成后必须执行 `master-verify.md`，产出 `verification.md`
6. **中文标签**：`findings.md` 必须使用中文标签模板（英文标签导致提取失败）
7. **产物路径**：写入 `<project_root>/audit/`，禁止写入 skill 目录
8. **交付前提**：`findings.jsonl` + `verdict.json` + `coverage.json` 必须先于 `report.md`
9. **格式校验**：交付前必须运行 `validate_findings_md.py`；提取为 0 条即失败
10. **禁止旁路**：交付路径禁止 `--allow-incomplete` 和 `--lenient`

---

## 环境要求

| 工具 | 版本 | 用途 |
|------|------|------|
| `rg` (ripgrep) | ≥ 15.0 | 文件枚举 + 模式匹配 |
| `ast-grep` (sg) | ≥ 0.40 | AST 结构化匹配（25+ 语言） |
| `python3` | ≥ 3.8 | 脚本执行 |
| TypeScript LSP | — | 可选，用于 AUDIT 阶段的语义追踪（有 fallback） |

**零新依赖**：所有工具均为环境预装，不引入 Semgrep / Joern / CodeQL 等外部依赖。

---

## 常见问题

### Q: RECON 超时怎么办？

V6 的 `recon_lite.py` 在大型代码库上通常能在数十秒级完成 RECON。如果仍超时：
- 检查 `RG_GLOBAL_EXCLUDES` 是否排除了 `node_modules` / `dist` / `.git`
- 使用 `AUDIT_MAX_FILES_PER_SHARD` 调整分片大小

### Q: G0 FAIL 怎么办？

执行 `prompts/recon-fallback.md` 手动枚举，补充 `audit_targets.md`，重跑 G0。禁止手改 `attack-surface.jsonl` 做覆盖率"补分"。

### Q: findings.md 提取失败？

最常见原因：使用了英文标签（如 `**Severity**:` 而非 `**严重程度**:`）。`extract_findings.py` 按中文标签解析，英文标签会导致 exit 1。回到 AUDIT 修正为中文标签后重新提取。

### Q: LSP 不可用怎么办？

droid 内置 LSP Fallback 协议：记录 `LSP_UNAVAILABLE` → 用 `Grep` + `Read` 替代 → 在 `LSP_EVIDENCE` 表中标注 `RG_FALLBACK`。审计质量不受阻断影响。

### Q: 如何对新语言项目使用？

`recon_lite.py` 的 `LANG_MAP` 支持 27 种语言后缀。`rules/patterns/*.yml` 的 `include_globs` 控制每条规则适用的文件类型。添加新语言只需在规则中扩展 glob 模式。

### Q: 如何注册子代理？

在项目的 `opencode.json` 中注册 4 个 agent：

```json
{
  "agents": {
    "access-scanner": { "prompt": ".opencode/skills/code-security-audit-v6/droids/access-scanner.md" },
    "injection-scanner": { "prompt": ".opencode/skills/code-security-audit-v6/droids/injection-scanner.md" },
    "infra-scanner": { "prompt": ".opencode/skills/code-security-audit-v6/droids/infra-scanner.md" },
    "chain-synthesizer": { "prompt": ".opencode/skills/code-security-audit-v6/droids/chain-synthesizer.md" }
  }
}
```
