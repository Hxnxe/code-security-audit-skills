# Master Orchestrator (V6)

推荐优先使用 `scripts/run_audit_cycle.sh` 作为执行入口，由脚本强制控制 RECON/AUDIT/HARDEN 状态流转。

## 0) Bootstrap

```bash
PROJECT_ROOT="<project_root>"
SKILL_ROOT="$PROJECT_ROOT/.opencode/skills/code-security-audit-v6"
API_ROOT="$PROJECT_ROOT/<api_root>"
AUDIT_DIR="$PROJECT_ROOT/audit"
```

预检（必须）：
```bash
python3 - <<'PY' "$PROJECT_ROOT" "$AUDIT_DIR"
import pathlib,sys
project=pathlib.Path(sys.argv[1]).resolve()
audit=pathlib.Path(sys.argv[2]).resolve()
if not str(audit).startswith(str(project) + "/"):
    raise SystemExit(f"AUDIT_DIR must be under PROJECT_ROOT: {audit} !< {project}")
print(f"PATH_OK: audit_dir={audit}")
PY
```

## 1) RECON (混合：机器 + LLM)

### Step 1.1: 机器侦察（phase0_recon_v6 + recon_lite）

```bash
bash "$SKILL_ROOT/scripts/phase0_recon_v6.sh" "$API_ROOT" "$AUDIT_DIR"
```

产出：
- `audit/inventory.jsonl` (语言无关的文件清单)
- `audit/attack-surface.jsonl` (静态信号)
- `audit/scope_stats.json` + `audit/batches.json`
- `audit/attack_surface_stats.json` + `audit/anomalies.jsonl` + `audit/must_investigate.jsonl`
- `audit/audit_targets.md` (P0 目标文件列表)
- `audit/audit_target_shards.json` (分片计划)
- `audit/repo_overview.md` (仓库概览)

### Step 1.2: LLM 语义侦察（NEW）

执行 `prompts/recon-semantic-v6.md` 生成 `audit/recon-semantic-v6.md`：
- 路由发现（从框架入口文件追踪路由定义）
- 认证检测（识别认证中间件、装饰器、守卫）
- 框架识别（确定 Web 框架、ORM、认证库）
- 业务语义分析（识别高风险业务逻辑：支付、管理员、用户数据）

输入：
- `audit/inventory.jsonl`
- `audit/attack-surface.jsonl`
- 源码文件（按 inventory 中的入口文件和高风险文件）

输出：
- `audit/recon-semantic-v6.md` (结构化 Markdown，包含路由表、认证边界、框架信息)

**跳过 LLM RECON**（仅用于测试）：
```bash
bash "$SKILL_ROOT/scripts/phase0_recon_v6.sh" "$API_ROOT" "$AUDIT_DIR" --skip-semantic
```

### Step 1.3: G0 Gate

```bash
python3 "$SKILL_ROOT/scripts/gate.py" g0 "$AUDIT_DIR" --mode strict
```

Pass condition:
1. `phase0_recon_v6.sh` exits `0`
2. `inventory.jsonl` + `attack-surface.jsonl` + `scope_stats.json` + `batches.json` + `attack_surface_stats.json` + `anomalies.jsonl` + `must_investigate.jsonl` + `audit_targets.md` + `audit_target_shards.json` exist
3. G0 通过（覆盖率达标）
4. （可选）`recon-semantic-v6.md` 存在且格式正确

Fallback（脚本失败或 G0 FAIL）:
- 若 `phase0_recon_v6.sh` 执行失败：按 `prompts/recon-fallback.md` 手动枚举
- 若脚本成功但 G0 FAIL（覆盖率不足）：按 `prompts/recon-fallback.md` 补充枚举，写入 `audit/audit_targets.md`
- Fallback 后重跑 G0，直到 PASS 才能进入 AUDIT
- **禁止在 G0 未通过的情况下进入 AUDIT**
- **禁止手改 `attack-surface.jsonl` 做覆盖率"补分"**；如需修复覆盖，必须重跑 RECON 产物链路（`inventory`/`attack-surface`/`attack_surface_stats` 一致）。

## 2) AUDIT (master 编排 + droid 委派)

### Step 2.1: 读取 audit_targets.md

Master 必须先 Read `audit/audit_targets.md`，获取 P0 文件列表和分类。

若存在 `audit/audit_target_shards.json`，必须按分片推进（wave-by-wave），禁止把全量 50MB+ RECON 产物一次塞给子代理。

### Step 2.2: 并行委派 3 个 scanner droid

按当前 shard 同时启动 3 个 Task（每轮仅处理一个 shard）：

优先使用 `audit/droid_dispatch/<shard_id>.md` 或 `.json` 里的明确文件列表；禁止使用"审计 auth/sql/infra"这类无文件清单的通用 prompt。

> **Manifest 追踪**: 每个 shard 完成后，Master 必须调用 `python3 scripts/update_manifest.py <audit_dir> --shard-id <shard_id> --agent <agent> --status done --files <file_list>` 记录进度。

Task 1: `access-scanner`
- 维度：D2 + D3 + D11
- 范围：`audit_targets.md` 中 auth/login、settings、blog、semantic contradiction 相关 P0 文件

Task 2: `injection-scanner`
- 维度：D1 + D4
- 范围：`audit_targets.md` 中 SQL sink 相关文件 + `attack-surface.jsonl` 中 `category=SINK_SQL_LITERAL` 的文件

Task 3: `infra-scanner`
- 维度：D5-D10 + D13
- 范围：seeders/migrations/.env 与 `attack-surface.jsonl` 中 CONFIG_EXPOSURE / SECRET_IN_NON_RUNTIME / HARDCODED_CREDS 信号文件

Task() 约束：
- `subagent_type`: `access-scanner` / `injection-scanner` / `infra-scanner`
- `prompt`: 必须包含 project root、audit dir、以及该 droid 的具体文件列表
- `description`: 简短标签（示例：`D2+D3 auth scan`）
- 若任一 `subagent_type` 不可用：立即中止并报告 blocker（检查 `opencode.json` agent 注册），禁止降级为通用 agent 继续交付流程
- 单个 Task 文件列表建议不超过 25 个；超出时拆成下一 shard wave

### Step 2.2b: 串行执行 chain-synthesizer

在 3 个 scanner 输出可用后，调用 `chain-synthesizer`：
- 输入：`audit/findings.md`（若已有）、`audit/findings.jsonl`（若已有）、`audit/scanner-alerts/*.md`（可选）
- 输出：`audit/attack-graph.md`
- 约束：不可创建新 `F-XXX`

> **V6 Pipeline Resilience 流程重排序**: scanner → master-verify → findings.md → chain-synthesizer。
> chain-synthesizer 必须在 verification.md 产出后执行，以便消费已验证的 finding 列表。

### Step 2.3: Master L1 验证（MANDATORY，NEW）

**这是 V6 强制步骤，不可跳过。**

Master 收到 3 份 scanner 报告后，必须对所有 L1 ALERT 逐条复核：

1. **执行 `prompts/master-verify.md`**
   - 对每个 L1 ALERT，亲自 Read 源码验证
   - 追踪数据流：从入口到 sink 的完整调用链
   - 验证认证边界：检查路径上是否存在认证/授权校验
   - 审查业务逻辑：判断是否存在语义矛盾
   - 给出独立判定：`CONFIRMED` / `DISPUTED` / `NEEDS_DEEPER`

2. **产出 `audit/verification.md`**
   - 必须包含验证摘要（总计、确认、推翻、待定）
   - 必须包含逐条 V-XXX 条目（来源、文件、数据流追踪、验证结论、证据）
   - `NEEDS_DEEPER` 不可超过总数的 20%
   - 每个 CONFIRMED 必须提供从入口到 sink 的完整调用链
   - 每个 DISPUTED 必须提供反证代码路径

3b. **产出 `audit/verification.jsonl`**（NEW）
   - 在 verification.md 完成后，运行 `python3 scripts/extract_verification.py <audit_dir>`
   - 产出结构化的 verification.jsonl，供 gate.py G1 和 chain-synthesizer 消费

3. **验证标准（强约束）**
   - 必须亲自 Read 源码，不可仅依赖 scanner 报告中的描述
   - 对每个结论必须提供 `file:line` 证据
   - 不得遗漏任何 L1 ALERT

4. **扩散同类模式**
   - 对验证通过的模式用 `rg` 全量扩散同类
   - 合并所有 L2 ALERT，按 droid 抽样验证

5. **LSP 证据覆盖**
   - 汇总 3 份报告中的 `LSP_EVIDENCE`，逐一核对 `audit_targets.md` 的每个 P0 文件
   - 必须存在至少一条 LSP 证据（`goto_definition` / `find_references`），或
   - 明确 `LSP_UNAVAILABLE` + `RG_FALLBACK` 证据

### Step 2.4: 写入 findings.md

按 `prompts/audit.md` 规范输出 `audit/findings.md`，并包含 `## P0 语义证据覆盖（LSP）` 汇总表。

## 3) HARDEN

### Step 3.1: 结构化提取
先校验 findings 模板：
```bash
python3 "$SKILL_ROOT/scripts/validate_findings_md.py" --audit-dir "$AUDIT_DIR"
```

```bash
python3 "$SKILL_ROOT/scripts/extract_findings.py" "$AUDIT_DIR"
```
交付路径禁止使用 `--lenient`（仅调试可用）。
如果 exit code 非 0 且 stderr 包含 `extraction quality too low`，说明 findings.md 中标签格式不正确（可能用了英文标签）。必须回到 Step 2.4 修正 findings.md 为中文标签格式后重新提取。

### Step 3.2: Judge（Master 角色切换为防御方）

若 `audit/verdict.json` 缺失，先运行：
```bash
python3 "$SKILL_ROOT/scripts/generate_verdict_skeleton.py" "$AUDIT_DIR" --out "$AUDIT_DIR/verdict.skeleton.json" --overwrite
```
再基于 skeleton 完成 pass1/pass2，写 `audit/verdict_draft.md`，并运行：
```bash
python3 "$SKILL_ROOT/scripts/compile_verdict.py" "$AUDIT_DIR" --overwrite
```
生成 `audit/verdict.json`（禁止手猜 schema）。

**Pass 1**（对抗性反证，按 `prompts/judge-pass1.md`）:
1. Read `audit/findings.jsonl`
2. 对每个 finding 选 ≥2 种反证策略：
   AUTHZ_GUARD_EXISTS / SANITIZER_PRESENT / UNREACHABLE_SINK / SAFE_API_USED / PRECONDITION_IMPOSSIBLE / FRAMEWORK_PROTECTION / RATE_LIMIT_PRESENT
3. 每种策略 Read 代码给出 file:line 证据
4. 记录 FAILED_TO_DISPROVE / DISPROVED / INCONCLUSIVE

**Pass 2**（最终裁决，按 `prompts/judge-pass2.md` + `schemas/verdict.schema.json`）:
1. 消费 Pass 1 结果
2. 输出 `audit/verdict.json`（必须为顶层对象：`{"verdicts": [...]}`）
3. 每元素必含：`schema_version`(1), `finding_id`, `validity_verdict`, `severity_action`, `disproof_attempts`(≥2), `independent_code_refs`
4. CONFIRMED 需 `confirmation_basis`；DISPUTED 需 `refuting_code_path`
5. 最终交付禁止 NEEDS_CONTEXT

### Step 3.3: Coverage + Progress Report

```bash
python3 "$SKILL_ROOT/scripts/build_coverage.py" "$AUDIT_DIR" --iteration 1
```

生成 `audit/coverage.json`，包含：
- `audited_files`: 已审计文件列表
- `coverage_gap`: 是否存在覆盖缺口（布尔值）
- `uncovered_targets`: 未覆盖的高风险目标列表

**用户驱动决策**
- 不再自动回到 Step 2.3 补查
- 用户通过 `audit/progress.md` 了解审计进度，自行决定是否继续

### Step 3.4: Report + Gate + Progress

```bash
bash "$SKILL_ROOT/scripts/harden_delivery.sh" "$AUDIT_DIR" "${ITERATION:-1}"
```

`harden_delivery.sh` 会在报告前执行：
- 检查 `audit/verification.md` 是否存在（非阻断性 WARNING）
- `export_chains_from_attack_graph.py`（attack-graph 优先，findings fallback）
- `gate.py all --mode ${GATE_MODE:-advisory}`（默认交互式，strict 用于 CI/最终硬阻断）
- `compile_report.py` 生成 `audit/report.md`

完成后，`run_audit_cycle.sh` 会调用：
```bash
python3 "$SKILL_ROOT/scripts/build_progress.py" "$AUDIT_DIR" --iteration "$ITERATION"
```

生成 `audit/progress.md`，包含：
- 覆盖率概览（总目标文件、已审计、已确认漏洞、待验证）
- 已确认漏洞摘要表
- 未覆盖高风险目标列表（按风险评分排序）
- 建议下一步操作

### Step 3.5: 用户决策（NEW）

用户读取 `audit/progress.md` 后，可选择：

1. **继续审计未覆盖目标**
   ```bash
   AUDIT_TARGETS=file1,file2,file3 SKIP_RECON=1 bash scripts/run_audit_cycle.sh "$PROJECT_ROOT" "$API_ROOT" "$AUDIT_DIR" 2
   ```

2. **停止审计并接受当前报告**
   - 直接使用 `audit/report.md` 作为最终交付

3. **调整审计方向**
   - 修改 `audit/audit_target_shards.json` 中的优先级
   - 重新运行审计周期

## Delivery Files

- `audit/inventory.jsonl`
- `audit/attack-surface.jsonl`
- `audit/audit_targets.md`
- `audit/recon-semantic-v6.md` (NEW)
- `audit/droid_dispatch/*.md`
- `audit/verification.md` (NEW)
- `audit/verification.jsonl` (NEW)
- `audit/manifest.jsonl` (NEW)
- `audit/findings.md`
- `audit/findings.jsonl`
- `audit/chains.json`
- `audit/verdict.json`
- `audit/coverage.json`
- `audit/progress.md` (NEW)
- `audit/report.md`
