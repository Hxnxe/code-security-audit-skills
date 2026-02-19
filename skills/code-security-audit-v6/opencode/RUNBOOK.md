# Runbook (V6)

流程：`RECON(机器+LLM) -> AUDIT(droid委派+master验证) -> HARDEN(judge+进度报告)`

推荐使用 `scripts/run_audit_cycle.sh` 作为控制面入口，避免手工跳步/绕过：

```bash
bash "$SKILL_ROOT/scripts/run_audit_cycle.sh" "$PROJECT_ROOT" "$PROJECT_ROOT/<api_root>" "$PROJECT_ROOT/audit" 1
```

**退出码**：
- 0: 审计完成（生成 progress.md）
- 3: 需要 Judge 介入（填写 verdict.json）
- 10: findings.md 缺失（需先执行 AUDIT）
- 1: 其他错误

## Step 0: RECON（机器 + LLM）

```bash
PROJECT_ROOT=<repo_root>
SKILL_ROOT="$PROJECT_ROOT/.opencode/skills/code-security-audit-v6"
bash "$SKILL_ROOT/scripts/phase0_recon_v6.sh" "$PROJECT_ROOT/<api_root>" "$PROJECT_ROOT/audit"
```

路径预检（防止产物写入 skill 目录）：
```bash
python3 - <<'PY' "$PROJECT_ROOT" "$PROJECT_ROOT/audit"
import pathlib,sys
project=pathlib.Path(sys.argv[1]).resolve()
audit=pathlib.Path(sys.argv[2]).resolve()
if not str(audit).startswith(str(project) + "/"):
    raise SystemExit("AUDIT_DIR must be inside PROJECT_ROOT")
print("PATH_OK")
PY
```

**LLM RECON（新增）**：
- 若 `phase0_recon_v6.sh` 输出 `ACTION_REQUIRED`，执行 `prompts/recon-semantic-v6.md` 进行语义补充
- 测试时可用 `--skip-semantic` 跳过此步骤：
  ```bash
  bash "$SKILL_ROOT/scripts/phase0_recon_v6.sh" "$API_ROOT" "$AUDIT_DIR" --skip-semantic
  ```

校验：
```bash
python3 "$SKILL_ROOT/scripts/gate.py" g0 "$PROJECT_ROOT/audit" --mode strict
```

回退：
- 若 RECON 失败或 `audit/audit_targets.md` 缺失，执行 `prompts/recon-fallback.md` 手动生成 `audit_targets.md` 后再继续。
- 禁止手动编辑 `attack-surface.jsonl` 直接抬高覆盖率；应通过重跑 RECON/fallback 重新生成一致产物（含 `attack_surface_stats.json`）。
- RECON 会自动生成 `audit/audit_target_shards.json` + `audit/audit_target_shards.md`；大仓库必须按 shard 分轮审计。
- RECON 还会生成 `audit/droid_dispatch/<shard_id>.md` 与 `.json`；AUDIT 必须使用这些明确文件清单进行委派。

## Step 1: AUDIT（master + 3 scanner + 1 chain synth + master verify）

1. Read `audit/audit_targets.md`
   - 若存在 `audit/audit_target_shards.json`，先按 shard 取本轮文件列表
   - 同时读取 `audit/droid_dispatch/<shard_id>.md`，直接使用其文件清单构造 Task prompt
2. 按 D2/D3/D11 | D1/D4 | D5-D10/D13 拆分文件列表
3. 并行 Task() 调用 `access-scanner` / `injection-scanner` / `infra-scanner`，每个 Task 的 prompt 必须含具体文件列表
   - 单个 Task 文件列表建议不超过 25 个，超出拆到下一轮 shard
   - 若出现 subagent 不可用错误：立即中止，修复 `opencode.json` 的 agent 注册后重试；禁止用通用 agent 代替
4. 收集 3 份 ALERT 报告
5. 逐个验证 L1 ALERT（Read 源码）
6. 扩散搜索同类模式
7. 汇总 `LSP_EVIDENCE`，核对每个 P0 文件：
   - 至少 1 条 LSP 证据（`goto_definition` / `find_references`），或
   - `LSP_UNAVAILABLE` + `RG_FALLBACK` 证据
8. 构建攻击链
9. 串行调用 `chain-synthesizer`，产出 `audit/attack-graph.md`
10. 写入 `audit/findings.md`（包含 `## P0 语义证据覆盖（LSP）` 表）
11. **Master 验证（新增，必须执行）**：
    - 执行 `prompts/master-verify.md`
    - 产出 `audit/verification.md`
    - 此步骤不可跳过

## Step 2: HARDEN（机器 + Judge）

0. 先校验 findings 模板
```bash
python3 "$SKILL_ROOT/scripts/validate_findings_md.py" --audit-dir "$PROJECT_ROOT/audit"
```
1. 结构化提取
```bash
python3 "$SKILL_ROOT/scripts/extract_findings.py" "$PROJECT_ROOT/audit"
```
   - 交付路径禁止 `--lenient`（仅调试可用）
   - 若 exit 1 + stderr 含 `extraction quality too low` → 回修 findings.md 中文标签
2. Judge（Master 切换为防御方）:
   a. Read `audit/findings.jsonl`，对每个 finding 按 `prompts/judge-pass1.md` 选 ≥2 种反证策略，Read 代码验证
   b. 先写 `audit/verdict_draft.md`，再运行 `compile_verdict.py` 编译为 `audit/verdict.json`
3. 计算覆盖率
```bash
python3 "$SKILL_ROOT/scripts/build_coverage.py" "$PROJECT_ROOT/audit" --iteration 1
```
4. 生成报告 + 最终验收
```bash
bash "$SKILL_ROOT/scripts/harden_delivery.sh" "$PROJECT_ROOT/audit" "${ITERATION:-1}"
```
5. 查看审计进度：
   - 检查 `audit/progress.md` 了解覆盖状态
   - 用户根据进度报告决定下一步行动（见下文"查看审计进度"和"用户定向补扫"）

## 查看审计进度

审计完成后，查看 `audit/progress.md` 了解：
- **覆盖率统计**：已审计文件数 / 总目标文件数
- **发现汇总**：按严重程度分类的漏洞数量
- **未覆盖目标**：尚未审计的文件列表（如有）

手动生成进度报告：
```bash
python3 "$SKILL_ROOT/scripts/build_progress.py" "$PROJECT_ROOT/audit" --iteration 1
```

根据进度报告，用户可以：
- 若覆盖率满意且无重要遗漏 → 审计结束
- 若存在未覆盖的关键文件 → 执行定向补扫（见下文）

## 用户定向补扫

若需要对特定文件进行补充审计，使用 `AUDIT_TARGETS` 环境变量：

```bash
AUDIT_TARGETS="<path1>,<path2>" bash "$SKILL_ROOT/scripts/run_audit_cycle.sh" "$PROJECT_ROOT" "$API_ROOT" "$AUDIT_DIR" 2
```

**说明**：
- `AUDIT_TARGETS`：逗号分隔的文件路径列表（相对于 `PROJECT_ROOT`）
- 设置 `AUDIT_TARGETS` 会自动跳过 RECON 阶段（`SKIP_RECON=1`）
- 迭代号（第 4 个参数）建议递增，用于区分不同轮次的审计

**手动跳过 RECON**（不使用 `AUDIT_TARGETS` 时）：
```bash
SKIP_RECON=1 bash "$SKILL_ROOT/scripts/run_audit_cycle.sh" "$PROJECT_ROOT" "$API_ROOT" "$AUDIT_DIR" 2
```
