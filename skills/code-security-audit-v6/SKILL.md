---
name: code-security-audit-v6
description: V6 hybrid security audit skill using lightweight rg+sg RECON + LLM semantic analysis + master-orchestrated droid audit + mandatory deep verification + user-driven audit flow.
---

# Code Security Audit (V6)

## OpenCode Loading Contract

- OpenCode skills are loaded from `SKILL.md` first.
- Critical execution constraints are defined here (do not assume other prompt files are auto-loaded).
- `opencode/SYSTEM-PROMPT.md`, `opencode/MASTER-ORCHESTRATOR.md`, and `opencode/RUNBOOK.md` are companion references for the same contract.
- This skill expects project-level `opencode.json` to register subagents:
  - `access-scanner`
  - `injection-scanner`
  - `infra-scanner`
  - `chain-synthesizer`

## 适用场景

- 大规模白盒安全审计
- 需要兼顾“发现能力 + 可验证交付”
- 需要降低单 LLM 自由审计的漏报风险

## 核心架构

1. `Phase 0: RECON`（混合：机器 + LLM）
- Step 1: `phase0_recon_v6.sh` 调用 `recon_lite.py`（轻量 rg+sg 枚举与信号聚合）
- Step 2: LLM 执行 `prompts/recon-semantic-v6.md` → 产出 `audit/recon-semantic-v6.md`（路由发现、认证检测、框架识别、业务语义分析）
- Step 3: G0 gate 验证
- 产物：`inventory.jsonl`、`attack-surface.jsonl`、`scope_stats.json`、`batches.json`、`attack_surface_stats.json`、`anomalies.jsonl`、`must_investigate.jsonl`、`audit_targets.md`、`audit_target_shards.json`、`recon-semantic-v6.md`、`manifest.jsonl`（分片执行追踪）

2. `Phase 1: AUDIT`（master + droid 委派）
- master 先读 `audit_targets.md`
- 按维度拆分并行 Task：`access-scanner` / `injection-scanner` / `infra-scanner`
- 在 scanner 输出后串行执行 `chain-synthesizer`，生成 `attack-graph.md`
- 收集 ALERT 后，**强制验证**（新）— Master 按 `prompts/master-verify.md` 对每个 L1 ALERT 执行数据流追踪，产出 `audit/verification.md`。此步骤不可跳过。
- 产物：`findings.md`、`verification.md`、`verification.jsonl`（结构化验证条目，由 extract_verification.py 产出）

3. `Phase 2: HARDEN`（机器 + Judge）
- `extract_findings.py` -> `findings.jsonl/chains.json`
- judge pass1/pass2 -> `verdict.json`
- `export_chains_from_attack_graph.py` -> `chains.json`（优先 attack-graph，fallback findings）
- `build_coverage.py` -> `coverage.json`
- `compile_report.py` -> `report.md`
- HARDEN 完成后生成 `audit/progress.md` 进度报告
- `gate.py all` 最终验收
- 产物：`report.md`、`progress.md`

## Gate

- 默认交互模式（advisory）：`python3 scripts/gate.py <g0|g1|all> audit`
- 严格交付模式（strict）：`python3 scripts/gate.py <g0|g1|all> audit --mode strict`

## Non-Negotiable Rules

1. 必须按顺序执行：`RECON -> AUDIT -> HARDEN`。
2. 未生成 `audit/audit_targets.md` 禁止进入 AUDIT。
3. AUDIT 阶段必须委派 3 个 scanner 子代理，不可退化为单 LLM 自由扫库。
4. scanner 完成后必须由 `chain-synthesizer` 合成攻击链，不得直接手写 `chains.json`。
5. 报告前必须完成：`findings.jsonl`、`verdict.json`、`coverage.json`。
6. 审计产物必须写入 `<project_root>/audit/`，禁止写入 skill 目录。
7. AUDIT 委派必须使用 `audit/droid_dispatch/<shard_id>.md` 的明确文件列表，禁止只给通用描述。
8. 交付前必须先运行 `validate_findings_md.py`；`extract_findings.py` 提取为 0 条即视为失败。
9. 交付路径禁止 `--allow-incomplete` 与 `--lenient`。
10. `findings.md` 必须使用中文标签模板（见 `prompts/audit.md`），英文标签会导致提取与 gate 校验失败。

## 快速执行

推荐控制面入口（优先）：
1. `bash "$SKILL_ROOT/scripts/run_audit_cycle.sh" "$PROJECT_ROOT" "$API_ROOT" "$AUDIT_DIR"`

分步入口（调试）：
1. `PROJECT_ROOT=<repo_root>`，`SKILL_ROOT="$PROJECT_ROOT/.opencode/skills/code-security-audit-v6"`
2. `bash "$SKILL_ROOT/scripts/phase0_recon_v6.sh" "<api_root>" "$PROJECT_ROOT/audit"`
3. 读取 `"$PROJECT_ROOT/audit/droid_dispatch/<shard_id>.md"`，按文件清单执行 droid 委派 AUDIT，输出 `"$PROJECT_ROOT/audit/findings.md"`（格式细则见 `prompts/audit.md`）。
4. 先运行 `python3 "$SKILL_ROOT/scripts/validate_findings_md.py" --audit-dir "$PROJECT_ROOT/audit"`，再运行 `python3 "$SKILL_ROOT/scripts/extract_findings.py" "$PROJECT_ROOT/audit"`。
5. Judge 产出 `"$PROJECT_ROOT/audit/verdict.json"`（流程见 `prompts/judge-pass1.md` + `prompts/judge-pass2.md`，schema 见 `schemas/verdict.schema.json`）。
6. `bash "$SKILL_ROOT/scripts/harden_delivery.sh" "$PROJECT_ROOT/audit" 1`

## 用户定向补扫

HARDEN 完成后查看 `audit/progress.md`，了解覆盖率和未审计文件。
用户可通过 `AUDIT_TARGETS` 环境变量指定补扫方向：

```bash
AUDIT_TARGETS=file1,file2 bash "$SKILL_ROOT/scripts/run_audit_cycle.sh" "$PROJECT_ROOT" "$API_ROOT" "$AUDIT_DIR"
```
