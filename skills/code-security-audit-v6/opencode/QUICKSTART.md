# OpenCode Quickstart (V6)

## 推荐入口（控制面脚本）

```bash
bash scripts/run_audit_cycle.sh <project_root> <api_root> <project_root>/audit 1
```

- exit `2`: 需要按 `coverage.next_targets` 做 R2 回补后重跑（`SKIP_RECON=1`）。
- exit `3`: 已生成 `audit/verdict.skeleton.json`，先完成 Judge 再重跑。

## 1) RECON

```bash
bash scripts/phase0_recon_v6.sh <api_root> audit
```

## 2) AUDIT

- 读取 `audit/droid_dispatch/<shard_id>.md`，按明确文件清单委派 3 个 droid
- 按 `prompts/audit.md` 输出 `audit/findings.md`

## 3) HARDEN

```bash
python3 scripts/validate_findings_md.py --audit-dir audit
python3 scripts/extract_findings.py audit
# judge-pass1 + judge-pass2 -> audit/verdict.json
bash scripts/harden_delivery.sh audit "${R2_ITERATION:-1}"
```

## 4) Deliverables

- `audit/inventory.jsonl`
- `audit/attack-surface.jsonl`
- `audit/findings.md`
- `audit/findings.jsonl`
- `audit/chains.json`
- `audit/verdict.json`
- `audit/coverage.json`
- `audit/report.md`
- `audit/droid_dispatch/*.md`
