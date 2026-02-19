# Usage (V6)

## One-pass Skeleton

1. `bash scripts/phase0_recon_v6.sh <api_root> audit`
   - RECON 会同时生成 `audit/audit_targets.md`、`audit/audit_target_shards.json`、`audit/droid_dispatch/*.md`
2. 按 shard 读取 `audit/droid_dispatch/<shard_id>.md`，并行委派 3 个 droid，按 `prompts/audit.md` 输出 `audit/findings.md`
3. `python3 scripts/validate_findings_md.py --audit-dir audit`
4. `python3 scripts/extract_findings.py audit`
5. Judge 产出 `audit/verdict.json`
6. `bash scripts/harden_delivery.sh audit "${R2_ITERATION:-1}"`

## R2 Loop

如果 `coverage.json.r2_required=true`，按 `coverage.json.next_targets` 回到 AUDIT 补查，再次执行 HARDEN。
