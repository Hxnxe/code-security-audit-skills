# 审计进度报告

生成时间: {{GENERATED_AT}}
迭代: {{ITERATION}}

## 覆盖率概览

| 指标 | 值 |
|------|-----|
| 总目标文件 | {{TOTAL_TARGETS}} |
| 已审计 | {{AUDITED}} ({{AUDITED_PCT}}%) |
| 已确认漏洞 | {{CONFIRMED_COUNT}} |
| 待验证 | {{PENDING_COUNT}} |

## 已确认漏洞摘要

| ID | 严重程度 | 文件 | 简述 |
|----|----------|------|------|
{{FINDINGS_TABLE}}

## 未覆盖高风险目标

> 以下文件尚未被任何 scanner 审计，按风险评分排序。
> 用户可指定补扫：`AUDIT_TARGETS=file1,file2 bash scripts/run_audit_cycle.sh ...`

| # | 文件 | 风险评分 | Stratum | 原因 |
|---|------|----------|---------|------|
{{UNCOVERED_TABLE}}

## 建议下一步

{{RECOMMENDATIONS}}

### 用户可选操作

1. **继续审计未覆盖目标**
   ```bash
   AUDIT_TARGETS=target1,target2,target3 bash scripts/run_audit_cycle.sh
   ```

2. **停止审计并生成最终报告**
   ```bash
   bash scripts/harden_delivery.sh "$AUDIT_DIR"
   ```

3. **调整审计方向**
   - 修改 `audit_target_shards.json` 中的优先级
   - 重新运行审计周期
