# Repository Security Overview

- Project root: {{PROJECT_ROOT}}
- API root: {{API_ROOT}}
- Generated at: {{GENERATED_AT}}

## Recon Summary

- inventory_total: {{INVENTORY_TOTAL}}
- signals_total: {{SIGNALS_TOTAL}}
- p0_targets_total: {{P0_TOTAL}}
- shards_total: {{SHARDS_TOTAL}}

## Critical Surface Snapshot

- auth-related: {{AUTH_COUNT}}
- admin-related: {{ADMIN_COUNT}}
- finance-related: {{FINANCE_COUNT}}
- webhook-related: {{WEBHOOK_COUNT}}

## 信任边界 (Trust Boundaries)

| 边界 | 入口 | 认证 | 描述 |
|------|------|------|------|
| {{BOUNDARY_1}} | {{ENTRY_1}} | {{AUTH_1}} | {{DESC_1}} |
| {{BOUNDARY_2}} | {{ENTRY_2}} | {{AUTH_2}} | {{DESC_2}} |
| {{BOUNDARY_3}} | {{ENTRY_3}} | {{AUTH_3}} | {{DESC_3}} |

## 敏感数据流 (Sensitive Data Flows)

| 数据类型 | 入口 | 处理 | 存储 | 风险等级 |
|---------|------|------|------|---------|
| {{DATA_TYPE_1}} | {{SOURCE_1}} | {{PROCESS_1}} | {{STORAGE_1}} | {{RISK_1}} |
| {{DATA_TYPE_2}} | {{SOURCE_2}} | {{PROCESS_2}} | {{STORAGE_2}} | {{RISK_2}} |
| {{DATA_TYPE_3}} | {{SOURCE_3}} | {{PROCESS_3}} | {{STORAGE_3}} | {{RISK_3}} |

## 关键模块关系 (Critical Module Relationships)

- {{MODULE_A}} → {{MODULE_B}}：{{RELATIONSHIP_1}}
- {{MODULE_C}} → {{MODULE_D}}：{{RELATIONSHIP_2}}
- {{MODULE_E}} → {{MODULE_F}}：{{RELATIONSHIP_3}}

## Audit Guidance

1. 优先处理 P0 shard（auth/admin/finance）。
2. 对 `must_investigate` 条目必须给出明确调查结论。
3. 进入 HARDEN 前确保 findings.md 包含：
   - `## 已检查无问题`
   - `## P0 语义证据覆盖（LSP）`
4. 阅读 repo_overview.md 建立全局认知后再开始 chain-synthesizer 合成。
