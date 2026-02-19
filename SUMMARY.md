# Code Security Audit Skills Summary

## 内容概览
- **Skill (V6)**: `skills/code-security-audit-v6/`
- **Skill (Legacy)**: `skills/code-security-audit/`
- **Droids**: `droids/`（access/injection/infra 等扫描器及 Phase 3 子代理）

## 核心能力
- V6 三阶段审计流程（RECON → AUDIT → HARDEN）：机器枚举 + 语义侦察 → 并行扫描 + Master 验证 → Judge 裁决 + 交付
- Q1–Q7 通用安全问题驱动的语义审计
- AUDIT 触发器分级（ALERT + STATS），severity 判定回归 master
- HARDEN 输出为**全中文渗透复现报告**，Critical/High 必含 PoC

## 关键变更点（本次打包版本）
1. **新增 V6 版本**：独立目录 `skills/code-security-audit-v6/`，保留旧版不覆盖
2. **三阶段架构**：RECON → AUDIT → HARDEN，机器化产物 + Master 验证 + Judge 裁决
3. **强制门禁**：G0/G1 gate + findings/verification/verdict/coverage/report 交付契约
4. **Scanner 输出两级化**：ALERT + STATS，预算控制与采样建议
5. **报告模板更新**：默认中文复现导向，Critical/High PoC 强制

## 使用方式（简要）
1. 将 `skills/` 与 `droids/` 放入对应 Factory 目录
2. 调用 `code-security-audit` skill 执行审计流程
3. 输出在 `audit/` 目录下
