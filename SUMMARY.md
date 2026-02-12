# Code Security Audit Skills Summary

## 内容概览
- **Skill**: `skills/code-security-audit/`
- **Droids**: `droids/`（access/injection/infra 等扫描器及 Phase 3 子代理）

## 核心能力
- 四阶段审计流程（Phase 1–4）：建图 → 并行扫描 → 收敛检查 → 深度验证 → 复现报告
- Q1–Q7 通用安全问题驱动的语义审计
- Phase 1.8 业务心智模型（行为签名 + 敏感数据清单）
- Phase 2 触发器分级（ALERT + STATS），severity 判定回归 master
- Phase 4 输出为**全中文渗透复现报告**，Critical/High 必含 PoC

## 关键变更点（本次打包版本）
1. **Phase 1.8 业务心智模型**：新增 business-model.md 输出
2. **F 类扫描扩展**：F1/F2/F3 覆盖敏感字段、间接数据出口、include 深度
3. **Scanner 输出两级化**：ALERT + STATS，预算控制与采样建议
4. **Step 0.5 复核队列**：基于 business-model.md 做 Q3/Q7 语义复核
5. **报告模板更新**：默认中文复现导向，Critical/High PoC 强制

## 使用方式（简要）
1. 将 `skills/` 与 `droids/` 放入对应 Factory 目录
2. 调用 `code-security-audit` skill 执行审计流程
3. 输出在 `audit/` 目录下
