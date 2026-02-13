# Code Security Audit Skills 项目完整介绍

## 1. 项目定位
`code-security-audit-skills` 是一套面向 Web 应用代码审计的可编排技能体系。它不是单点“规则扫描器”，而是一个分阶段、带门禁、带产物契约、可复核的审计流程系统。

目标是把“代码安全审计”从一次性 prompt，升级为可重复执行的工程化流程。

---

## 2. 要解决的问题
常见 AI skills 在安全审计中通常存在以下问题：
- 只有扫描，没有收敛与复核，误报与漏报难以管理
- 缺少阶段门禁，流程可随意跳步，结果不稳定
- 产物无统一契约，不便团队协作与二次自动化
- 报告不面向复现，难以直接给开发/安全/攻防团队落地

本项目通过 Phase 1-4 + 门禁 + 产物契约 + 角色分工解决上述问题。

---

## 3. 核心创新点

### 3.1 四阶段硬门禁流程
- Phase 1: 建图与 triage
- Phase 2: 候选风险并行扫描 + 主控复核
- Phase 2.5: 覆盖率与收敛硬门禁
- Phase 3: 深度验证与证据固化
- Phase 4: 中文复现导向报告

关键门禁不是建议，而是 hard gate（如 D1/D2/D3/D11/D12 + E1/E2/E4/E5/E6）。

### 3.2 产物契约（Artifact Contract）
统一 `audit/` 目录作为流程状态与交接总线，确保不同 runtime 与不同 agent 的输入输出一致。

### 3.3 候选与验证分离
Phase 2 扫描器只做候选发现（ALERT/STATS），最终严重性由主控和 Phase 3 统一裁决，降低“扫描器即裁判”的偏差。

### 3.4 攻击链优先验证
Phase 2 先产出 `attack-chains-draft.md`，Phase 3 按链路优先级深挖，避免只做孤立漏洞清单。

### 3.5 中文复现导向报告
输出模板强制面向复现，包含 AC-001 攻击链章节，并禁止“同类省略”占位式输出。

---

## 4. 整体架构

## 4.1 目录架构
- `skills/code-security-audit/`：核心方法学（playbooks/rules/templates）
- `droids/droids/`：各子角色能力定义
- `unified-skills/`：三套运行时资料汇总（`droid/`、`codex/`、`opencode/`）

## 4.2 逻辑分层
1. 方法学层：Q1-Q7、D1-D12、全局约束与产物模板  
2. 编排层：Phase 顺序、任务分发、门禁检查、R2 回补机制  
3. 执行层：scanners/validators/security-analyst 等角色协作  
4. 报告层：复现导向报告、攻击链与修复优先级输出

---

## 5. 核心流程思路

### 5.1 Phase 1（Recon）
- 建立 `map.json`（入口、sinks、models、configs）
- 输出 triage/hypotheses/read-log/business-model
- 不满足基础覆盖不进入 Phase 2

### 5.2 Phase 2（Candidate Scan）
- scanner 并行跑候选风险
- 主控做语义复核，合并到 `risk-map.md`
- 实时维护 `prereq-candidates.md`
- 生成 `attack-chains-draft.md`（`security-analyst` draft 模式）

### 5.3 Phase 2.5（Coverage & Convergence）
- 覆盖检查（D/E）
- 收敛检查（Q1/Q2/Q3）
- 不通过触发 R2，仅补扫缺口范围

### 5.4 Phase 3（Deep Verify）
- dataflow/access/logic/validator/poc 等深度验证
- `security-analyst` final 模式做最终收敛与去重
- 形成 `findings-consolidated.md`

### 5.5 Phase 4（Report）
- 产出中文复现报告 `report.md`
- Critical/High 必须 PoC

---

## 6. 与常见市面 Skills 的区别
以下“市面”指常见通用 AI skills 设计范式（单阶段、单代理、单输出）：

1. 过程可治理性更强  
常见方案：一轮扫描后直接给结论。  
本项目：强制 Phase + hard gate + R2 回补。

2. 输入输出更工程化  
常见方案：结果散落在对话中。  
本项目：`audit/` 产物契约固定、可追踪、可二次自动化。

3. 角色职责更清晰  
常见方案：一个 agent 全包，容易上下文污染。  
本项目：scanner（候选）与 validator/analyst（验证与收敛）解耦。

4. 报告可执行性更高  
常见方案：偏解释性总结。  
本项目：默认中文复现导向，要求攻击链和可复现实操信息。

5. 跨 runtime 一致性  
常见方案：换平台要重写。  
本项目：方法学不变，编排适配 `codex/opencode`，并在 `unified-skills/` 汇总。

---

## 7. 三套 Skills 汇总说明
仓库已提供统一汇总目录：
- `unified-skills/droid/`
- `unified-skills/codex/`
- `unified-skills/opencode/`
- `unified-skills/shared/`
- `unified-skills/templates/`

这套目录可直接作为跨运行时交付包使用。

---

## 8. 安装与接入方法

## 8.1 Codex（项目级）
将 skill 放到项目目录：
- `./.codex/skills/code-security-audit/`

推荐触发语句：
- `Use skill code-security-audit to run the full workflow (Phase 1->2->2.5->3->4) ...`

说明：如果运行时未注册自定义 skill，只放文件不会自动出现在可用 skills 列表，需要平台侧注册/加载。

## 8.2 OpenCode
放置到：
- `.opencode/skills/code-security-audit/`

使用：
- 读取 `opencode/SYSTEM-PROMPT.md`
- 按 `opencode/RUNBOOK.md` 与 `opencode/TASKS.md` 执行
- 门禁以 `shared/phase-gates.md` 为准

## 8.3 Droid/Prompt 直连模式
直接使用 `droids/` 或 `unified-skills/droid/` 中角色定义，按 Phase 顺序手工编排。

---

## 9. 运行要求与建议
- 代码库可读权限
- 能写 `audit/` 目录
- 可用文本检索能力（如 `rg`）
- 建议具备 AST/LSP 能力用于深挖阶段精确追链（可选增强）

---

## 10. 输出清单（按阶段）

### Phase 1
- `map.json`
- `triage.md`
- `hypotheses.md`
- `read-log.md`
- `business-model.md`

### Phase 2
- `public-endpoint-review.md`
- `risk-map.md`
- `prereq-candidates.md`
- `attack-chains-draft.md`

### Phase 3
- `dataflow.md`
- `findings.md`
- `pocs.md`（或内联）
- `findings-consolidated.md`

### Phase 4
- `report.md`

---

## 11. 适用场景与边界

适用：
- Web 应用安全审计
- 代码仓库级风险评估
- 漏洞复现与修复优先级梳理

边界：
- 不替代动态渗透测试环境搭建
- 不替代人工业务访谈与合规审计
- 对运行时“技能注册能力”有平台依赖

---

## 12. 未来演进方向
- 增加更多 runtime 适配（统一接口层）
- 更细粒度的领域策略包（按语言/框架）
- 与 CI/CD 集成的增量审计模式（PR / diff 审计）
- 自动生成修复补丁建议与回归测试建议

---

## 13. 快速结论
这个项目的核心价值不是“再做一个扫描器”，而是把 AI 安全审计流程产品化：  
可执行、可验证、可复核、可交付、可复现。
