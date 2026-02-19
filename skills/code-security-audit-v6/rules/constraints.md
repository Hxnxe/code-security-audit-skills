# Agent Constraint Rules

## Rule 1: 只报告你实际读到的代码
- 不猜测文件路径或代码实现。
- 结论必须可追溯到 `file:line`。

## Rule 2: Every finding must have code evidence
- 每个发现至少引用一个 `file:line`。
- 注入类漏洞（D1）应尽量提供 source -> sink 数据流。
- 配置/逻辑类漏洞（D2/D3/D7/D8/D9/D11/D13）可直接以代码位置作为主要证据。

## Rule 3: AUDIT 输出 findings.md
- AUDIT 阶段输出 `findings.md`（半结构化 markdown）。
- `findings.jsonl` 由 `scripts/extract_findings.py` 后置生成。
