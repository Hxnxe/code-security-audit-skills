# Output File Templates

All audit outputs are saved to the `audit/` directory under the project root.

## 1. map.json (Phase 1)

```json
{
  "tech_stack": {
    "language": "Python 3.11",
    "framework": "Flask 2.3",
    "orm": "SQLAlchemy",
    "auth": "Flask-Login + JWT",
    "middleware": ["CORS", "rate-limit"],
    "template_engine": "Jinja2"
  },
  "modules": [
    {"name": "user_management", "path": "app/users/", "description": "Registration, login, profile"},
    {"name": "file_service", "path": "app/files/", "description": "Upload, download, share"},
    {"name": "admin_panel", "path": "app/admin/", "description": "System configuration, user management"}
  ],
  "entries": [
    {
      "route": "/api/users/login",
      "method": "POST",
      "handler": "app/users/views.py:login",
      "line": 42,
      "auth_required": false,
      "parameters": ["username", "password"],
      "module": "user_management"
    }
  ],
  "sinks": [
    {
      "file": "app/db/queries.py",
      "line": 23,
      "type": "sql_injection",
      "function": "cursor.execute",
      "danger_level": "critical",
      "module": "user_management"
    }
  ],
  "configs": [
    {
      "file": "config.py",
      "line": 15,
      "category": "hardcoded_secret",
      "finding": "SECRET_KEY hardcoded",
      "severity": "high"
    }
  ],
  "models": [
    {
      "name": "Document",
      "file": "app/models/document.py",
      "ownership_field": "owner_id",
      "ownership_type": "user-owned",
      "relationships": [
        {"field": "owner", "target": "User", "type": "ForeignKey"}
      ]
    }
  ]
}
```

## 2. risk-map.md (Phase 2)

```markdown
# Risk Map

## P0 - Critical Priority

### 1. SQL Injection in User Search
- **File**: `app/users/views.py:67`
- **Sink Type**: sql_injection
- **Suspected Dataflow**: `request.args['q']` → `f"SELECT * FROM users WHERE name='{q}'"`
- **Scanner**: injection-scanner
- **Module**: user_management

### 2. Command Injection in File Processing
- **File**: `app/files/utils.py:34`
- **Sink Type**: command_injection
- **Suspected Dataflow**: `request.form['filename']` → `os.system('convert ' + filename)`
- **Scanner**: injection-scanner
- **Module**: file_service

## P1 - High Priority

### 3. Missing Auth on Admin Export
- **File**: `app/admin/views.py:112`
- **Issue**: No @admin_required decorator
- **Scanner**: auth-scanner
- **Module**: admin_panel
```

## 3. dataflow.md (Phase 3)

```markdown
# Dataflow Analysis

## Trace 1: SQL Injection in User Search

### Source
- **Entry**: `GET /api/users/search`
- **Parameter**: `request.args.get('q')`
- **File**: `app/users/views.py:60`

### Flow
1. `views.py:60` — `q = request.args.get('q')` (user input captured)
2. `views.py:63` — `results = user_service.search(q)` (passed to service)
3. `services/user.py:28` — `def search(query): return db.search_users(query)` (no sanitization)
4. `db/queries.py:15` — `cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")` (SINK)

### Sanitization Barriers
- None found between source and sink.

### Four-Step Verification
1. **Dataflow Completeness**: ✅ Complete path, no sanitization
2. **Protection Bypassability**: ✅ No protection to bypass
3. **Precondition Satisfiability**: ✅ Endpoint requires no authentication
4. **Impact Scope**: Full database read access via UNION injection

### Verdict: CONFIRMED
```

## 4. findings.md (Phase 3)

Each finding follows this exact template:

```markdown
# Audit Findings

## [SQL Injection] User Search Endpoint
- **File**: `app/db/queries.py:15`
- **Entry**: `request.args.get('q')` via `GET /api/users/search`
- **Sink**: `cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")`
- **Dataflow**: `q` → `user_service.search(q)` → `db.search_users(query)` → `cursor.execute(f"...")`
- **Verification**: No sanitization. String directly interpolated into SQL. Accepts `' UNION SELECT...`
- **Severity**: Critical
- **Preconditions**: None (unauthenticated endpoint)
- **Impact**: Full database read, potential write via stacked queries
- **PoC**:
  ```bash
  curl "http://target/api/users/search?q=' UNION SELECT null,version(),null--"
  ```
- **Remediation**: Use parameterized query: `cursor.execute("SELECT * FROM users WHERE name LIKE %s", (f"%{query}%",))`

## [Missing Authentication] Admin Export Endpoint
- **File**: `app/admin/views.py:112`
- **Entry**: `GET /api/admin/export`
- **Sink**: N/A (data exposure)
- **Dataflow**: Direct access to admin function without auth check
- **Verification**: No @admin_required or @login_required decorator. Compared with sibling endpoints that all have auth.
- **Severity**: High
- **Preconditions**: None (unauthenticated)
- **Impact**: Unauthorized access to admin data export
- **Remediation**: Add `@admin_required` decorator
```

## Structured Finding Template (Required)

```
## [Type] SQL Injection
- File: `path/to/file:line`
- Entry: `source`
- Sink: `sink`
- Dataflow: `source` → `transform` → `sink`
- Verification: <evidence>
- Severity: Critical
```

## 5. report.md (Phase 4)

**默认规范（强制）：**
- 报告语言：**全中文**
- 报告目标：**渗透复现导向**（可直接指导复现）
- PoC 覆盖范围：**仅 Critical / High**

```markdown
# 安全审计复现报告

## 项目概览
- **项目**: [name]
- **技术栈**: [lang/framework]
- **审计日期**: [date]
- **审计方式**: AI-assisted (code-security-audit)

## 复现总览（Critical/High）

| 编号 | 等级 | 漏洞类型 | 复现路径 | 认证要求 | PoC |
|------|------|----------|----------|----------|-----|
| C-01 | Critical | JWT 伪造 | /api/... | 无 | 是 |

## 关键漏洞复现指南

### C-01 [漏洞标题]
- **影响**: [中文描述]
- **前置条件**: [是否需要登录/权限]
- **复现步骤**:
  1. ...
  2. ...
  3. ...
- **PoC**:
  ```bash
  curl "{{BASE_URL}}/..."
  ```
- **预期结果**:
  - 漏洞态: ...
  - 修复态: ...

## 攻击链复现（按杀伤力排序）

### AC-001 [攻击链名称]
- **起点**: 未认证 / 已认证低权限
- **终点**: 管理员接管 / 资金盗取 / 数据泄露 / RCE
- **杀伤力**: Critical / High

| 步骤 | 漏洞编号 | 操作 | 获得能力 |
|------|---------|------|---------|
| 1 | BLOG-001 | `curl GET {{BASE_URL}}/api/...` | 获取管理员邮箱 |
| 2 | CRIT-002 | `curl GET {{BASE_URL}}/api/...` | 重置管理员密码 |
| 3 | - | `curl POST {{BASE_URL}}/api/auth/login ...` | 获取管理员会话 |

- **断点修复**: 修复 [漏洞编号] 即可阻断整条链路

## 修复优先级（按攻击链断点）
1. ...

## 占位符说明
- `{{BASE_URL}}`：目标 API 根路径
- `{{ACCESS_TOKEN}}`：普通用户 Token
- `{{ADMIN_TOKEN}}`：管理员 Token
```

**Output integrity rule (MANDATORY):**
- If the report claims `N` findings, it MUST list all `N` findings explicitly.
- Forbidden placeholders:
  - `[Additional findings documented with similar structure]`
  - `...等 X 条中危漏洞`
  - any "similar/as above" wording replacing concrete finding content
