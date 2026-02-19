# RECON 回退（V6）：脚本失败时的手动兜底

当 `phase0_recon_v6.sh` 执行失败，或 `gate.py g0` 失败且需要人工补充时，
你**必须**按以下步骤手动建立审计靶标，**不得跳过直接进入 AUDIT**。

## 步骤 0：补齐核心产物（仅在缺失时）

如果以下任一文件缺失：`inventory.jsonl`、`attack-surface.jsonl`、`must_investigate.jsonl`，
先补跑一次轻量 RECON：

```bash
python3 <skill_root>/scripts/recon_lite.py <api_root> --audit-dir <audit_dir> --project-root <project_root>
python3 <skill_root>/scripts/validate_schema.py <audit_dir>/inventory.jsonl inventory
python3 <skill_root>/scripts/validate_schema.py <audit_dir>/attack-surface.jsonl attack-surface
```

若核心产物已存在，跳过本步骤，直接进入步骤 1。

## 步骤 1：枚举所有公开端点

```bash
rg "requiresAuth\s*:\s*false|@PermitAll|permitAll\s*\(" --include="*.ts" --include="*.js" --include="*.java" -l <api_root>
```

将结果记录为 P0 靶标，标注原因 "requiresAuth:false"。

## 步骤 2：枚举 SQL 注入候选

```bash
rg "Sequelize\.literal|\.query\(|\.raw\(|\.execute\(|JdbcTemplate|createNativeQuery|EntityManager\.createQuery" --include="*.ts" --include="*.js" --include="*.java" -l <api_root>
```

将结果记录为 P0 靶标，标注原因 "SQL sink"。

## 步骤 3：枚举默认凭据候选

```bash
ls <project_root>/seeders/ <project_root>/migrations/
rg "hashPassword|bcrypt\.hash|argon2|defaultPassword|\"12345|@Bean|spring\.security|inMemoryAuthentication" --include="*.js" --include="*.ts" --include="*.sql" --include="*.java" -l <project_root>
```

将结果记录为 P0 靶标，标注原因 "default credentials surface"。

## 步骤 4：枚举 GET + 敏感参数

```bash
rg "password|secret|token|apiKey|private.?key" --include="*.ts" --include="*.js" --include="*.java" -l <api_root>
```

交叉对比步骤 1 结果，同时出现在两个列表中的文件标注为 P0，原因 "public GET + sensitive param"。

## 步骤 5：枚举语义矛盾

```bash
rg "permission\s*:|@PreAuthorize|@Secured|@RolesAllowed" --include="*.ts" --include="*.js" --include="*.java" -l <api_root>
```

交叉对比步骤 1 结果，同时出现的文件标注为 P0，原因 "semantic contradiction: permission declared but requiresAuth:false"。

## 步骤 6：写入 audit/audit_targets.md

将上述结果去重后写入 `audit/audit_targets.md`，格式（必须包含 `stratum` 列）：

| # | 文件 | 原因 | stratum |
|---|------|------|---------|
| 1 | path/to/file.ts | requiresAuth:false + SQL sink | S1 |
| ... | ... | ... | S2/S4/... |

推荐映射：
- 公开写操作: `S1`
- 公开敏感读: `S2`
- 公开只读: `S3`
- 鉴权声明缺失/语义矛盾: `S4`
- 其他关键模块: `S5`

**此步骤完成前，不得进入 AUDIT 阶段。**

## 步骤 7：重建分片与委派清单（必须）

```bash
python3 - <<'PY' <audit_dir>/audit_targets.md <audit_dir>/audit_target_shards.json 15
import json
import re
import sys
from pathlib import Path
from collections import defaultdict

targets_md = Path(sys.argv[1])
shards_json = Path(sys.argv[2])
max_files = max(1, int(sys.argv[3]))
if not targets_md.exists():
    raise SystemExit(f"missing audit_targets.md: {targets_md}")

rows = []
priority = None
for raw in targets_md.read_text(encoding="utf-8", errors="ignore").splitlines():
    line = raw.strip()
    if line.startswith("## P0"):
        priority = "P0"
        continue
    if line.startswith("## P1"):
        priority = "P1"
        continue
    if line.startswith("## "):
        priority = None
    if priority is None:
        continue
    if not line.startswith("|") or line.startswith("|---") or line.startswith("| #"):
        continue
    cols = [c.strip() for c in line.strip("|").split("|")]
    if len(cols) < 4:
        continue
    file_path, reason, stratum = cols[1], cols[2], cols[3]
    if not file_path or file_path in {"文件", "-"}:
        continue
    rows.append(
        {
            "priority": priority,
            "file": file_path,
            "reason": reason or "-",
            "stratum": stratum or "-",
        }
    )

groups = defaultdict(list)
for row in rows:
    module = row["file"].split("/", 1)[0] if "/" in row["file"] else "root"
    groups[(row["priority"], module)].append(row)

def gkey(k):
    p, m = k
    return (0 if p == "P0" else 1, m)

shards = []
seq = 1
for key in sorted(groups.keys(), key=gkey):
    p, module = key
    items = sorted(groups[key], key=lambda r: r["file"])
    for i in range(0, len(items), max_files):
        chunk = items[i:i+max_files]
        targets = []
        for it in chunk:
            targets.append(
                {
                    "file": it["file"],
                    "reason": it["reason"],
                    "stratum": it["stratum"],
                    "estimated_lines": 120,
                }
            )
        shards.append(
            {
                "shard_id": f"S{seq:03d}",
                "priority": p,
                "module": module,
                "target_count": len(targets),
                "estimated_lines_total": len(targets) * 120,
                "estimated_tokens_total": len(targets) * 1800,
                "targets": targets,
            }
        )
        seq += 1

payload = {
    "schema_version": 1,
    "max_files_per_shard": max_files,
    "total_targets": len(rows),
    "shards_total": len(shards),
    "shards": shards,
}
shards_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"shards generated: {shards_json} ({len(shards)} shards, {len(rows)} targets)")
PY
python3 <skill_root>/scripts/build_droid_dispatch.py --audit-dir <audit_dir> --project-root <project_root> --audit-dir-ref <audit_dir>
python3 <skill_root>/scripts/gate.py g0 <audit_dir> --mode strict
```

未完成上述命令，禁止进入 AUDIT。
