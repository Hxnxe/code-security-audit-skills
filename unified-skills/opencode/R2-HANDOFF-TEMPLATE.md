# R2 Handoff Template (OpenCode)

Use this exact structure when Phase 2.5 triggers R2.

```markdown
## R2 Handoff

### Covered Dimensions
- D1: <evidence>
- D2: <evidence>

### Uncovered Dimensions
- D3: <gap>
- D9: <gap>

### Analyzed Files
- path/to/fileA
- path/to/fileB

### CLEAN Surfaces
- surface: <attack surface>
  reason: <why clean>
  evidence_ref: <read-log or risk-map reference>

### R2 Scope Plan
- scanner(s): <which tasks to run>
- target gaps: <specific missing checks>
- prohibited repeats: no re-read of analyzed files, no re-scan of CLEAN surfaces
```
