# Agent Constraint Rules

## Rule 1: Only report code you have READ
- Never guess file paths or code content.
- All citations must come from Read outputs.

## Rule 2: Every finding must have dataflow evidence
- Entry → Intermediate processing → Sink.
- A single dangerous call without source trace is not a valid finding.

## Rule 3: Structured output only
- All vulnerabilities must follow the fixed template.
