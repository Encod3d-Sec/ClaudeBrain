---
title: "Static Code Analysis"
type: technique
tags: [binary, git-poc, sast]
phase: recon
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [git-raptor]
---

# Static Code Analysis

## What it is

Static code analysis finds vulnerabilities by examining source code (or bytecode) without executing it. It complements fuzzing and manual review — it scales to large codebases and finds injection paths, dataflow issues, and logic bugs that dynamic testing may miss.

## Two Primary Tools

| | [[semgrep|Semgrep]] | [[codeql|CodeQL]] |
|--|------------|-----------|
| Approach | Pattern-matching (AST-aware) | Full dataflow + semantic |
| Speed | Very fast (seconds) | Slower (minutes to hours) |
| False positive rate | Higher (context-unaware) | Lower (dataflow validated) |
| Languages | 30+ | Java, Python, JS, C/C++, Go, Ruby, C#, Swift |
| Offline | Yes (cache registry packs) | Requires DB build |
| Best for | Quick scan; custom pattern hunting | Deep source-to-sink analysis |

---

## Semgrep

### Installation & scan
```bash
pip install semgrep

# Scan with auto-detected rules
semgrep --config=auto ./src

# Target-specific packs
semgrep --config=p/ci ./src
semgrep --config=p/owasp-top-ten ./src
semgrep --config=p/python ./src

# Custom rule file
semgrep --config=my_rules.yaml ./src

# Offline (cache packs locally first)
semgrep --config=p/python --save-test-output-tar=cache.tgz
semgrep --config=cache.tgz ./src
```

### Custom rule structure
```yaml
rules:
  - id: sql-injection-f-string
    patterns:
      - pattern: |
          cursor.execute(f"... {$INPUT} ...")
      - pattern-not: |
          cursor.execute($QUERY, ($INPUT,))
    message: "Possible SQL injection via f-string"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-89
```

### Taint mode (dataflow-lite)
```yaml
rules:
  - id: taint-request-to-shell
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sinks:
      - pattern: os.system(...)
      - pattern: subprocess.run(..., shell=True)
    message: "User input reaches shell execution"
    languages: [python]
    severity: ERROR
```

---

## CodeQL

### Database build
```bash
# Auto-detect language and build system
codeql database create ./codeql-db --language=python --source-root=./src

# Explicit build command (for compiled languages)
codeql database create ./codeql-db --language=cpp \
  --command="make -j4" --source-root=./src

# Multiple languages
codeql database create ./codeql-db --language=java,kotlin \
  --build-mode=autobuild --source-root=./src
```

### Run queries
```bash
# Run built-in query pack
codeql database analyze ./codeql-db \
  codeql/python-queries:Security/CWE-089 \
  --format=sarif-latest --output=results.sarif

# Run all security queries
codeql database analyze ./codeql-db \
  codeql/python-queries \
  --format=sarif-latest --output=results.sarif

# Custom query file
codeql database analyze ./codeql-db my_query.ql \
  --format=sarif-latest --output=results.sarif

# View results
cat results.sarif | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['runs'][0]['results']:
    loc = r['locations'][0]['physicalLocation']
    print(loc['artifactLocation']['uri'], ':', loc['region']['startLine'], '-', r['message']['text'][:80])
"
```

### CodeQL query (source-to-sink dataflow)
```ql
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjection" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof Call and
    source.asExpr().(Call).getFunc().toString() = "get"
    // request.get(), request.args.get() etc.
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call c |
      c.getFunc().toString() = "execute" and
      sink.asExpr() = c.getArg(0)
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@", source.getNode(), "user input"
```

---

## Vulnerability Validation Pipeline (7 Stages)

After static tools generate findings, validate them through this pipeline before investing in exploit development. Validates that findings are real, reachable, and exploitable.

```
Stage 0 → A → B → C → D → E → F → Report
```

### Stage 0: Inventory (automated)
Build a complete function/method checklist for the target. Establishes coverage tracking.

### Stage A: One-Shot Discovery
Read all source files and assess each function for vulnerabilities. If binary available, run it to gather PoC evidence. **Output:** findings array with `origin` and initial summary.

**ASSUME-EXPLOIT:** Treat everything as exploitable until proven otherwise.

### Stage B: Attack Tree + Systematic Analysis
For each finding, form *value-level predictions* (e.g., "if I send `'; DROP TABLE--`, column count will mismatch and produce error X"). Test them. Track:
- `hypotheses.json` — predictions with expected vs. actual
- `disproven.json` — what was tried and why it failed
- `PROXIMITY` score (0–10) — how close to exploitation

**Why this matters:** Forces evidence-backed analysis. Even "obvious" false positives sometimes turn exploitable once you trace the full path.

### Stage C: Sanity Check
Open each file and verify code verbatim. Confirm:
- Source-to-sink dataflow exists in actual code (not LLM hallucination)
- Code path is reachable (not dead code, not test-only)
- Sanitizer isn't applied somewhere missed in stage B

### Stage D: Ruling
Synthesize evidence from A/B/C. Apply disqualifier checks:
- **D-0**: Is this test/mock code only?
- **D-1**: Is the source truly attacker-controlled?
- **D-2**: Are preconditions realistic (requires auth, specific state)?
- **D-3**: Is there a sanitizer that's actually effective?
- **D-4**: Is the sink truly dangerous in this context?

Assign CVSS vector. Output final verdict per finding.

### Stage E: Binary Feasibility (memory corruption only)
Run constraint analysis on the compiled binary:
```bash
libexec/raptor-run-feasibility ./binary findings.json output/
```

| Feasibility verdict | Final status |
|--------------------|-------------|
| Likely / Likely exploitable | `exploitable` |
| Difficult | `confirmed_constrained` |
| Unlikely | `confirmed_blocked` |
| Not applicable | `confirmed` |
| Binary not found | `confirmed_unverified` |

Skip if no memory corruption findings or no binary available.

### Stage F: Self-Review
Review all findings as if you're a skeptical peer reviewer. Ask: "What did I get wrong?" Catch misclassifications, weak evidence, inconsistent CVSS, missed instances.

### MUST-GATEs (apply throughout)

| Gate | Rule |
|------|------|
| **ASSUME-EXPLOIT** | Investigate as exploitable until proven otherwise |
| **FULL-COVERAGE** | Check ALL code, no sampling |
| **POC-EVIDENCE** | PoC must produce observable output, not just "ran without error" |
| **NO-HEDGING** | Verify all "if/maybe/uncertain" claims before stating them |
| **PROOF** | Show vulnerable code for every finding |

---

## Attack Surface Mapping

Before scanning, map the attack surface to prioritize findings:

```
Entry points    → trust boundaries → sinks
(HTTP params)     (auth middleware)   (DB queries, shell, files)
```

**Attacker-controlled sources (high confidence):**
- HTTP request parameters (GET, POST, headers, cookies)
- User input (form fields, file uploads, URL path segments)
- External API responses (treat as untrusted)

**Conditional sources (requires some access):**
- Config files (need server access)
- Environment variables (need shell access)
- Database content (need SQL access or indirect injection)

**Internal only (false positive if flagged as source):**
- Hardcoded constants
- Framework-generated values
- Trusted internal services

---

## Sanitizer Effectiveness Analysis

For each sanitizer in a dataflow path, assess:

1. **Does it match the vuln type?**
   - SQLi needs parameterized queries OR proper SQL escaping
   - XSS needs HTML entity encoding (context-aware: HTML/JS/CSS/URL)
   - CMDi needs argument list (no `shell=True`) OR strict allowlist
   - Path traversal needs canonicalization + whitelist

2. **Can it be bypassed?**
   - Incomplete (only filters some chars) — look for missing chars
   - Encoding bypass (URL encode, double encode, Unicode normalize)
   - Case sensitivity (blacklist checks lowercase only)
   - Logic error (sanitizes var A, uses var B)
   - Order of operations (validate → sanitize → use ORIGINAL)

3. **Applied to all paths?**
   - Check branches (if/else gaps)
   - Error handling paths (exception thrown before sanitize)
   - Alternative routes to same sink

---

## Verdict System

| Verdict | Criteria |
|---------|----------|
| **EXPLOITABLE** | Source is attacker-controlled; sanitizer absent or bypassable; code path reachable in production; significant impact |
| **FALSE POSITIVE** | Source is internal only; effective sanitizer verified; dead code; framework protection present |
| **NEEDS TESTING** | Source requires some access; sanitizer unclear; reachability conditional; impact depends on data |

**Confidence levels:**
- **High** — Direct exploitation, simple payload, confirmed dataflow
- **Medium** — Requires bypass technique or specific conditions
- **Low** — Complex chain or uncertain reachability

---

## SARIF Output Processing

Most scanners output SARIF. Quick processing:
```bash
# Count findings by severity
cat results.sarif | python3 -c "
import json, sys
d = json.load(sys.stdin)
from collections import Counter
levels = [r.get('level','note') for r in d['runs'][0]['results']]
print(Counter(levels))
"

# Extract unique rules triggered
cat results.sarif | python3 -c "
import json, sys
d = json.load(sys.stdin)
rules = {r['ruleId'] for r in d['runs'][0]['results']}
print('\n'.join(sorted(rules)))
"
```
