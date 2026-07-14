---
title: "Source Audit Checklist (Finding the Bug)"
type: technique
tags: [methodology, cve-research, code-audit, sast, taint, source-review]
phase: exploitation
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

## What it is

A systematic checklist for auditing application source to find vulnerabilities: map where untrusted input enters (**sources**), find the dangerous operations it can reach (**sinks**), and confirm a real source-to-sink path. The web/logic counterpart to [[memory-safety-bugs]]; the source-repo path of the `research` skill.

## How it works

Almost every app bug is **tainted input reaching a sink without proper validation/encoding**. You audit by enumerating sinks (fast, with grep/[[semgrep]]) and proving the dataflow from a source ([[codeql]] taint, or by hand). One found bug -> grep the pattern for siblings (variant analysis).

## Attack phases
Exploitation / research (source-available web apps, libraries, services).

## Prerequisites
- The source. Identify language + framework + entry points first; scan deps for known CVEs with [[trivy]].

## Methodology

### 1. Recon the codebase
Language/framework, routes/handlers (entry points), auth + session model, ORM/DB layer, templating, file handling, and dependencies. `trivy fs .` for known-vuln deps; map the routing table to find every reachable handler.

### 2. Find sinks by vuln class (grep -> semgrep -> codeql)
| Class | Dangerous sinks (any language) | First grep |
|---|---|---|
| **Command injection** | `system exec popen shell_exec subprocess(...,shell=True) child_process.exec Runtime.exec os/exec` | `grep -rnE 'exec\|system\|popen\|shell_exec\|ProcessBuilder'` |
| **SQL injection** | string-built queries, `.raw(` , `query("..."+x)` , f-strings in SQL | `grep -rnE 'SELECT .*\+\|execute\(.*%\|f"SELECT'` |
| **Path traversal / file** | `open fopen readFile sendFile include require File(` with input in path | `grep -rnE 'open\(\|readFile\|sendFile\|include\('` |
| **Deserialization** | `pickle.loads yaml.load unserialize ObjectInputStream Marshal.load node-serialize` | `grep -rnE 'unserialize\|pickle.loads\|readObject\|yaml.load\b'` |
| **SSRF** | server-side `http.get curl requests.get fetch URLConnection` with input URL | `grep -rnE 'requests\.(get\|post)\|http\.get\|curl_exec\|URLConnection'` |
| **XXE** | XML parsers with external entities enabled (`libxml`, `DocumentBuilder`, `etree`) | `grep -rnE 'DocumentBuilder\|libxml\|etree.parse\|SAXParser'` |
| **Template injection (SSTI)** | `render_template_string Template(...).render eval-like template concat` | `grep -rnE 'render_template_string\|Template\(\|Twig'` |
| **Open redirect** | `redirect(input) Location: input sendRedirect` | `grep -rnE 'redirect\(\|sendRedirect\|Location:'` |
| **XSS (stored/reflected)** | output of input without encoding; `innerHTML dangerouslySetInnerHTML \|safe \|raw render` | `grep -rnE 'innerHTML\|dangerouslySetInnerHTML\|\|safe\|render\('` |
| **Auth / access control** | missing authz check on a handler; `if user.isAdmin` after the action; IDOR on object IDs | review every route's authz guard |
| **Secrets** | hardcoded keys/passwords/tokens | `trufflehog`/`gitleaks` + `grep -rniE 'api[_-]?key\|secret\|password\s*='` |

### 3. Prove the dataflow (reachability)
A sink is only a bug if a **source** reaches it tainted. Sources by layer: HTTP params/body/headers/cookies, file uploads, message queues, DB rows (second-order), and inter-service calls.
```bash
semgrep --config p/security-audit .          # fast first sweep (leads, not findings)
# then prove the hard ones with CodeQL taint (source = request input, sink = the call):
codeql database create db --language=<lang> [--command="build"]
codeql database analyze db <lang>-security-extended.qls --format=sarifv2.1.0 -o r.sarif
```
Walk the SARIF path; confirm no sanitizer/validator neutralises the input on the way.

### 4. Variant analysis
Found one? Generalise the grep/semgrep rule (or CodeQL query) and sweep the whole repo - the same mistake usually repeats. That sweep is where a single audit yields multiple CVEs.

## Per-language quick reference (sources -> top sinks)
```
PHP      $_GET/$_POST/$_REQUEST/$_COOKIE -> system,exec,shell_exec,include,unserialize,eval, mysqli string concat
Python   request.args/form/json/headers -> os.system,subprocess(shell=True),pickle.loads,yaml.load,eval, .raw SQL, jinja string
Node/JS  req.query/body/params/headers -> child_process.exec,eval,Function(),fs.*(path),res.redirect, innerHTML, sequelize.literal
Java     request.getParameter/getHeader -> Runtime.exec,ProcessBuilder,ObjectInputStream,DocumentBuilder, Statement string SQL
Ruby     params[...] -> system/`backticks`,Marshal.load,YAML.load,send(), ERB, AR where("..."+x)
Go       r.URL.Query/r.FormValue -> os/exec.Command,text/template,fmt into SQL, filepath.Join(input)
```

## Detection and defence
Parameterised queries, allowlist input validation, output encoding per context, safe deserialization (no untrusted input), SSRF allowlists, SAST + secret scanning in CI, least-privilege handlers with enforced authz.

## Tools
[[semgrep]] (fast sweep), [[codeql]] (taint proof), [[trivy]] (dep CVEs), `trufflehog`/`gitleaks` (secrets), grep. Web confirmation -> the matching `hunt-*` skill and `wiki/payloads/`. Memory-unsafe code -> [[memory-safety-bugs]]. Methodology: [[static-code-analysis]].

## Sources
