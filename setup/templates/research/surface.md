---
title: "Attack Surface: <PROJECT>"
type: research-surface
date_created: <DATE>
date_updated: <DATE>
sources: []
---

# Attack Surface: <PROJECT>

Where bugs live. Map this before hypothesizing. `qmd_query` the tech/language/framework first to pull the matching methodology.

## Entry points (attacker-controlled input)
| Entry | Input type | Reaches (sink/component) | Notes |
|---|---|---|---|

## Parsers / decoders / deserializers
<!-- file formats, network protocols, serialization, regex, templating -->

## Dangerous sinks
<!-- memcpy/strcpy/sprintf, system/exec/popen, eval, unserialize/pickle, SQL, template render, path join, format string -->

## Privileged operations
<!-- setuid/setgid, IPC, kernel/driver, auth/session, crypto, file write -->

## Dependencies (CVE history)
| Dependency | Version | Known CVEs | Reachable from input? |
|---|---|---|---|
