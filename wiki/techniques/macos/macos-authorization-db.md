---
title: "macOS Authorization DB and authd"
type: technique
tags: [macos, privilege-escalation, post-exploitation]
phase: privilege-escalation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-macos]
---

## Authorization DB and authd

`/var/db/auth.db` (seeded from `/System/Library/Security/authorization.plist`) stores the rights that userspace XPC services consult to decide whether a client may perform a sensitive action. This is the model behind "enter your password to change X" prompts and is a rich privesc-audit and weakening surface, distinct from the SecurityAgentPlugins persistence angle in [[macos-persistence]]. The `rules` table keys a named right to a class: `allow`, `deny`, `user` (membership of `group`, e.g. admin), `rule` (subrules), or `evaluate-mechanisms` (runs builtins or SecurityAgentPlugin bundles). Read and reason about rights:

```bash
sudo sqlite3 /var/db/auth.db "select name, comment from rules"
security authorizationdb read com.apple.tcc.util.admin        # what protects a right
security authorizationdb read system.privilege.admin
```

A right whose rule is `authenticate-admin-nonshared` means class `user`, group `admin`, `allow-root=false`, `session-owner=false`: an admin password is required. If a service pins a sensitive action to a weak right (or a right you can satisfy), or if you can rewrite a right (root), you weaken the authorization gate. `authd` (`/usr/libexec/...`, logs to `/var/log/authd.log`) is the XPC daemon serving these checks. The `security` tool exercises `Security.framework`, including the classic root trampoline:

```bash
security execute-with-privileges /bin/ls   # forks /usr/libexec/security_authtrampoline /bin/ls as root
```

`AuthorizationExecuteWithPrivileges` funnels through that same `security_authtrampoline`; combined with a writable target path this is a recurring root privesc (see also [[macos-installers-abuse]]).
