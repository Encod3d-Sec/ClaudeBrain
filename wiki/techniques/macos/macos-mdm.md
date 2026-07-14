---
title: "macOS MDM"
type: technique
tags: [macos, mdm, post-exploitation]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## MDM and DEP enrollment abuse

An MDM server pushes commands to enrolled devices over APNs plus HTTPS, including config profiles that carry certificates, apps, WiFi/VPN credentials, and trusted root CAs, so MDM effectively functions as a root-level config-push channel. The weak point is enrollment. DEP zero-touch enrollment often requires only a serial number belonging to the target org to enroll a rogue device, after which the org pushes its sensitive payloads onto the attacker device. Apple 12-char serials are semi-predictable (location/year/week/unique/model).

Trigger the DEP check-in / Activation Record fetch (same path as first-boot Setup Assistant), and inspect enrollment:

```bash
sudo profiles show -type enrollment
profiles list
profiles status -type enrollment
```

Enrollment flow internals: `cloudconfigurationd` (root LaunchDaemon) fetches the DEP Activation Record over the private DEP API via XPC (`CPFetchActivationRecord` -> `MCTeslaConfigurationFetcher`, "Absinthe" encryption); `mdmclient` installs the profile and polls `ServerURL` for commands. Enrollment payloads: `com.apple.mdm` (enroll), `com.apple.security.scep` (client cert), `com.apple.security.pem` (trusted CA into System Keychain).

DEP Activation Record endpoints for tooling/replay:

```
GET  https://iprofiles.apple.com/resource/certificate.cer   # cert (serial via IOKit, NACInit)
POST https://iprofiles.apple.com/session                    # session key (NACKeyEstablishment)
POST https://iprofiles.apple.com/macProfile                 # {"action":"RequestProfileConfiguration","sn":"..."}
```
