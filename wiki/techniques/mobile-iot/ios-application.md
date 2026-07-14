---
title: "iOS Application Testing"
type: technique
tags: [mobile, ios, frida, objection, keychain, ssl-pinning, exploitation]
phase: exploitation
date_created: 2026-06-16
date_updated: 2026-07-02
sources: [owasp-mastg-ios]
---

## What it is

Security testing of iOS apps: inspecting the IPA, runtime instrumentation with Frida/objection, keychain and local-storage extraction, and bypassing SSL pinning and jailbreak detection. The iOS counterpart to [[android-application]].

## How it works

iOS apps are signed Mach-O binaries in an encrypted IPA, sandboxed per app. Testing usually needs a jailbroken device (or a re-signed app on a real device) to read app containers, hook Objective-C/Swift methods, and intercept TLS.

## Attack phases
Exploitation (app assessment; client-side and API trust-boundary testing).

## Prerequisites
- Jailbroken device (checkra1n/palera1n for A-series) or a re-signed IPA + sideload (Sideloadly). macOS with Xcode tooling helps. Frida server on device.

## Setup: device and Frida server

You need a jailbroken device (or a re-signed app on a normal device) to reach the container and hook the runtime. Jailbreaks are tied to chip/iOS: **checkra1n/palera1n** (checkm8 bootrom, A7-A11), **Dopamine/XinaA15** (A12-A15 rootless jailbreaks). On a jailbroken device install `frida` from the `re.frida.server` Cydia/Sileo repo; then:

```bash
frida-ps -Uai                       # list installed apps + PIDs over USB
frida-ps -Uai | grep -i <name>      # find the bundle id (e.g. com.company.app)
objection -g com.company.app explore # attach objection to a running/spawned app
```

Non-jailbroken path: re-sign the IPA with `objection patchipa` / `applesign` to inject the Frida gadget, then sideload with **Sideloadly** or AltStore. Slower, but works on stock iOS.

## Methodology

### 1. Acquire the IPA
The App Store binary is FairPlay-encrypted; you must dump the decrypted Mach-O from memory on a jailbroken device.

```bash
# decrypt + repackage from a jailbroken device (dumps decrypted Mach-O from RAM)
frida-ios-dump -l                   # list apps
frida-ios-dump com.company.app      # pulls app.ipa (decrypted)
# alternatives on-device: bagbak, flexdecrypt/frida-decrypt, or Clutch (older)
unzip app.ipa -d app/               # -> Payload/<App>.app/
otool -l "app/Payload/<App>.app/<App>" | grep -A4 LC_ENCRYPTION_INFO  # cryptid 0 == decrypted
```

Confirm `cryptid 0` before static analysis; `cryptid 1` means you dumped the still-encrypted binary and strings/disasm will be garbage.

### 2. Static analysis
```bash
# metadata
plutil -p "app/Payload/<App>.app/Info.plist"   # URL schemes, ATS, UIFileSharingEnabled, permissions
codesign -d --entitlements :- "app/Payload/<App>.app/<App>"  # keychain-access-groups, app-groups, associated-domains
otool -L <App>                                  # linked frameworks (AFNetworking/TrustKit -> pinning)
otool -Iv <App> | grep -i objc                  # ObjC/Swift runtime present?
nm <App>; strings -a <App> | grep -Ei 'http|api|token|secret|key'  # hardcoded endpoints/secrets
class-dump -H <App> -o headers/                 # ObjC class/method surface (Swift needs a demangler)
```

- **Ghidra** ([[ghidra]]) / **Hopper** / **radare2** ([[radare2]]) for the Mach-O: reverse crypto, jailbreak/anti-tamper logic, license/paywall checks. Swift symbols are mangled; use `swift-demangle` or Ghidra's Swift analyzer.
- **`Info.plist` red flags**: `NSAppTransportSecurity` -> `NSAllowsArbitraryLoads`/exception domains (cleartext or downgraded TLS), custom `CFBundleURLSchemes` (deep-link abuse surface), `UIFileSharingEnabled`/`LSSupportsOpeningDocumentsInPlace` (iTunes/Files exposes the Documents dir).
- **Entitlements**: shared `keychain-access-groups` and `com.apple.security.application-groups` widen data sharing across apps; `associated-domains` lists universal-link hosts to test.
- **Embedded secrets**: API keys, private keys, Firebase config, and hardcoded credentials in the binary, `*.plist`, and bundled JS (Cordova/React Native `main.jsbundle`). MobSF (see [[android-application]]) also handles IPAs for a quick automated pass.

### 3. Dynamic analysis (Frida / objection)
```bash
objection -g com.company.app explore
> env                                       # dump container paths (Documents/Library/tmp)
> ios sslpinning disable                    # bypass TLS pinning
> ios jailbreak disable                     # bypass jailbreak detection
> ios hooking list classes                  # runtime class list
> ios hooking search methods login          # find candidate methods
> ios hooking watch method "-[LoginVC validate:]" --dump-args --dump-return --dump-backtrace
> ios nsuserdefaults get                    # dump NSUserDefaults
> ios cookies get                           # WebView/HTTP cookies
```
```javascript
// Frida: force an ObjC validation method to return success
Interceptor.attach(ObjC.classes.LoginVC['- validate:'].implementation, {
  onLeave(ret){ ret.replace(ptr(1)); }   // YES / true
});

// enumerate loaded classes matching a keyword
ObjC.enumerateLoaderQuery; ObjC.classes; // e.g. Object.keys(ObjC.classes).filter(n => /Login|Crypto|Pin/.test(n))
```
Common hooking targets: LocalAuthentication (`-[LAContext evaluatePolicy:...]` -> bypass Face ID/Touch ID gate), keychain wrappers, feature-flag/paywall checks, and custom crypto (log keys/plaintext with a hook on `CCCrypt`).

### 4. Local data storage
```bash
# app container on a jailbroken device:
/var/mobile/Containers/Data/Application/<UUID>/
#   Library/Preferences/<bundle>.plist   -> NSUserDefaults (tokens/PII in cleartext)
#   Documents/*.sqlite, *.realm          -> Core Data / SQLite / Realm DBs
#   Library/Caches/                      -> cached API responses, snapshots
#   Library/Cookies/Cookies.binarycookies-> HTTP cookies
objection -g com.company.app explore -> ios keychain dump   # all keychain items + accessibility
```
Look for: tokens/PII in NSUserDefaults (never encrypted), unencrypted SQLite/Realm/Core Data, sensitive data in `Library/Caches` and app-switcher snapshots (`Library/SplashBoard`), and keychain items with weak `kSecAttrAccessible` (`kSecAttrAccessibleAlways`/`AlwaysThisDeviceOnly` persist through lock; prefer `WhenUnlockedThisDeviceOnly`). Backup exposure: items without `ThisDeviceOnly` sync to iCloud/iTunes backups.

### 5. IPC: URL schemes, universal links, pasteboard
- **Custom URL schemes** (`myapp://`): unprivileged and any app can invoke them, so treat parameters as untrusted input. Test for auth bypass, injection, and sensitive actions triggered without confirmation:
```bash
# on-device trigger:
uiopen "myapp://transfer?to=attacker&amount=1000"
# or via objection / Frida hook on application:openURL:options:
```
- **Universal links** (`https://` + `apple-app-site-association` at the domain): verify the AASA file and whether the app trusts the path without re-checking auth.
- **Pasteboard**: apps writing tokens to the general `UIPasteboard` leak them to every other app (and, pre-iOS 14, silently). Hook `UIPasteboard` setters.
- **App extensions / share sheet / WKWebView**: `WKWebView` with `javaScriptEnabled` + a JS bridge (`WKScriptMessageHandler`) or loading remote content is a client-side injection surface; test the bridge like a web target.

### 6. Traffic interception
Set the device HTTP proxy to Burp, install and trust the Burp CA (Settings -> General -> About -> Certificate Trust Settings -> enable full trust), then disable pinning (objection/Frida) and intercept the API. The real attack surface is almost always server-side: test the API as its own target, [[access-control]] / IDOR, [[authentication-attacks]], [[jwt-attacks]], and the web hunt skills. If pinning uses low-level `SecTrustEvaluate`, use the SSL-Kill-Switch2 tweak or a Frida `SecTrustEvaluateWithError` hook.

## Common iOS bug classes
- **Insecure local storage**: tokens/PII in NSUserDefaults, plaintext SQLite/Realm, weak keychain accessibility (the most common finding).
- **Broken TLS**: ATS disabled / arbitrary loads, missing or trivially bypassed pinning, trust-all `URLSession` delegates.
- **Hardcoded secrets** in the binary/plists/JS bundle.
- **URL-scheme / universal-link abuse**: unauthenticated deep-link actions, parameter injection, WebView `loadRequest` from a scheme.
- **Weak biometric gate**: `evaluatePolicy` used for UI unlock only (bypassable by hooking) rather than releasing a keychain item gated by `SecAccessControl`/`.biometryCurrentSet`.
- **WebView injection**: remote content in `WKWebView`, JS bridge exposing native functions, file:// access.
- **Client-side crypto**: hardcoded keys, ECB, static IVs, custom crypto (recover via a `CCCrypt` hook).
- **Sensitive data in logs / snapshots / backups** (ASL/os_log, app-switcher screenshot, iCloud backup).

## Bypasses and variants
- **SSL pinning**: objection `ios sslpinning disable`, SSL-Kill-Switch2, or a Frida hook of `SecTrustEvaluate`/`SecTrustEvaluateWithError`/AFNetworking/TrustKit pinning callbacks.
- **Jailbreak detection**: hook `fork`, `stat`/`fopen` on `/Applications/Cydia.app`, `/bin/bash`, `/etc/apt`, `canOpenURL:` for the `cydia:` scheme, and sandbox-escape write tests; objection `ios jailbreak disable` or the `Shadow`/`Liberty` tweaks.
- **Anti-Frida/debug**: hook `ptrace(PT_DENY_ATTACH)`, `sysctl(KERN_PROC)` debugger checks, and scans for the Frida port/`frida-agent` strings.
- **Biometric bypass**: hook `-[LAContext evaluatePolicy:localizedReason:reply:]` to invoke the reply block with success, effective only when biometrics gate UI rather than a keychain `SecAccessControl` item.

## Detection and defence
Pin with backup pins (and pin the intermediate), encrypted storage (keychain with `WhenUnlockedThisDeviceOnly`, data-protection classes), jailbreak/integrity attestation via **DeviceCheck / App Attest** (server-verified, not a client boolean), no secrets in the binary, ATS enforced with no arbitrary-loads exception, biometric gates that release a keychain item bound to `.biometryCurrentSet`, and no sensitive data in logs, pasteboard, snapshots, or backups.

## Tools
`frida` ([[frida]]) / `frida-ios-dump` / bagbak, `objection`, Burp Suite ([[burp-suite]]), `class-dump`, `otool`/`nm`/`plutil`/`codesign`, `radare2` ([[radare2]]) / [[ghidra]] / Hopper, MobSF, SSL-Kill-Switch2, checkra1n/palera1n/Dopamine, Sideloadly/AltStore. API testing pairs with the web hunt skills; shares runtime tooling with [[android-application]].

## Sources
- OWASP Mobile Application Security Testing Guide (MASTG) - iOS (slug: owasp-mastg-ios).
