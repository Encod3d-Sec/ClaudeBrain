---
title: "macOS Function Hooking"
type: technique
tags: [macos, injection, post-exploitation]
phase: post-exploitation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-macos]
---

## Function hooking: interposing, fishhook, method swizzling

Three in-process hooking primitives distinct from the DYLD_INSERT/dylib-hijack coverage in [[macos-library-injection]]. All require your code inside the target (via injection); the DYLD_INSERT restrictions still gate the load.

Interposing: a dylib with a `__DATA,__interpose` section of {replacement, original} tuples replaces C functions at load, before main runs. Debug with `DYLD_PRINT_INTERPOSING=1`. Does not affect calls resolved from the shared library cache.

```c
// gcc -dynamiclib interpose.c -o interpose.dylib
#include <stdio.h>
int my_printf(const char *f, ...) { return printf("hooked\n"); }
__attribute__((used)) static struct { const void *r; const void *o; }
_ip __attribute__((section("__DATA,__interpose"))) = { (void*)my_printf, (void*)printf };
// DYLD_INSERT_LIBRARIES=./interpose.dylib ./target
```

fishhook-style import rebinding: for an already-running process, walk `__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr`/`__nl_symbol_ptr` and overwrite the import slot (`rebind_symbols`, or `rebind_symbols_image` for one image). Only hooks calls that go through an import pointer, not intra-image direct calls. On recent macOS you must temporarily make `__DATA_CONST` writable, and on arm64e handle authenticated pointers in `__AUTH_CONST.__auth_got` with `<ptrauth.h>` helpers. `dyld_dynamic_interpose()` does the same programmatically at runtime.

Objective-C method swizzling: swap `IMP`s. `method_exchangeImplementations(orig, swz)` trades two implementations (detectable if the original checks its own selector); `method_setImplementation(orig, swizzledIMP)` replaces one and returns the old `IMP` to chain. Inspect classes/selectors with `class-dump` or `otool -ov`.

```objectivec
// prefer setImplementation: store original, install swizzle
static IMP orig;
orig = method_setImplementation(class_getInstanceMethod(cls, @selector(target:)), (IMP)hook);
```
