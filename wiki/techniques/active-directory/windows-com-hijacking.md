---
title: Windows - COM Hijacking
type: technique
tags: [windows, privilege-escalation, com, persistence]
phase: privilege-escalation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-windows]
---

# Windows - COM Hijacking

## What it is

COM (Component Object Model) classes are resolved from the registry by CLSID. The
per-user hive `HKCU\Software\Classes\CLSID` takes precedence over the machine-wide
`HKLM`/`HKCR` registration and is writable by the current user. When a privileged
or high-frequency process resolves a COM class from HKCU, you plant your DLL there
and it loads in that process's context, giving both local privilege escalation and
persistence.

## Finding hijackable classes

Hunt missing registrations with Procmon: filter `RegOpenKey`, result
`NAME NOT FOUND`, path ending in `InprocServer32` (in-proc DLL) or `LocalServer32`
(out-of-proc EXE). Also watch `TreatAs` and `ScriptletURL`.

## Base InprocServer32 hijack

Copy the real `ThreadingModel` to keep activation stable:

```powershell
$clsid = "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item "HKCU:Software\Classes\CLSID\$clsid\InprocServer32" -Value "C:\payload.dll" -Force
New-ItemProperty "HKCU:Software\Classes\CLSID\$clsid\InprocServer32" "ThreadingModel" "Both"
```

## Task Scheduler COM triggers

Task Scheduler COM triggers give predictable execution: enumerate scheduled tasks
whose action is a COM CLSID and that trigger at logon for the Users group, find one
absent from HKCU, and create it there so your DLL fires on the next logon.

```powershell
Get-ScheduledTask | Where-Object { $_.Actions.ClassId -and $_.Triggers.Enabled } |
  Select-Object TaskName,TaskPath,{$_.Actions.ClassId}
```

## Registry-only variants (no InprocServer32 replacement)

- TreatAs + ScriptletURL: create a per-user class backed by `scrobj.dll` with a
  `ScriptletURL` pointing to a local or remote `.sct`, then add
  `HKCU\...\CLSID\{victim}\TreatAs` redirecting a stable high-frequency CLSID to it.
- TypeLib hijack (`script:` moniker): resolve the `LIBID` from
  `HKCR\CLSID\{clsid}\TypeLib`, then set the per-user
  `HKCU\Software\Classes\TypeLib\{LIBID}\<ver>\0\win32` default to `script:C:\evil.sct`.
  Loading the TypeLib (for example touching the Microsoft Web Browser control via
  Explorer/IE) runs the scriptlet. Populate `win64` too on 64-bit consumers.

## Related

- [[windows-privilege-escalation]]
- [[uac-bypass]]
