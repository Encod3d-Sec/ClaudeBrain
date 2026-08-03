---
title: Linux - Evasion
type: technique
tags: [evasion, linux, reference-import, fileless]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-15
sources: [InternalAllTheThings, hacktricks-linux]
---

# Linux - Evasion

## What it is

Technical reference for **Linux - Evasion** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Linux evasion techniques hide attacker activity from administrators and security tools by manipulating file names, timestamps, and process listings. Inserting Unicode zero-width characters into filenames creates files that appear identical to legitimate files visually but differ at the byte level, defeating simple filename-based auditing. Timestomping with `touch -t` or `debugfs` makes malicious files appear old and unrelated to the compromise, while techniques like hiding PIDs from non-root users via bind mounts on `/proc` obscure running implant processes from non-privileged defenders.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Summary

- [File Names](#file-names)
- [Command History](#command-history)
- [Hiding Text](#hiding-text)
- [Timestomping](#timestomping)
- [Hiding PID Listings From Non-Root Users](#hiding-pid-listings-from-non-root-users)

## File Names

An Unicode zero-width space can be inserted into filenames which makes the names visually indistinguishable:

```bash
# A decoy file with no special characters
touch 'index.php'

# An imposter file with visually identical name
touch $'index\u200D.php'
```

## Command History

Most shells save their command history so a user can recall them again later.  The command history can be viewed with the `history` command or by manually inspecting the contents of the file pointed to by `$HISTFILE` (e.g. `~/.bash_history`).
This can be prevented in a number of ways.

```bash
# Prevent writing to the history file at all
unset HISTFILE

# Don't save this session's command history in memory
export HISTSIZE=0
```

Individual commands that match a pattern in `HISTIGNORE` will be excluded from the command history, regardless of `HISTFILE` or `HISTSIZE` settings.  
By default, `HISTIGNORE` will ignore all commands that begin with whitespace:

```bash
# Note the leading space character:
 my-sneaky-command
```

If commands are accidentally added to the command history, individual command entries can be removed with `history -d`:

```bash
# Removes the most recently logged command.
# Note that we actually have to delete two history entries at once,
# otherwise the `history -d` command itself will be logged as well.
history -d -2 && history -d -1
```

The entire command history can be purged as well, although this approach is much less subtle and very likely to be noticed:

```bash
# Clears the in-memory history and writes the empty history to disk.
history -c && history -w
```

For a more destructive approach, you can either delete the contents of the `.bash_history` file or link it to `/dev/null` to prevent future history logging.

```ps1
# Permanently disable bash history by linking it to /dev/null
ln /dev/null -/.bash_history -sf

# Clear the existing bash history
echo "" > .bash history
```

## Hiding Text

ANSI escape sequences can be abused to hide text under certain circumstances.  
If the file's contents are printed to the terminal (e.g. `cat`, `head`, `tail`) then the text will be hidden.  
If the file is viewed with an editor (e.g. `vim`, `nano`, `emacs`), then the escape sequences will be visible.

```bash
echo "sneaky-payload-command" > script.sh
echo "# $(clear)" >> script.sh
echo "# Do not remove. Generated from /etc/issue.conf by configure." >> script.sh

# When printed, the terminal will be cleared and only the last line will be visible:
cat script.sh
```

## Timestomping

Timestomping refers to the alteration of a file or directory's modification/access timestamps in order to conceal the fact that it was modified.  
The simplest way to accomplish this is with the `touch` command:

```bash
# Changes the access (-a) and modification (-m) times using YYYYMMDDhhmm format.
touch -a -m -t 202210312359 "example"

# Changes time using a Unix epoch timestamp.
touch -a -m -d @1667275140 "example"

# Copies timestamp from one file to another.
touch -a -m -r "other_file" "example"

# Get the file's modification timestamp, modify the file, then restore the timestamp.
MODIFIED_TS=$(stat --format="%Y" "example")
echo "backdoor" >> "example"
touch -a -m -d @$MODIFIED_TS "example"
```

It should be noted that `touch` can only modify the access and modification timestamps.  It can't be used to update a file's "change" or "birth" timestamps.  The birth timestamp, if supported by the filesystem, tracks when the file was created.  The change timestamp tracks whenever the file's metadata changes, including updates to the access and modification timestamps.

If an attacker has root privileges, they can work around this limitation by modifying the system clock, creating or modifying a file, then reverting the system clock:

```bash
ORIG_TIME=$(date)
date -s "2022-10-31 23:59:59"
touch -a -m "example"
date -s "${ORIG_TIME}"
```

Don't forget that creating a file also updates the parent directory's modification timestamp as well!

## Hiding PID Listings From Non-Root Users

By default, the `/proc` filesystem exposes process information to all users. You can limit this access to only root by modifying the `/proc` mount options.

```ps1
sudo mount -o remount,rw,nosuid,nodev,noexec,relatime,hidepid=2 /proc
```

- `hidepid=2`: Hides all processes that don't belong to the user.
- `hidepid=1`: Hides only process details (command line, environment variables) but still shows PIDs.

## DDexec / EverythingExec: fileless in-memory execution (bypass noexec / read-only / allowlisting)

`execve()` needs a file path, which is exactly what noexec mounts, read-only filesystems, distroless containers, and hash/name allowlisting rely on to control execution. DDexec sidesteps all of it by NOT starting a new process: it rewrites the memory of the current shell via `/proc/self/mem` to replay what the kernel does on `execve()` (build the mappings, read the binary in, set perms, prime the stack + auxv, jump to the loader). No file ever touches disk with an executable bit.

Mechanics: a shell-created file descriptor to `/proc/$pid/mem` with write perms is inherited by children, so child processes can patch the shell's memory; ASLR is defeated by reading `/proc/$pid/maps`; `lseek()` into the huge `mem` file is done from shell via `dd` (or alternatives). The target binary is fed base64 on stdin and read by the injected shellcode. Only ubiquitous coreutils are needed: `dd`/`tail`/`head`/`cut`/`grep`/`od`/`readlink`/`base64`/`tr`.

```bash
# arget13/DDexec: run a binary that only exists as base64, no file on disk
base64 -w0 /bin/ls | bash ddexec.sh ls -l
# swap the seeker if dd is blocked/monitored (tail is default; hexdump/cmp/xxd also work)
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Related fileless primitives worth pairing on the same locked-down host: `memfd_create()` + `fexecve()` to execute from an anonymous RAM fd, and process hijack via `ptrace()`/`gdb` when available (same overwrite-the-return-address idea). Detection is EDR-side (`socket`/`ptrace`/`/proc/*/mem` write patterns), not file-based, so this evades filesystem allowlists entirely.

## References

- [ATT&CK - Impair Defenses: Impair Command History Logging](https://attack.mitre.org/techniques/T1562/003/)
- [ATT&CK - Indicator Removal: Timestomp](https://attack.mitre.org/techniques/T1070/006/)
- [ATT&CK - Indicator Removal on Host: Clear Command History](https://attack.mitre.org/techniques/T1070/003/)
- [ATT&CK - Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [Wikipedia - ANSI escape codes](https://en.wikipedia.org/wiki/ANSI_escape_code)
- [InverseCos - Detecting Linux Anti-Forensics: Timestomping](https://www.inversecos.com/2022/08/detecting-linux-anti-forensics.html)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
- HackTricks linux-hardening (ingest slug `hacktricks-linux`).
