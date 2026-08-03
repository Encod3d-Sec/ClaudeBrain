---
title: Kiosk Escape and Jail Breakout
type: technique
tags: [bypass, evasion, kiosk, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-14
sources: [InternalAllTheThings, hacktricks-hardware]
---

# Kiosk Escape and Jail Breakout

## What it is

Technical reference for **Kiosk Escape and Jail Breakout** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Kiosk breakout targets restricted desktop environments (thin clients, library PCs, ATMs) where a user is locked to a single application with no access to the desktop, taskbar, or file system. Attackers exploit dialog boxes (file open/save, print, help) to navigate the file system, launch browsers, or access shell URI handlers (`shell:startup`, `shell:programs`) that open Explorer or a run dialog. Once a command shell is obtained (often via Sticky Keys accessibility shortcuts, which launch `cmd.exe` at the lock screen), full control of the underlying Windows session is achieved.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Summary

* [Methodology](#methodology)
* [Gaining a command shell](#gaining-a-command-shell)
* [Sticky Keys](#sticky-keys)
* [Dialog Boxes](#dialog-boxes)
    * [Creating new files](#creating-new-files)
    * [Open a new Windows Explorer instance](#open-a-new-windows-explorer-instance)
    * [Exploring Context Menus](#exploring-context-menus)
    * [Save as](#save-as)
    * [Input Boxes](#input-boxes)
    * [Bypass file restrictions](#bypass-file-restrictions)
* [Internet Explorer](#internet-explorer)
* [Shell URI Handlers](#shell-uri-handlers)
* [References](#references)

## Tools

* [kiosk.vsim.xyz](https://kiosk.vsim.xyz/) - Tooling for browser-based, Kiosk mode testing.
* [break.yxz.red](https://break.yxz.red/) - Breakout Kit for Web Browser / Kiosk breakout Assessments.

## Methodology

* Display global variables and their permissions: `export -p`
* Switch to another user using `sudo`/`su`
* Basic privilege escalations such as CVE, sudo misconfiguration, etc. Comprehensive list at [Linux](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/) / [Windows](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/)
* List default commands in the restricted shell: `compgen -c`
* Container escape if it's running inside a `Docker`/`LXC` container
* Pivot onto the network
    * Scan other machines on the network or attempt SSRF exploitation
    * Metadata for Cloud assets, see `cloud/aws` and `cloud/azure`
* Use globbing capability built inside the shell: `echo *`, `echo .*`, `echo /*`

## Gaining a command shell

* **Shortcut**
    * [Window] + [R] -> cmd
    * [CTRL] + [SHIFT] + [ESC] -> Task Manager
    * [CTRL] + [ALT] + [DELETE] -> Task Manager
* **Access through file browser**: Browsing to the folder containing the binary (i.e. `C:\windows\system32\`), we can simply right click and `open` it
* **Drag-and-drop**: dragging and dropping any file onto the cmd.exe
* **Hyperlink**: `file:///c:/Windows/System32/cmd.exe`
* **Task Manager**: `File` > `New Task (Run...)` > `cmd`
* **MSPAINT.exe**
    * Open MSPaint.exe and set the canvas size to: `Width=6` and `Height=1` pixels
    * Zoom in to make the following tasks easier
    * Using the colour picker, set pixels values to (from left to right):

```ps1
1st: R: 10,  G: 0,   B: 0
2nd: R: 13,  G: 10,  B: 13
3rd: R: 100, G: 109, B: 99
4th: R: 120, G: 101, B: 46
5th: R: 0,   G: 0,   B: 101
6th: R: 0,   G: 0,   B: 0
```

    * Save it as 24-bit Bitmap (*.bmp;*.dib)
    * Change its extension from bmp to bat and run
    * The generated file is also available for download: [escape-breakout-mspaint.bmp](./files/escape-breakout-mspaint.bmp)

## Sticky Keys

* Spawn the sticky keys dialog
    * Via Shell URI : `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}`
    * Hit 5 times [SHIFT]
* Visit "Ease of Access Center"
* You land on "Setup Sticky Keys", move up a level on "Ease of Access Center"
* Start the OSK (On-Screen-Keyboard)
* You can now use the keyboard shortcut (CTRL+N)

## Dialog Boxes

### Creating new files

* Batch files – Right click > New > Text File > rename to .BAT (or .CMD) > edit > open
* Shortcuts – Right click > New > Shortcut > `%WINDIR%\system32`

## Open a new Windows Explorer instance

* Right click any folder > select `Open in new window`

## Exploring Context Menus

* Right click any file/folder and explore context menus
* Clicking `Properties`, especially on shortcuts, can yield further access via `Open File Location`

### Save as

* "Save as" / "Open as" option
* "Print" feature – selecting "print to file" option (XPS/PDF/etc)
* `\\127.0.0.1\c$\Windows\System32\` and execute `cmd.exe`

### Input Boxes

Many input boxes accept file paths; try all inputs with UNC paths such as `//attacker–pc/` or `//127.0.0.1/c$` or `C:\`

### Bypass file restrictions

Enter *.* or *.exe or similar in `File name` box

## Internet Explorer

### Download and Run/Open

* Text files -> opened by Notepad

### Menus

* The address bar
* Search menus
* Help menus
* Print menus
* All other menus that provide dialog boxes

### Accessing filesystem

Enter these paths in the address bar:

* file://C:/windows
* C:/windows/
* %HOMEDRIVE%
* \\127.0.0.1\c$\Windows\System32

### Unassociated Protocols

It is possible to escape a browser based kiosk with other protocols than usual `http` or `https`.
If you have access to the address bar, you can use any known protocol (`irc`, `ftp`, `telnet`, `mailto`, etc.)
to trigger the *open with* prompt and select a program installed on the host.
The program will than be launched with the uri as a parameter, you need to select a program that will not crash when recieving it.
It is possible to send multiple parameters to the program by adding spaces in your uri.

Note: This technique required that the protocol used is not already associated with a program.

Example - Launching Firefox with a custom profile:

This is a nice trick since Firefox launched with the custom profile may not be as much hardened as the default profile.

0. Firefox need to be installed.
1. Enter the following uri in the address bar: `irc://127.0.0.1 -P "Test"`
2. Press enter to navigate to the uri.
3. Select the firefox program.
4. Firefox will be launched with the profile `Test`.

In this example, it's the equivalent of running the following command:

```ps1
firefox irc://127.0.0.1 -P "Test"
```

## Shell URI Handlers

A URI (Uniform Resource Identifier) handler is a software component that enables a web browser or operating system to pass a URI to an appropriate application for further handling.

For example, when you click on a "mailto:" link in a webpage, your device knows to open your default email application. This is because the "mailto:" URI scheme is registered to be handled by an email application. Similarly, "http:" and "https:" URIs are typically handled by a web browser.

In essence, URI handlers provide a bridge between web content and desktop applications, allowing for a seamless user experience when navigating between different types of resources.

The following URI handlers might trigger application on the machine:

* shell:DocumentsLibrary
* shell:Librariesshell:UserProfiles
* shell:Personal
* shell:SearchHomeFolder
* shell:System shell:NetworkPlacesFolder
* shell:SendTo
* shell:Common Administrative Tools
* shell:MyComputerFolder
* shell:InternetFolder

## Kiosk/VDI and tablet GUI-application escape

Additions covering VDI allowlists and tablet kiosks not in the Windows-dialog material above:
- First, check the physical device: power-cycle to expose the start screen, brief power-cut to force a reboot, plug a real USB keyboard for more shortcuts, use an exposed Ethernet port to scan/sniff.
- Command execution from a common dialog's "Open with": pick a shell binary; enumerate more via LOLBAS (Windows) and GTFOBins (nix).
- Citrix/RDS/VDI restricted-desktop breakout: use Open/Save/Print-to-file dialogs as a mini-Explorer (`*.*`/`*.exe` in the filename box, right-click "Open in new window", Properties -> Open file location). Create execution paths by renaming a new file to `.CMD`/`.BAT` or a shortcut to `%WINDIR%\System32\cmd.exe`; drag-and-drop a file onto cmd.exe; if Task Manager is reachable use Run new task; if interactive shells are blocked but scheduling is allowed, schedule cmd.exe (`schtasks.exe` / `taskschd.msc`). Beat allowlists by filename/extension rename or by copying the payload into an allowed directory. Find writable staging with AccessChk:
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- Browser-only kiosk: `document.write('<input/type=file>')` opens a file dialog; unassociated protocols (`irc:`, `ftp:`, `telnet:`) trigger an "open with" prompt to launch an installed program with attacker args (e.g. `irc://127.0.0.1 -P "Test"` launches Firefox with a less-hardened custom profile).
- iPad/tablet kiosk: escape via gestures (swipe up with 4-5 fingers or slow swipe from the bottom for dock/multitask; swipe from the left for Today view) and a paired keyboard (Cmd-H home, Cmd-Space Spotlight, Cmd-Tab app switch, Cmd-L address bar in Safari). Only the app-escape shortcuts matter.

## References

* [PentestPartners - Breaking out of Citrix and other restricted desktop environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
* [Breaking Out! of Applications Deployed via Terminal Services, Citrix, and Kiosks - Scott Sutherland - May 22nd, 2013](https://blog.netspi.com/breaking-out-of-applications-deployed-via-terminal-services-citrix-and-kiosks/)
* [Escaping from KIOSKs - HackTricks](https://book.hacktricks.xyz/physical-attacks/escaping-from-gui-applications)
* [Breaking out of Windows Kiosks using only Microsoft Edge - Firat Acar - May 24, 2022](https://blog.nviso.eu/2022/05/24/breaking-out-of-windows-kiosks-using-only-microsoft-edge/)
* [HOW TO LAUNCH COMMAND PROMPT AND POWERSHELL FROM MS PAINT - 2022-05-14 - Rickard](https://tzusec.com/how-to-launch-command-prompt-and-powershell-from-ms-paint/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
- HackTricks (hardware-physical-access), ingest slug `hacktricks-hardware`.
