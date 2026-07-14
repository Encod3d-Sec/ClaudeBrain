---
title: Hardcoded Secrets Enumeration
type: technique
tags: [cloud, credentials, enumeration, linux, reference-import, secrets, web, windows]
phase: recon
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Hardcoded Secrets Enumeration

## What it is

Technical reference for **Hardcoded Secrets Enumeration** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Hardcoded secrets appear in source code, configuration files, deployment scripts, and CI/CD pipeline definitions when developers embed credentials directly rather than using a secrets manager. Attackers enumerate these by searching repositories (including git history with tools like truffleHog or gitleaks), scanning for pattern-matched strings (API key formats, connection strings, private key headers), and reviewing package manager files and build configurations for embedded tokens. Secrets found this way often provide direct access to cloud environments, databases, or third-party services without requiring any vulnerability exploitation.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Tools

* [synacktiv/nord-stream](https://github.com/synacktiv/nord-stream) - List the secrets stored inside CI/CD environments and extract them by deploying malicious pipelines
* [xforcered/SCMKit](https://github.com/xforcered/SCMKit) - Source Code Management Attack Toolkit

## Search inside Repositories, Files and Codes

* Discover repositories being used in a particular SCM system

```ps1
SCMKit.exe -s gitlab -m listrepo -c userName:password -u https://gitlab.something.local
SCMKit.exe -s gitlab -m listrepo -c apiKey -u https://gitlab.something.local
```

* Search for repositories by repository name in a particular SCM system

```ps1
SCMKit.exe -s github -m searchrepo -c userName:password -u https://github.something.local -o "some search term"
SCMKit.exe -s gitlab -m searchrepo -c apikey -u https://gitlab.something.local -o "some search term"
```

* Search for code containing a given keyword in a particular SCM system

```ps1
SCMKit.exe -s github -m searchcode -c userName:password -u https://github.something.local -o "some search term"
SCMKit.exe -s github -m searchcode -c apikey -u https://github.something.local -o "some search term"
```

* Search for files in repositories containing a given keyword in the file name in a particular SCM system

```ps1
SCMKit.exe -s gitlab -m searchfile -c userName:password -u https://gitlab.something.local -o "some search term"
SCMKit.exe -s gitlab -m searchfile -c apikey -u https://gitlab.something.local -o "some search term"
```

* List snippets owned by the current user in GitLab

```ps1
SCMKit.exe -s gitlab -m listsnippet -c userName:password -u https://gitlab.something.local
SCMKit.exe -s gitlab -m listsnippet -c apikey -u https://gitlab.something.local
```

## References

* [CI/CD SECRETS EXTRACTION, TIPS AND TRICKS - Hugo Vincent, Théo Louis-Tisserand - 01/03/2023](https://www.synacktiv.com/publications/cicd-secrets-extraction-tips-and-tricks.html)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
