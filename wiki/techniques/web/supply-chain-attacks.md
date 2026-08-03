---
title: "Supply Chain & Dependency Confusion"
type: technique
tags: [cloud, dependency-confusion, supply-chain, cicd, exploitation, linux, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [payloadsallthethings-dependencyconfusion, pillar-rules-file-backdoor]
---

# Supply Chain & Dependency Confusion

## What it is

Compromising software by attacking what it *depends on* or *how it is built*, rather than the app itself. The headline variant, **dependency confusion**, tricks a package manager into pulling a malicious public package in place of an intended internal one of the same name. Pairs with `cicd-attacks` and [[trivy]] (find vulnerable deps).

## How it works (dependency confusion)
Many resolvers, when configured with both a public registry and a private one, will pull whichever has the **higher version** - or fall back to public when the private name is not found. Register the internal name publicly at `v99.99.99` and the build grabs yours, running your `preinstall`/`postinstall` (npm), `setup.py` (pip), or build hook.

### Attack flow (npm)
1. **Recon:** find internal package names - leaked `package.json`/`requirements.txt`/`pom.xml` on public GitHub, `require()`/import in client JS bundles, SBOMs, error pages.
2. **Verify:** the name is unregistered on the public registry (`npmjs.com`, `pypi.org`) - if absent, it is claimable.
3. **Exploit:** publish that name publicly with a high version + an install script that beacons out (DNS/HTTP) and/or runs code.
4. **Execute:** the target's CI runs `npm install`/`pip install` and pulls + executes your package.

Ecosystem files to mine: npm `package.json`, pip `requirements.txt`, maven `pom.xml`, composer `composer.json`, gem `Gemfile`, Dockerfile base images.

## Other supply-chain vectors
- **Typosquatting / combosquatting:** `reqeusts`, `python-sqlite`, `electron-prebuilt` - names close to popular packages.
- **Starjacking:** claim a package and point its repo URL at a popular project to borrow trust.
- **Install-script abuse:** malicious `postinstall`/`setup.py`/Gradle task - code runs at install, not import.
- **Maintainer takeover:** expired domain on a maintainer email, leaked npm token, no 2FA -> push a trojaned version (event-stream, ua-parser-js, ctx).
- **Build/CI poisoning:** compromise the pipeline (GitHub Actions, `npm publish` token, codecov bash uploader) to inject into legit releases.
- **Lockfile / `--extra-index-url`:** pip's `extra-index-url` checks public too; a lockfile poisoned in a PR.
- **Backdoored upstream:** the xz/`liblzma` (CVE-2024-3094) social-engineered backdoor.

### Rules File Backdoor (AI coding-assistant config poisoning)
A newer supply-chain carrier: hide malicious instructions inside an AI coding assistant's rules file (Cursor `.cursor/rules`, GitHub Copilot instruction files) or a project README using invisible Unicode (zero-width joiners/spaces, bidirectional/bidi markers, Unicode Tags-block chars). The text is invisible to a human reviewer and to the GitHub PR diff, but the model reads it and silently emits backdoored code without disclosing the change. Once the poisoned file is committed it taints every future generation in that repo and survives forking, so a single popular rules pack or starter template weaponizes every downstream project that adopts it, the same trust-inheritance abuse as a trojaned dependency or starjacked package. Full mechanism, test/grep recipe, and defence in [[mcp-server-attacks]].

## Real-world
Alex Birsan's 2021 dependency confusion hit Apple, Microsoft, PayPal and dozens more (>$130k bounties). event-stream (2018, crypto-wallet theft), codecov (2021), SolarWinds/SUNBURST (2020), ua-parser-js (2021), and xz (2024) are the canonical supply-chain incidents.

## Methodology / tools
```bash
# scan a repo's manifests for confusable / claimable internal names
confused -l npm package.json          # also pip, mvn, composer, rubygems
depfuzzer -d https://target ...        # find confusion + takeoverable owner emails
# inventory + known-CVE deps:
trivy fs --scanners vuln,license .     # see [[trivy]]
```
- [visma-prodsec/confused](https://github.com/visma-prodsec/confused), [synacktiv/DepFuzzer](https://github.com/synacktiv/DepFuzzer).

## Detection and defence
Use **scoped/namespaced** packages (`@org/pkg`) and reserve your names publicly; pin versions + commit lockfiles with **integrity hashes**; configure the private registry to NOT fall back to public for owned scopes; verify publisher 2FA + signed provenance (npm provenance, Sigstore); SBOM + SCA ([[trivy]]/grype) and dependency review in CI; vendor critical deps.

## Sources
- PayloadsAllTheThings - Dependency Confusion

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[package-managers-and-build-files]]
