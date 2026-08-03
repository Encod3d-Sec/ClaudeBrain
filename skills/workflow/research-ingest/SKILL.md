---
name: research-ingest
description: Ingest a CVE writeup, blog post, advisory, or GitHub repo into the wiki - fetch, dedup via sources:, update the right technique/tool page(s), re-index. Generic knowledge only; never client data.
---

# Research Ingest

Turn an external source (URL or `raw/research/` file) into durable wiki knowledge. Synthesise into existing technique/tool pages; do NOT create one page per source. Full workflow: `docs/workflows.md` (Research ingest / Git repo ingest).

## Procedure

1. **Fetch the source.**
   - URL: `defuddle parse <url> --md` for clean markdown (install: `npm i -g defuddle`); fall back to the `WebFetch` tool.
   - Local: read the file under `raw/research/`. GitHub repo: clone via WSL only (`wsl -d kali-linux -u kali -- git clone <url> /home/kali/<name>`), then read source/README.

2. **Find the home page.** `qmd_query "<technique/CVE class>"` via wiki-search MCP -> identify the technique/tool page that should hold this. One class = one page.

3. **Dedup (skip rule).** Read only the target page's frontmatter. If the ingest slug is already in `sources:`, STOP - already ingested. Otherwise continue.

4. **Synthesise** the new payload / bypass / CVE chain / detail into the page's existing sections (Methodology, Key payloads, Bypasses and variants). Add concrete commands in code blocks. Reconstruct any image into a code block - never embed images. No em-dashes.

5. **Tool page** if a new standalone tool appears: create/update `wiki/tools/<tool>.md`.

6. **Record the source.** Add the slug to the page's `sources:` list; bump `date_updated`. Register URL/path + slug in `raw/manifest.md`.

7. **Re-index + log.** `python3 scripts/gen_index.py` (catalog) and, after a bulk session, `qmd update` (search index). Append a one-line entry to `session/log.md`. Run `python3 scripts/lint-wiki.py -q` - must be clean.

## Guardrails
- **Generic only.** Wiki holds reusable methodology; client/engagement specifics stay in `targets/<eng>/`. Reusable default creds -> `wiki/cheatsheets/default-credentials.md`; reusable request patterns -> `api-request-findings.md`.
- Prefer enriching an existing page over creating a new one. New page only for a genuinely new technique/tool class.

Report: page(s) updated + slug added + lint status.
