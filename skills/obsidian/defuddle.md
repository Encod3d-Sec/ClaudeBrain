---
name: obsidian:defuddle
description: Fetch a URL and convert to clean markdown for research ingest. Uses defuddle when available, falls back to WebFetch.
type: tool
---

## Usage

```bash
# Primary: defuddle (clean markdown extraction)
defuddle parse <url> --md

# Install if missing
npm install -g defuddle
```

## Fallback

If defuddle is unavailable, use the `WebFetch` tool directly.

## When to use

- Ingesting CVE writeups, blog posts, advisories from a URL
- Fetching tool documentation for a tool page
- Any research ingest workflow where the source is a URL rather than a local file

## After fetching

1. Strip all image references (`![[...]]`, `![](...)`) from the fetched content
2. Proceed with normal ingest workflow - update relevant technique/tool pages
3. Register in `raw/manifest.md` if it's a significant reference source
