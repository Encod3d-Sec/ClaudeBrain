---
name: obsidian:obsidian-markdown
description: Obsidian-flavoured markdown conventions for writing vault pages - wikilinks, callouts, embeds, frontmatter, and image rules.
type: style
---

## Frontmatter

Every wiki page starts with YAML frontmatter. Required fields depend on page type - see CLAUDE.md `## Page types and frontmatter`.

```yaml
---
title: "Page Title"
type: technique | tool | cheatsheet | course | target | overview
tags: []
date_created: YYYY-MM-DD
date_updated: YYYY-MM-DD
sources: []
---
```

Always set `date_updated` to today when modifying a page.

## Wikilinks

```markdown
[[Page Title]]                    -- link to page by exact title
[[Page Title|display text]]       -- link with custom display text
```

Link targets must match the title exactly as it appears in `wiki/index.md`.

## Callouts

```markdown
> [!note]
> Note content

> [!warning]
> Warning content

> [!tip]
> Tip content

> [!important]
> Critical information
```

Use callouts sparingly - only for genuinely important warnings or tips.

## Code blocks

Always use fenced blocks with language tags:

```bash
nmap -sV -p- target
```

```sql
' OR 1=1 --
```

```python
import requests
```

## Image rule - CRITICAL

**Never embed images in wiki pages.** The vault contains many `![[Pasted image *.png]]` references in source files - skip them all.

- If surrounding text describes the image: extract as prose or a code block
- If a screenshot shows a command: reconstruct as a code block
- If truly irreplaceable: `[diagram: brief description]` inline - no embed

## Cross-references

- Link tools on first mention in technique pages
- Link techniques on first mention in tool pages
- Every course page must link all technique and tool pages it covers

## Style

- Clear, precise prose - no filler
- `**bold**` for defined terms on first use
- `[uncertain]` inline to flag uncertain claims
- `[contradicts: [[Other Page]]]` to flag source conflicts
- Cheatsheets: `#` comments for annotations, no prose
