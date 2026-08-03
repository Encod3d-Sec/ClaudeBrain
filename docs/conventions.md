# Wiki Conventions

## Cross-referencing

- Use Obsidian wiki links: `[[Page Title]]` or `[[Page Title|display text]]`
- Link to the exact page title as it appears in `index.md`.
- In technique pages, link tools on first mention. In tool pages, link techniques on first mention.
- Every course page must link to all technique and tool pages it covers.
- Target pages link to technique pages used during the engagement.

## Log format

Each entry must start with a consistent header (grep-parseable):

```
## [YYYY-MM-DD] ingest:cpts | Module Name
## [YYYY-MM-DD] ingest:portswigger | Module Name
## [YYYY-MM-DD] ingest:thm | Section Name (N rooms)
## [YYYY-MM-DD] ingest:research | Source Title
## [YYYY-MM-DD] target | Target Name -- phase
## [YYYY-MM-DD] query | Brief description
## [YYYY-MM-DD] lint | pass N
```

Followed by 2-4 bullet points summarising what changed.

## Style guide

- Write in clear, precise prose. No filler.
- All commands in fenced code blocks with the appropriate language tag (`bash`, `sql`, `python`, etc.).
- Use `**bold**` for defined terms on first use.
- Flag uncertainty with `[uncertain]` inline.
- Flag contradictions between sources with `[contradicts: [[Other Page]]]` inline.
- Cheatsheets use `#` comments for annotations, not prose.
- Do not add warnings or legal disclaimers to technique or cheatsheet pages.
- Never use em-dashes (--) in any output or wiki pages. Use a comma, semicolon, or rewrite the sentence instead.
- Never use emojis in any output or wiki pages.

## Tag taxonomy

Controlled vocabulary lives in `scripts/tag-vocab.json` (canonical `keep` set, `aliases` for synonyms, `keep_patterns` like `esc\d+`/`cve-*`, `drop` for vague tags). A tag survives only if it is canonical or used >=3x across the corpus; tool names, protocol names, and one-off vague tags are dropped.

- New pages: tag with **domain** (matches the wiki dir), **phase** (recon/enumeration/exploitation/post-exploitation/lateral-movement/privilege-escalation/persistence/evasion), **source** (thm/htb/h1/reference-import/writeup/cve), and specific **topic** tags from the vocabulary. Prefer existing canonical tags over inventing new ones.
- Don't tag with tool names (find tools by page title) or vague words (meta, technique, session, scripting).
- After bulk tag edits or before a lint pass, run `python3 scripts/normalize-tags.py` (dry-run) then `--apply`. Idempotent. **Excludes CTF and courses.**
- To add a synonym merge or rescue a wrongly-dropped tag, edit `tag-vocab.json` and re-run.
