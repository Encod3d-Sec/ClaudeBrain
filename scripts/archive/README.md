# Archived scripts

Completed one-time migrations. Kept for provenance, not part of any live
workflow. Do not reference these from docs, CLAUDE.md, or hooks.

| Script | Purpose | Run once |
|---|---|---|
| `retag_iatt.py` | Fixed tags/phase on InternalAllTheThings-imported wiki pages | 2026-05-13 |
| `rename_iatt_files.py` | Normalized triple-dash IATT filenames to single-dash | 2026-05-13 |

The IATT import is long finished; these will not run again. If a future bulk
import needs similar cleanup, copy the relevant logic into a fresh, named
migration rather than re-running these.
