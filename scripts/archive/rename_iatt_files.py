#!/usr/bin/env python3
"""
rename_iatt_files.py -- Rename triple-dash IATT filenames to single-dash.

  active-directory---certificate-esc1.md  →  active-directory-certificate-esc1.md
  aws---service---ec2.md                  →  aws-service-ec2.md
  nopac--samaccountname-spoofing.md       →  nopac-samaccountname-spoofing.md

Also:
  - Deletes active-directory---enumeration.md (duplicate of active-directory-enumeration.md)
  - Fixes static-code-analysis.md phase: reconnaissance -> recon
  - Updates wikilinks in files that reference old triple-dash stems

Run: python3 scripts/rename_iatt_files.py [--dry-run]
"""

import re
import sys
from pathlib import Path

VAULT = Path("/path/to/ClaudeBrain")
TECH = VAULT / "wiki" / "techniques"
DRY = "--dry-run" in sys.argv

TODAY = __import__("datetime").date.today().isoformat()


def normalise_stem(stem: str) -> str:
    """Replace --- and -- with single dash."""
    s = stem.replace("---", "-")
    while "--" in s:
        s = s.replace("--", "-")
    return s


def collect_renames(directory: Path) -> tuple[list, list, list]:
    """Return (renames, conflicts, unchanged)."""
    existing = {f.name for f in directory.glob("*.md")}
    renames, conflicts, unchanged = [], [], []
    for f in sorted(directory.glob("*.md")):
        new_stem = normalise_stem(f.stem)
        new_name = new_stem + ".md"
        if new_name == f.name:
            unchanged.append(f.name)
        elif new_name in existing and new_name != f.name:
            conflicts.append((f, directory / new_name))
        else:
            renames.append((f, directory / new_name))
    return renames, conflicts, unchanged


def update_wikilinks(path: Path, rename_map: dict[str, str]) -> bool:
    """Replace [[old-stem]] and [[old-stem|display]] in file. Returns True if changed."""
    raw = path.read_text(encoding="utf-8")
    changed = False
    for old_stem, new_stem in rename_map.items():
        # Match [[old-stem]] and [[old-stem|anything]]
        pattern = re.compile(r"\[\[" + re.escape(old_stem) + r"(\|[^\]]+)?\]\]")
        def replace(m):
            suffix = m.group(1) or ""
            return f"[[{new_stem}{suffix}]]"
        new_raw = pattern.sub(replace, raw)
        if new_raw != raw:
            raw = new_raw
            changed = True
    if changed and not DRY:
        path.write_text(raw, encoding="utf-8")
    return changed


def fix_static_code_analysis():
    p = TECH / "static-code-analysis.md"
    if not p.exists():
        return
    raw = p.read_text(encoding="utf-8")
    new = re.sub(r"^phase: reconnaissance$", "phase: recon", raw, flags=re.MULTILINE)
    if new != raw:
        print(f"{'[DRY] ' if DRY else ''}FIXED phase  static-code-analysis.md: reconnaissance → recon")
        if not DRY:
            p.write_text(new, encoding="utf-8")


def main():
    prefix = "[DRY] " if DRY else ""

    # ── 1. Collect renames ────────────────────────────────────────────────
    renames, conflicts, _ = collect_renames(TECH)

    # ── 2. Handle conflict: active-directory---enumeration.md ─────────────
    # The enriched active-directory-enumeration.md is better; delete the IATT stub.
    conflict_delete = []
    for old_f, new_f in conflicts:
        if old_f.name == "active-directory---enumeration.md":
            conflict_delete.append(old_f)
            print(f"{prefix}DELETE (duplicate) {old_f.name}  →  kept {new_f.name}")
        else:
            print(f"UNHANDLED CONFLICT: {old_f.name} → {new_f.name} (manual review needed)")

    # ── 3. Build rename map (old_stem → new_stem) ─────────────────────────
    rename_map: dict[str, str] = {}
    for old_f, new_f in renames:
        rename_map[old_f.stem] = new_f.stem

    # ── 4. Scan vault for wikilinks using old stems ───────────────────────
    wiki_dir = VAULT / "wiki"
    link_fixes: dict[Path, bool] = {}
    for md_file in sorted(wiki_dir.rglob("*.md")):
        changed = update_wikilinks(md_file, rename_map)
        if changed:
            link_fixes[md_file] = True
            print(f"{prefix}LINKS  {md_file.relative_to(VAULT)}")

    # ── 5. Perform file renames ───────────────────────────────────────────
    for old_f, new_f in renames:
        print(f"{prefix}RENAME {old_f.name}  →  {new_f.name}")
        if not DRY:
            old_f.rename(new_f)

    # ── 6. Delete duplicates ──────────────────────────────────────────────
    for f in conflict_delete:
        if not DRY:
            f.unlink()

    # ── 7. Fix static-code-analysis.md phase ─────────────────────────────
    fix_static_code_analysis()

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"{prefix}Renamed: {len(renames)}  Deleted (dup): {len(conflict_delete)}  Link files updated: {len(link_fixes)}  Phase fixes: 1")
    if DRY:
        print("Re-run without --dry-run to apply.")


if __name__ == "__main__":
    main()
