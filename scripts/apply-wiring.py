#!/usr/bin/env python3
"""Apply a merged wiki-wiring proposal (JSON array of action objects) to the auto-fire config.

Consumes the proposals produced by the domain subagents (see
docs/superpowers/specs/2026-07-08-wiki-context-wiring-design.md) and edits:
  - scripts/playbook.json       (add_ref, new_fingerprint)  -- format preserved: one fingerprint/line
  - skills/hunt/triggers.json   (trigger)                    -- consolidated new entries per (tier,skill)
  - wiki/<hub>.md               (hub_link)                   -- adds [[child]] under a Wired section
  - scripts/wiring-exempt.txt     (exempt)

Action schema (one of):
  {"action":"add_ref","fingerprint":"<exact playbook key>","slug":"<page>"}
  {"action":"new_fingerprint","key":"<regex>","skills":[...],"tests":[...],"refs":[...],"prio":2,"approach":[...]?}
  {"action":"hub_link","hub":"<hub-slug>","slug":"<child-slug>"}
  {"action":"trigger","tier":"hard|surface","add":"<regex fragment>","skill":"hunt-xxx"}
  {"action":"exempt","slug":"<page>","reason":"<why>"}

Usage: apply-wiring.py proposals.json   (edits in place, prints a summary + warnings)
"""
from __future__ import annotations
import json, os, sys, glob, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOK = os.path.join(ROOT, "scripts", "playbook.json")
TRIGGERS = os.path.join(ROOT, "skills", "hunt", "triggers.json")
EXEMPT = os.path.join(ROOT, "scripts", "wiring-exempt.txt")

warn = []


def wiki_path(slug: str) -> str | None:
    hits = glob.glob(os.path.join(ROOT, "wiki", "**", f"{slug}.md"), recursive=True)
    return hits[0] if hits else None


def write_playbook(d):
    items = list(d["fingerprints"].items())
    lines = ["{", '  "_comment": ' + json.dumps(d["_comment"], ensure_ascii=False) + ",", '  "fingerprints": {']
    for i, (k, v) in enumerate(items):
        tail = "," if i < len(items) - 1 else ""
        lines.append("    " + json.dumps(k, ensure_ascii=False) + ": " + json.dumps(v, ensure_ascii=False) + tail)
    lines += ["  }", "}", ""]
    open(PLAYBOOK, "w", encoding="utf-8").write("\n".join(lines))


def write_triggers(d):
    def block(name, trailing):
        items = list(d[name].items())
        out = [f'  "{name}": ' + "{"]
        for i, (k, v) in enumerate(items):
            tail = "," if i < len(items) - 1 else ""
            out.append("    " + json.dumps(k, ensure_ascii=False) + ": " + json.dumps(v, ensure_ascii=False) + tail)
        out.append("  }" + trailing)
        return out
    lines = ["{", '  "_comment": ' + json.dumps(d["_comment"], ensure_ascii=False) + ","]
    lines += block("triggers", ",")
    lines.append('  "_surface_comment": ' + json.dumps(d.get("_surface_comment", ""), ensure_ascii=False) + ",")
    lines += block("surface_triggers", "")
    lines += ["}", ""]
    open(TRIGGERS, "w", encoding="utf-8").write("\n".join(lines))


def main():
    actions = json.load(open(sys.argv[1], encoding="utf-8"))
    pb = json.load(open(PLAYBOOK, encoding="utf-8"))
    tr = json.load(open(TRIGGERS, encoding="utf-8"))
    fps = pb["fingerprints"]

    counts = {"add_ref": 0, "new_fingerprint": 0, "hub_link": 0, "trigger": 0, "exempt": 0, "add_tools": 0}
    hub_children: dict[str, list[str]] = {}
    skill_tools: dict[str, list[str]] = {}     # skill name -> [tool slugs]
    trig_groups: dict[tuple, list[str]] = {}   # (tier, skill) -> [fragments]
    exempts: list[tuple] = []

    for a in actions:
        act = a.get("action")
        if act == "add_ref":
            k = a.get("fingerprint") or a.get("fingerprint_key")
            slug = a["slug"].replace("payloads/", "")
            if k not in fps:
                warn.append(f"add_ref: fingerprint key not found: {k!r} (slug {slug})"); continue
            refs = fps[k].setdefault("refs", [])
            if slug not in refs:
                refs.append(slug); counts["add_ref"] += 1
        elif act == "new_fingerprint":
            k = a.get("key") or a.get("regex")
            if k in fps:
                # merge refs instead of duplicating
                for r in a.get("refs", []):
                    if r not in fps[k].setdefault("refs", []):
                        fps[k]["refs"].append(r)
                warn.append(f"new_fingerprint: key already exists, merged refs: {k!r}"); continue
            entry = {"prio": a.get("prio", 2), "skills": a.get("skills", []),
                     "tests": a.get("tests", []), "refs": a.get("refs", [])}
            if a.get("approach"):
                entry["approach"] = a["approach"]
            fps[k] = entry; counts["new_fingerprint"] += 1
        elif act == "add_tools":
            k = a.get("fingerprint") or a.get("fingerprint_key")
            if k not in fps:
                warn.append(f"add_tools: fingerprint key not found: {k!r}"); continue
            tl = fps[k].setdefault("tools", [])
            for t in a.get("tools", []):
                if t not in tl:
                    tl.append(t); counts["add_tools"] += 1
        elif act == "hub_link":
            hub_children.setdefault(a["hub"], [])
            if a["slug"] not in hub_children[a["hub"]]:
                hub_children[a["hub"]].append(a["slug"]); counts["hub_link"] += 1
        elif act == "skill_tools":
            lst = skill_tools.setdefault(a["skill"], [])
            for t in a.get("tools", []):
                if t not in lst:
                    lst.append(t); counts.setdefault("skill_tools", 0); counts["skill_tools"] += 1
        elif act == "trigger":
            trig_groups.setdefault((a.get("tier", "surface"), a["skill"]), []).append(a["add"])
            counts["trigger"] += 1
        elif act == "exempt":
            exempts.append((a["slug"], a.get("reason", "").replace("\n", " "))); counts["exempt"] += 1
        else:
            warn.append(f"unknown action: {a!r}")

    # hub_link: append [[child]] links to each hub page under a maintained section
    for hub, kids in hub_children.items():
        hp = wiki_path(hub)
        if not hp:
            warn.append(f"hub_link: hub page not found: {hub!r} ({len(kids)} children skipped)"); continue
        text = open(hp, encoding="utf-8").read()
        existing = set(re.findall(r"\[\[([^\]|#]+)", text))
        new = [k for k in kids if k not in existing]
        if not new:
            continue
        block = "\n".join(f"- [[{k}]]" for k in new)
        marker = "## Wired sub-techniques"
        if marker in text:
            text = text.replace(marker, marker + "\n" + block, 1)
        else:
            text = text.rstrip() + f"\n\n{marker}\n\n<!-- auto-wired: context-reachable sub-technique pages -->\n{block}\n"
        open(hp, "w", encoding="utf-8").write(text)

    # skill_tools: link tool pages from a recon skill body (makes them anchors)
    for sk, tls in skill_tools.items():
        cand = (glob.glob(os.path.join(ROOT, "skills", "hunt", sk, "SKILL.md"))
                + glob.glob(os.path.join(ROOT, "skills", "hunt", sk, "*.md"))
                + glob.glob(os.path.join(ROOT, "skills", "hunt", f"{sk}.md")))
        if not cand:
            warn.append(f"skill_tools: skill file not found: {sk!r} ({len(tls)} tools skipped)"); continue
        sp = cand[0]
        text = open(sp, encoding="utf-8").read()
        existing = set(re.findall(r"\[\[([^\]|#]+)", text))
        new = [t for t in tls if t not in existing]
        if not new:
            continue
        block = "\n".join(f"- [[{t}]]" for t in new)
        marker = "## Context tools"
        if marker in text:
            text = text.replace(marker, marker + "\n" + block, 1)
        else:
            text = text.rstrip() + f"\n\n{marker}\n\n<!-- auto-wired: documented tools to reach for; do not hand-roll -->\n{block}\n"
        open(sp, "w", encoding="utf-8").write(text)

    # trigger: add one consolidated new entry per (tier, skill)
    for (tier, skill), frags in trig_groups.items():
        key = "|".join(dict.fromkeys(frags))   # dedup, keep order
        tier_key = "triggers" if tier == "hard" else "surface_triggers"
        tr[tier_key][key] = skill

    if hub_children or trig_groups:
        pass
    write_playbook(pb)
    if trig_groups:
        write_triggers(tr)

    # exemptions
    if exempts:
        with open(EXEMPT, "a", encoding="utf-8") as f:
            for slug, reason in exempts:
                f.write(f"{slug}  # {reason}\n")

    print("Applied:", json.dumps(counts))
    if warn:
        print("\nWARNINGS:")
        for w in warn:
            print("  -", w)


if __name__ == "__main__":
    main()
