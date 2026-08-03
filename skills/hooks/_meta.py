#!/usr/bin/env python3
"""Shared framework-meta guards for the recon-capture and hunt-trigger hooks.

Two callers, two questions:
  - recon-capture: is a Bash COMMAND operating on the vault's own machinery (playbook/
    hooks/wiring scripts)? Its output is full of playbook tokens that must NOT be read as
    target recon -> is_framework_meta(cmd).
  - hunt-trigger: is a PROMPT about the harness itself (documenting the wiki, editing
    triggers.json, discussing methodology) rather than attacking a target? Those hunt
    fires are false -> is_prompt_framework_meta(prompt). It is a superset of the command
    guard: it adds prose topics (wiki / documentation / methodology / playbook / "mcp
    server") that are safe to suppress on a PROMPT but would over-suppress a target-recon
    COMMAND (a real target can expose /wiki/ or /documentation/), which is why the command
    guard stays path-specific.
"""
import re

# Command-path oriented: names of the vault's own scripts/hooks/wiring files. Kept
# BYTE-IDENTICAL to recon-capture's original guard so its behavior + tests are unchanged.
_FRAMEWORK_META = re.compile(
    r"playbook\.json|triggers\.json|wiki-wiring|apply-wiring|wiring-exempt|"
    r"recon-capture|hunt-trigger|scope-guard|engagement-init|"
    r"scripts/(?:playbook|wiki|gen_index|build_moc|wl-add|wiki-stage|check-hooks)|"
    r"skills/hooks|/vault-hooks/", re.IGNORECASE)

# Prompt-topic oriented: prose that marks a PROMPT as harness-meta rather than target work.
# Deliberately NARROW: only the unambiguous "the harness" self-reference. Broad prose words
# (documentation / methodology / playbook / mcp server / wiki) were REMOVED - they appear
# constantly in real offensive prompts ("read the api documentation and test each endpoint for
# idor", "exploit the ssrf per the pentest methodology", "attack the mcp server for tool
# poisoning", "test the mediawiki app for xss"), and fully silencing those real hunts is a worse
# failure than a mild soft-fire. Harness CONFIG-FILE references (triggers.json / playbook.json /
# scripts/... / skills/hooks) are already caught by is_framework_meta (OR'd in below); the intent
# gate already keeps a non-offensive meta prompt out of a MANDATORY load.
_PROMPT_META = re.compile(r"\bthe harness\b", re.IGNORECASE)


def is_framework_meta(text):
    """True if `text` operates on the vault's own framework machinery (command-path guard)."""
    return bool(_FRAMEWORK_META.search(text or ""))


def is_prompt_framework_meta(text):
    """True if `text` is a PROMPT about the harness itself (documenting/editing the wiki,
    triggers.json, the playbook, methodology). Used by hunt-trigger to suppress false fires."""
    return is_framework_meta(text) or bool(_PROMPT_META.search(text or ""))
