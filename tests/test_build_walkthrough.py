"""Tests for scripts/build-walkthrough.py: walkthrough skeleton scaffolding plus
auto-population of the '## Evidence' gallery from rendered PoC images.

build-walkthrough.py has a hyphen in its filename, so it is loaded via importlib
(mirrors the _load helper pattern already used in tests/test_scripts.py and
tests/test_check_hooks.py).
"""
import importlib.util
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    spec = importlib.util.spec_from_file_location(
        "build_walkthrough", os.path.join(REPO, "scripts", "build-walkthrough.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_bytes(path, content=b"fake-png"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)


def _write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def test_absent_walkthrough_writes_skeleton_with_evidence_gallery(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    _write_bytes(str(eng / "recon" / "0001-nmap-x.png"))
    _write_bytes(str(eng / "poc" / "pages" / "0001-page-y.png"))

    text = bw.build(str(eng))

    assert "# Walkthrough - acme" in text
    # scaffolded from the FRAMEWORK template (setup/templates/_walkthrough.md), not
    # a competing skeleton: exact headings as they appear in that template.
    for heading in ("## 0. Access / connectivity", "## 1. Recon",
                     "## 2. Foothold  (-> user)", "## 3. Privilege escalation  (-> root)",
                     "## Flags", "## Evidence", "## One-shot reproduction (optional)",
                     "## Rabbit holes (skip on redo)"):
        assert heading in text, heading
    assert "<ENGAGEMENT>" not in text
    assert "<DATE>" not in text
    # captions now derive from the filename (the drain manifest was removed)
    assert "| ![](recon/0001-nmap-x.png) | nmap x |" in text
    assert "browser render + request/response (page capture)" in text  # 0001-page- card shape
    # actually written to disk, and matches the returned string
    written = (eng / "walkthrough.md").read_text(encoding="utf-8")
    assert written == text


def test_caption_fallback_derived_from_filename(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    _write_bytes(str(eng / "recon" / "0002-foothold-shell.png"))

    text = bw.build(str(eng))

    assert "0002-foothold-shell.png" in text
    assert "foothold shell" in text


def test_deterministic_ordering_recon_before_pages_before_leads(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    _write_bytes(str(eng / "poc" / "leads" / "0001-lead-a.png"))
    _write_bytes(str(eng / "poc" / "pages" / "0001-page-b.png"))
    _write_bytes(str(eng / "recon" / "0001-nmap-c.png"))

    text = bw.build(str(eng))

    i_recon = text.index("recon/0001-nmap-c.png")
    i_pages = text.index("poc/pages/0001-page-b.png")
    i_leads = text.index("poc/leads/0001-lead-a.png")
    assert i_recon < i_pages < i_leads


def test_idempotent_gallery_refresh_preserves_narrative(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    _write_bytes(str(eng / "recon" / "0001-nmap-x.png"))
    narrative = "The writable S3 bucket let us poison the CDN JS and steal the bot creds."
    existing = (
        "---\ntitle: \"Walkthrough - acme\"\n---\n\n"
        "# Walkthrough - acme\n\n"
        "## 1. Recon\n" + narrative + "\n\n"
        "## Evidence\n| shot | caption |\n|------|---------|\n"
        "| ![](recon/old.png) | stale row |\n\n"
        "## One-shot reproduction\nrun the script\n"
    )
    _write_text(str(eng / "walkthrough.md"), existing)

    text = bw.build(str(eng))

    assert narrative in text
    assert "recon/0001-nmap-x.png" in text
    assert "recon/old.png" not in text
    assert "## One-shot reproduction" in text
    assert "run the script" in text

    # running again with no new images changes nothing evidence-wise (idempotent)
    text_again = bw.build(str(eng))
    assert text_again == text

    # add another image, refresh again: new row appears, narrative still intact
    _write_bytes(str(eng / "recon" / "0002-linpeas-y.png"))
    text2 = bw.build(str(eng))
    assert narrative in text2
    assert "recon/0001-nmap-x.png" in text2
    assert "recon/0002-linpeas-y.png" in text2
    assert "run the script" in text2


def test_no_clobber_without_force_keeps_narrative(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    narrative = "Gained shell via CVE-2024-9999 in the vulnerable service."
    existing = (
        "# Walkthrough - acme\n\n"
        "## 2. Foothold\n" + narrative + "\n\n"
        "## Evidence\n| shot | caption |\n|------|---------|\n"
    )
    _write_text(str(eng / "walkthrough.md"), existing)

    text = bw.build(str(eng), force=False)

    assert narrative in text


def test_force_true_replaces_narrative_with_fresh_skeleton(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    narrative = "Gained shell via CVE-2024-9999 in the vulnerable service."
    existing = (
        "# Walkthrough - acme\n\n"
        "## 2. Foothold\n" + narrative + "\n\n"
        "## Evidence\n| shot | caption |\n|------|---------|\n"
    )
    _write_text(str(eng / "walkthrough.md"), existing)

    text = bw.build(str(eng), force=True)

    assert narrative not in text
    # force rewrites from the FRAMEWORK template (not the old competing skeleton),
    # so the structural headings from setup/templates/_walkthrough.md show up.
    assert "## 0. Access / connectivity" in text
    assert "## Rabbit holes (skip on redo)" in text


def test_empty_engagement_emits_placeholder_no_crash(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    eng.mkdir()

    text = bw.build(str(eng))

    assert "No rendered evidence found yet" in text
    assert "## Evidence" in text


def test_missing_area_dir_is_not_an_error(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    # only poc/leads exists; recon, poc/pages, poc, poc/scripts are all absent
    _write_bytes(str(eng / "poc" / "leads" / "0001-lead-only.png"))

    text = bw.build(str(eng))

    assert "poc/leads/0001-lead-only.png" in text


def test_insert_gallery_before_one_shot_when_no_evidence_heading(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    _write_bytes(str(eng / "recon" / "0001-nmap-x.png"))
    narrative = "No Evidence heading exists yet in this hand-written walkthrough."
    existing = (
        "# Walkthrough - acme\n\n"
        "## 1. Recon\n" + narrative + "\n\n"
        "## One-shot reproduction\nrun the script\n"
    )
    _write_text(str(eng / "walkthrough.md"), existing)

    text = bw.build(str(eng))

    assert narrative in text
    assert "run the script" in text
    assert "## Evidence" in text
    assert "recon/0001-nmap-x.png" in text
    # Evidence section must land before One-shot reproduction
    assert text.index("## Evidence") < text.index("## One-shot reproduction")


def test_insert_gallery_appends_at_end_when_no_one_shot_heading_either(tmp_path):
    """reviewer Important #2: a hand-written walkthrough with NEITHER an
    '## Evidence' heading NOR an '## One-shot reproduction' heading -> the gallery
    is appended at the end (the only sane fallback), narrative fully preserved."""
    bw = _load()
    eng = tmp_path / "acme"
    _write_bytes(str(eng / "recon" / "0001-nmap-x.png"))
    narrative = "Narrative with no Evidence heading and no One-shot heading at all."
    existing = "# Walkthrough - acme\n\n## 1. Recon\n" + narrative + "\n"
    _write_text(str(eng / "walkthrough.md"), existing)

    text = bw.build(str(eng))

    assert narrative in text
    assert "## Evidence" in text
    assert "recon/0001-nmap-x.png" in text
    # gallery lands after the narrative (appended at the end, not prepended/lost)
    assert text.index(narrative) < text.index("## Evidence")


def test_self_healed_template_is_refreshed_not_replaced(tmp_path):
    """The exact gap that let the Critical ship: engagement-init's self-heal
    substitutes <ENGAGEMENT>/<DATE> into setup/templates/_walkthrough.md BEFORE the
    file ever reaches disk, so a real engagement's walkthrough.md never contains the
    literal tokens. That self-healed-but-unfilled file must be refreshed in place
    (Evidence gallery populated, everything else preserved), not treated as bare and
    overwritten with a competing skeleton."""
    bw = _load()
    eng = tmp_path / "acme"
    tpl_path = os.path.join(REPO, "setup", "templates", "_walkthrough.md")
    with open(tpl_path, encoding="utf-8") as fh:
        tpl_text = fh.read()
    self_healed = tpl_text.replace("<ENGAGEMENT>", "acme").replace("<DATE>", "2020-01-01")
    _write_text(str(eng / "walkthrough.md"), self_healed)

    _write_bytes(str(eng / "recon" / "0001-nmap-x.png"))

    text = bw.build(str(eng))

    # (a) Evidence gallery now lists the image rows (caption from filename)
    assert "| ![](recon/0001-nmap-x.png) | nmap x |" in text
    # (b) template's structural headings and intro narrative are preserved
    assert "## 0. Access / connectivity" in text
    assert "## Flags" in text
    assert "## Rabbit holes (skip on redo)" in text
    assert "**TL;DR chain:**" in text
    # (c) no <ENGAGEMENT> token remains anywhere
    assert "<ENGAGEMENT>" not in text
    # (d) a second build run is idempotent (identical bytes)
    text_again = bw.build(str(eng))
    assert text_again == text


def test_truly_absent_file_scaffolds_framework_template(tmp_path):
    """A truly-absent walkthrough.md (empty engagement dir) scaffolds from the
    canonical FRAMEWORK template, not a competing skeleton."""
    bw = _load()
    eng = tmp_path / "acme"
    _write_bytes(str(eng / "recon" / "0001-nmap-x.png"))
    _write_bytes(str(eng / "poc" / "0001-shell.png"))

    text = bw.build(str(eng))

    assert "# Walkthrough - acme" in text
    assert "## 0. Access / connectivity" in text
    assert "## Rabbit holes (skip on redo)" in text
    assert "recon/0001-nmap-x.png" in text
    assert "poc/0001-shell.png" in text


# --- _caption_from_filename card shapes ----------------------------------

def test_caption_from_filename_tmux_card():
    bw = _load()
    result = bw._caption_from_filename("tmux-thm_UltraTech-10-112-128-181.png")
    assert "live tmux pane" in result
    assert "tmux thm UltraTech" not in result


def test_caption_from_filename_page_card():
    bw = _load()
    result = bw._caption_from_filename("0001-page-bf0858e7.png")
    assert "browser render" in result
    assert "request/response" in result


def test_caption_from_filename_source_card():
    bw = _load()
    result = bw._caption_from_filename("0001-source-x.png")
    assert "leaked source" in result


def test_caption_from_filename_lead_card():
    bw = _load()
    result = bw._caption_from_filename("0001-lead-x.png")
    assert "lead" in result


def test_caption_from_filename_generic_fallback_unchanged():
    bw = _load()
    result = bw._caption_from_filename("0002-foothold-shell.png")
    assert result == "foothold shell"


# --- gallery integration --------------------------------------------------

def test_gallery_uses_improved_filename_label_when_no_manifest(tmp_path):
    bw = _load()
    eng = tmp_path / "acme"
    _write_bytes(str(eng / "recon" / "tmux-thm_UltraTech-10-112-128-181.png"))

    text = bw.build(str(eng))

    assert "live tmux pane" in text
    assert "tmux thm UltraTech" not in text
