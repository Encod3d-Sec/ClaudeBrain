"""burp-approve.sh: the GUI approval-popup fallback. Source-level checks only (the click path needs a
live unlocked Kali seat + Burp, not CI). Verifies the safety probe and the primary-mechanism pointer."""
import pathlib

SCRIPT = (pathlib.Path(__file__).resolve().parents[1] / "scripts" / "burp" / "burp-approve.sh").read_text()


def test_probes_for_the_dialog_before_clicking():
    # it must confirm a dialog is present (orange Allow-Once pixel) before it clicks, never click blindly
    assert "import -window root -crop" in SCRIPT      # the pixel probe
    assert "Always Allow Host" in SCRIPT              # the sticky-approve button it targets
    assert "windowactivate" in SCRIPT                 # focus before the XTEST click


def test_points_at_scope_sync_as_the_primary():
    # this is a brittle fallback; it must name burp-scope-sync as the primary, non-brittle mechanism
    assert "burp-scope-sync" in SCRIPT
