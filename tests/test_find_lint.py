"""Tests for scripts/find-lint.py (finding-completeness gate).

Hyphenated filename -> load via importlib (mirrors tests/test_lint_md_tables.py).

These are isolated from the live (gitignored) targets/ tree: every case builds its
own finding text, so the suite asserts the MECHANISM, not whatever findings happen
to exist on this machine.
"""
import importlib.util
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

POC_RE = r"^#+\s*(proof of concept|poc|reproduction|repro|steps)"


def _load():
    spec = importlib.util.spec_from_file_location(
        "find_lint", os.path.join(REPO, "scripts", "find-lint.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_shell_comment_in_fence_is_not_a_heading():
    """Regression: a `# comment` inside a ```bash fence used to be read as a
    markdown heading, truncating the section body to the fence line alone and
    failing any finding whose PoC opened with a commented command."""
    fl = _load()
    text = (
        "## Reproduction\n"
        "```bash\n"
        "# control - address that certainly does not exist\n"
        "curl -s -X POST https://example.org/api/v1/account/verify\n"
        "# -> {\"statusCode\":404,\"message\":\"User Not Found\"}\n"
        "```\n"
    )
    assert fl.section_nonempty(text, POC_RE)


def test_tilde_fence_also_tracked():
    fl = _load()
    text = (
        "## Proof of Concept\n"
        "~~~sh\n"
        "# a commented command inside a tilde fence\n"
        "curl -s https://example.org/version\n"
        "~~~\n"
    )
    assert fl.section_nonempty(text, POC_RE)


def test_real_heading_still_ends_the_section():
    """The fence fix must not swallow the next section: an unfenced heading
    still terminates the body, so a genuinely empty PoC stays a failure."""
    fl = _load()
    text = (
        "## Proof of Concept\n"
        "\n"
        "## Impact\n"
        "Plenty of impact prose lives down here, well over fifteen characters.\n"
    )
    assert not fl.section_nonempty(text, POC_RE)


def test_heading_inside_a_fence_does_not_open_a_section():
    """A fenced line that looks like the PoC heading must not be treated as one."""
    fl = _load()
    text = (
        "## Description\n"
        "```md\n"
        "## Proof of Concept\n"
        "this text is inside a fence and is not a real section body\n"
        "```\n"
    )
    assert not fl.section_nonempty(text, POC_RE)


def test_placeholder_only_body_still_fails():
    """Angle-tag placeholders are stripped, so a template stub stays incomplete."""
    fl = _load()
    text = "## Proof of Concept\n<step one>\n<step two>\n"
    assert not fl.section_nonempty(text, POC_RE)


def test_missing_section_fails():
    fl = _load()
    assert not fl.section_nonempty("## Description\nsome prose here\n", POC_RE)
