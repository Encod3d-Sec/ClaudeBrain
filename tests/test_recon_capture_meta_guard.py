"""The fingerprint router must NOT treat framework meta-work as target recon.

Regression for the false-fire class: editing playbook.json / running the wiring scripts
emits playbook tokens (hunt-<class> names, fingerprint regexes) whose presence in a
command's output otherwise got fingerprinted and surfaced as a discovered class
(deserialization, sqli) no target ever exposed.
"""
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    os.environ.setdefault("CLAUDEBRAIN_VAULT", ROOT)
    spec = importlib.util.spec_from_file_location("rc", os.path.join(ROOT, "skills", "hooks", "recon-capture.py"))
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    return rc


META_COMMANDS = [
    "python3 scripts/apply-wiring.py merged.json",
    "python3 scripts/wiki-wiring-audit.py --json",
    "grep -n 'type=password' scripts/playbook.json",
    "python3 - <<'PY'\nimport json; json.load(open('scripts/playbook.json'))\nPY",
    "cat skills/hunt/triggers.json",
    "vim skills/hooks/recon-capture.py",
]

REAL_RECON_COMMANDS = [
    "bash /root/vm.sh 'nxc smb 10.10.10.5 -u a -p b'",
    "nuclei -u http://target -o out.txt",
    "curl -s http://target/login.php",
    "ffuf -u http://t/FUZZ -w list.txt",
    "nmap -sCV -p- 10.10.10.5",
    "sqlmap -u 'http://t/?id=1' --batch",
]


def test_framework_meta_commands_are_guarded():
    rc = _load()
    for cmd in META_COMMANDS:
        assert rc._is_framework_meta(cmd), f"should be treated as framework-meta: {cmd!r}"


def test_real_recon_commands_not_guarded():
    rc = _load()
    for cmd in REAL_RECON_COMMANDS:
        assert not rc._is_framework_meta(cmd), f"real recon wrongly flagged as meta: {cmd!r}"


def test_meta_output_no_longer_records_false_classes_via_guard():
    """The precise repro: a blob of playbook tokens DOES fingerprint-match, so the guard (not
    the matcher) is what must suppress recording for a framework-meta command."""
    rc = _load()
    blob = ('Applied deserializ ysoserial gadget chain; login form type="password"; '
            'sqlstate sql syntax')
    # the matcher still matches (that is expected) ...
    assert rc.fingerprint_hits(blob), "sanity: these tokens do fingerprint-match"
    # ... so correctness depends on the router being skipped for the meta command:
    assert rc._is_framework_meta("python3 scripts/apply-wiring.py")
