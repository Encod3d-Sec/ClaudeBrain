"""win-rsh.sh: send ONE command to a Windows PS reverse-shell tmux tab, return clean output framed
by the shell's OWN prompt (no injected markers/nonce). The fake vm.sh plays the bridge: it un-escapes
the sent command (so $env: round-trips), records what was sent, and returns a realistic prompt-framed
pane. Tests: clean extraction, no marker/nonce emitted, $-safety, dead-shell (false-RCE) detection."""
import os
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RSH = os.path.join(REPO, "scripts", "win-rsh.sh")


def _fake_live(tmp_path, output_lines):
    """Live PS reverse shell. On send-keys: record args, extract+unescape the command (bridge
    behaviour), write pane = 'PS C:\\X> <cmd>' + output + returning prompt. On capture-pane: cat it
    (identical each poll -> win-rsh's stability check fires)."""
    out = tmp_path / "out.txt"; out.write_text("\n".join(output_lines))
    pane = tmp_path / "pane.txt"
    sent = tmp_path / "sent.log"
    fake = tmp_path / "vm.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'PANE="%s"; OUT="%s"; SENT="%s"\n' % (pane, out, sent) +
        'A="$*"\n'
        'case "$A" in\n'
        "  *send-keys*)\n"
        '    printf "%s\\n" "$A" >> "$SENT"\n'
        # extract the quoted command sent to send-keys, then unescape ONE level (\$ \" \` \\)
        '    C=$(printf "%s" "$A" | sed -n \'s/.*send-keys -t [^ ]* "\\(.*\\)" Enter.*/\\1/p\')\n'
        '    C=$(printf "%s" "$C" | sed \'s/\\\\\\$/$/g; s/\\\\"/"/g; s/\\\\`/`/g; s/\\\\\\\\/\\\\/g\')\n'
        '    { echo "PS C:\\\\X> ${C}"; cat "$OUT"; echo; echo "PS C:\\\\X> "; } > "$PANE"\n'
        "  ;;\n"
        '  *capture-pane*) cat "$PANE" 2>/dev/null ;;\n'
        "  *) : ;;\n"
        "esac\n")
    fake.chmod(0o755)
    return str(fake), str(sent)


def _fake_dead(tmp_path):
    fake = tmp_path / "vm.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in\n'
        "  *capture-pane*) printf '%b' '\\u250c\\u2500\\u2500(root\\u327fkali)-[/home/kali]\\n\\u2514\\u2500# ' ;;\n"
        "  *) : ;;\n"
        "esac\n")
    fake.chmod(0o755)
    return str(fake)


def test_win_rsh_clean_output_no_markers(tmp_path):
    fake, sent = _fake_live(tmp_path, ["privesc\\svcadmin", "svcadmin"])
    env = dict(os.environ, VM_SH=fake)
    # a $-heavy command: proves it is typed plainly and survives the bridge (no base64, no markers)
    r = subprocess.run(["bash", RSH, "--timeout", "10", "jump", "whoami; $env:USERNAME"],
                       capture_output=True, text=True, env=env, timeout=40)
    assert r.returncode == 0, r.stderr
    # echoed command line + trailing prompt stripped, only real output returned
    assert r.stdout.strip("\n") == "privesc\\svcadmin\nsvcadmin"
    sent_text = open(sent).read()
    # discipline: no injected sentinel/marker/nonce, no string-literal concat to dodge echo
    for banned in ("RSHb", "__PS_", "Write-Output ('", "'+'", "START", "base64"):
        assert banned not in sent_text, "win-rsh must not inject %r" % banned
    # $-safety: the command reached the shell as $env (escaped on the wire, unescaped by the bridge)
    assert "$env:USERNAME" in open(tmp_path / "pane.txt").read()


def test_win_rsh_detects_dead_shell_false_rce(tmp_path):
    env = dict(os.environ, VM_SH=_fake_dead(tmp_path))
    r = subprocess.run(["bash", RSH, "--timeout", "2", "jump", "whoami"],
                       capture_output=True, text=True, env=env, timeout=40)
    assert r.returncode == 1
    assert "DEAD" in r.stderr
    assert "false-rce" in r.stderr.lower() or "attacker" in r.stderr.lower()
