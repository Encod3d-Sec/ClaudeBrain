"""PreToolUse no-echo-banner hook: block echo/printf '=== ... ===' banners, allow the rest."""
import json
import os
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "skills", "hooks", "no-echo-banner.py")


def _run(cmd, tool="Bash"):
    payload = {"tool_name": tool, "tool_input": {"command": cmd}}
    return subprocess.run(["python3", HOOK], input=json.dumps(payload),
                          capture_output=True, text=True, timeout=10).stdout


def test_denies_echo_banner():
    assert '"permissionDecision": "deny"' in _run('echo "=== nmap ==="; nmap -p- x')


def test_denies_printf_banner():
    assert "deny" in _run(r'printf "=== leads ===\n"')


def test_allows_clean_command():
    assert _run("nmap -p- 10.0.0.1 -oN out.txt").strip() == ""


def test_allows_echo_without_banner():
    assert _run("echo hello world").strip() == ""


def test_allows_equals_after_pipe_not_echo():
    # === reached only after a pipe from echo -> not a banner segment -> allowed
    assert _run("echo hi | grep '==='").strip() == ""


def test_allows_equals_in_grep():
    assert _run("grep -c '===' file.txt").strip() == ""


def test_non_bash_ignored():
    assert _run('echo "=== x ==="', tool="Write").strip() == ""


def test_denies_unquoted_banner():
    assert "deny" in _run("echo === section ===")


def test_denies_banner_inside_vm_wrapper():
    assert "deny" in _run('bash /root/vm.sh \'echo "=== nmap ==="; nmap -p- x\'')


# --- narrow scope: `===` that belongs to a TOOL / data, not a decorative banner, is allowed ---

def test_allows_echo_data_with_mid_string_equals():
    assert _run('echo "hello === world"').strip() == ""


def test_allows_echo_variable_that_may_contain_equals():
    assert _run('echo "$RESULT"').strip() == ""


def test_allows_grep_on_tool_banner_output():
    # a tool that integrates === separators -> grepping/reading it is fine (not echo/printf)
    assert _run("bash /root/vm.sh 'linpeas.sh | grep \"=== \"'").strip() == ""
