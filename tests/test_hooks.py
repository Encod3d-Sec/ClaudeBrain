"""End-to-end hook tests via subprocess with an isolated fixture vault."""
import json
import os
import subprocess
import time

# Import _engagement at module (collection) level, before any `vault` fixture runs,
# so its VAULT global self-locates to the REAL vault while CLAUDEBRAIN_VAULT is still
# unset. Without this, if this file is run in isolation, the first import happens
# lazily inside the first vault-fixture test (env var already monkeypatched at that
# point), which poisons the "original value" monkeypatch reverts to for the rest of
# the session. Mirrors the same pattern already relied on in test_engagement.py.
import _engagement  # noqa: E402,F401

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(REPO, "skills", "hooks")


def run_hook(name, payload, env):
    p = subprocess.run(
        ["python3", os.path.join(HOOKS, name)],
        input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=20)
    return p


def _env(vault):
    return dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))


def test_hunt_trigger_routes_without_mandating(vault):
    env = _env(vault)
    out = run_hook("hunt-trigger.py", {"prompt": "lets test ssrf here"}, env).stdout
    assert "Skill(hunt-ssrf)" in out                # still routes/surfaces the skill
    assert "Relevant skill" in out
    assert "MANDATORY" not in out                   # routing, not a hard mandate
    assert "before any other tool call" not in out.lower()


def test_hunt_trigger_surface_tier_is_softer(vault):
    # natural attack-surface term -> heuristic "consider" line, not MANDATORY
    out = run_hook("hunt-trigger.py", {"prompt": "look at this login form"}, _env(vault)).stdout
    assert "Skill(hunt-auth)" in out
    assert "consider" in out and "MANDATORY" not in out


def test_hunt_trigger_logs_fire_telemetry(vault):
    env = _env(vault)
    run_hook("hunt-trigger.py", {"prompt": "test ssrf"}, env)
    run_hook("hunt-trigger.py", {"prompt": "what time is it"}, env)  # miss
    log = os.path.join(str(vault), ".trigger-fire.jsonl")
    assert os.path.isfile(log)
    rows = [json.loads(l) for l in open(log) if l.strip()]
    assert any(r["hard"] == ["hunt-ssrf"] for r in rows)
    assert any(r["hard"] == [] and r["soft"] == [] for r in rows)  # miss logged too
    for r in rows:  # leak-safe: no prompt text in the record
        assert set(r) == {"ts", "hard", "soft", "n"}


def test_hunt_trigger_silent_on_unrelated(vault):
    out = run_hook("hunt-trigger.py", {"prompt": "what time is it"}, _env(vault)).stdout
    assert out.strip() == ""


def test_hunt_trigger_skips_injected_content(vault):
    # task-notifications / system-reminders reach UserPromptSubmit but are NOT typed
    # prompts; firing MANDATORY on their vuln-keyword text erodes trust in MANDATORY.
    injected = ("<task-notification>subagent found ssrf and idor; "
                "test the api and exploit it</task-notification>")
    out = run_hook("hunt-trigger.py", {"prompt": injected}, _env(vault)).stdout
    assert out.strip() == ""                                                    # no directive
    assert not os.path.isfile(os.path.join(str(vault), ".trigger-fire.jsonl"))  # not even logged


def test_session_guard_flags_client_marker(vault):
    # active engagement is 'acme' -> writing that marker into session/hot.md is a leak
    payload = {"tool_name": "Write",
               "tool_input": {"file_path": str(vault / "session" / "hot.md"),
                              "content": "today on acme we filed findings"}}
    out = run_hook("session-guard.py", payload, _env(vault)).stdout
    assert "CLIENT-DATA BOUNDARY" in out and "acme" in out


def test_session_guard_silent_for_targets_dest(vault):
    # writing the same into targets/<eng>/log.md is the CORRECT destination -> silent
    payload = {"tool_name": "Write",
               "tool_input": {"file_path": str(vault / "targets" / "acme" / "log.md"),
                              "content": "today on acme we filed findings"}}
    out = run_hook("session-guard.py", payload, _env(vault)).stdout
    assert out.strip() == ""


def test_session_guard_silent_for_generic_content(vault):
    payload = {"tool_name": "Write",
               "tool_input": {"file_path": str(vault / "session" / "hot.md"),
                              "content": "refactored the lint-wiki playbook check"}}
    out = run_hook("session-guard.py", payload, _env(vault)).stdout
    assert out.strip() == ""


def test_hunt_trigger_secrets_keyword(vault):
    # "found" is past-tense (excluded from the intent-verb gate), so hunt-secrets now
    # DOWNGRADES to the soft "consider" tier -- the assertion still holds via that line.
    out = run_hook("hunt-trigger.py", {"prompt": "found a hardcoded api key in the JS bundle"},
                   _env(vault)).stdout
    assert "Skill(hunt-secrets)" in out


def test_hunt_trigger_list_valued_routes_both(vault):
    # "broken access control" -> ["hunt-idor", "hunt-api"] (list-valued trigger)
    out = run_hook("hunt-trigger.py", {"prompt": "test for broken access control"}, _env(vault)).stdout
    assert "Skill(hunt-idor)" in out and "Skill(hunt-api)" in out


def test_hunt_trigger_multi_match(vault):
    # intent-laden prompt (was "sql injection and oauth", which has no intent verb) so
    # both hunt-* keywords stay in the hard tier -> MANDATORY multi-skill directive.
    out = run_hook("hunt-trigger.py",
                   {"prompt": "test for sql injection and attack the oauth flow"}, _env(vault)).stdout
    assert "hunt-sqli" in out and "hunt-federation" in out
    assert "Relevant skill" in out


def test_hunt_trigger_intent_verb_fires_hard(vault):
    # offensive/imperative verb ("exploit") near the hunt-* keyword -> stays MANDATORY
    out = run_hook("hunt-trigger.py",
                   {"prompt": "exploit the sqli in the login form"}, _env(vault)).stdout
    assert "Skill(hunt-sqli)" in out
    assert "Relevant skill" in out


def test_hunt_trigger_prose_mention_downgrades_to_soft(vault):
    # no intent verb near the keyword (ordinary descriptive prose) -> downgraded to
    # the soft "consider" tier, not dropped, and NOT a MANDATORY hard fire.
    out = run_hook("hunt-trigger.py",
                   {"prompt": "the SSRF router forwards requests to the backend"}, _env(vault)).stdout
    assert "MANDATORY" not in out
    assert "consider" in out and "Skill(hunt-ssrf)" in out


def test_hunt_trigger_review_prose_does_not_force_mandatory(vault):
    # discussing/reviewing a tool by name, not attacking it -> no intent verb nearby
    # -> hunt-mcp downgrades to soft, no imperative load-first directive.
    # (NOTE: the brief's original example prompt for this case, "using the Burp MCP
    # as a tool, not attacking one", was verified to still fire hard -- "attacking"
    # falls inside the 64-char window around the "mcp" match and the gate does not
    # do negation-detection ("not attacking"). Swapped in this prompt, which has no
    # intent-verb token anywhere in it, to actually exercise the intended behavior.)
    out = run_hook("hunt-trigger.py",
                   {"prompt": "using the Burp MCP as a tool during code review"}, _env(vault)).stdout
    assert "Your FIRST action MUST be to load Skill(hunt-mcp)" not in out
    assert "MANDATORY" not in out


def test_hunt_trigger_verbless_multi_downgrades_to_soft(vault):
    # two hunt-* keywords, no intent verb anywhere -> both downgrade to soft, no MANDATORY.
    # (NOTE: the brief's original example prompt for this case, "sql injection and oauth",
    # was verified to still fire hard -- "injection" itself matches the `inject\w*` intent
    # token baked into the vuln name, so the trigger keyword self-satisfies the gate
    # regardless of user intent. Swapped in this prompt, which has no intent-verb
    # substring in either keyword, to actually exercise the intended behavior.)
    out = run_hook("hunt-trigger.py", {"prompt": "idor and oauth"}, _env(vault)).stdout
    assert "hunt-idor" in out and "hunt-federation" in out
    assert "MANDATORY" not in out


def test_hunt_trigger_non_hunt_hard_trigger_unaffected_by_gate(vault):
    # non-hunt hard triggers (ingest, coverage, next-move, research, disclosure, nday,
    # ctf-*, screenshot) are not gated -- they keep firing MANDATORY unconditionally.
    out = run_hook("hunt-trigger.py", {"prompt": "ingest the recon dump"}, _env(vault)).stdout
    assert "Skill(ingest)" in out
    assert "Relevant skill" in out


def test_hunt_trigger_self_satisfying_keyword_still_gated(vault):
    # keywords that CONTAIN an intent verb (injection/bypass/smuggling/forgery/takeover/
    # poisoning) must not self-satisfy the gate: the intent verb must be in surrounding
    # prose, not the keyword span itself.
    env = _env(vault)
    for prose in ("the sql injection section of the report",
                  "the auth bypass finding is a dup",
                  "account takeover writeup for q2"):
        out = run_hook("hunt-trigger.py", {"prompt": prose}, env).stdout
        assert "MANDATORY" not in out, prose
    # with a real external intent verb, it fires hard
    out = run_hook("hunt-trigger.py", {"prompt": "test for sql injection on the login"}, env).stdout
    assert "Skill(hunt-sqli)" in out and "Relevant skill" in out


def test_hunt_trigger_cross_keyword_prose_does_not_fire(vault):
    # two vuln keywords in descriptive prose: one keyword's text must NOT satisfy the
    # OTHER's intent gate (both are masked before the intent search).
    env = _env(vault)
    for prose in ("cache poisoning and request smuggling are both discussed in this report",
                  "sql injection and oauth"):
        out = run_hook("hunt-trigger.py", {"prompt": prose}, env).stdout
        assert "MANDATORY" not in out, prose


def test_hunt_trigger_meta_prose_verbs_do_not_fire(vault):
    # narrowed intent set: common review/meta verbs (check/trigger/reach) near a keyword
    # must not force a MANDATORY load.
    env = _env(vault)
    for prose in ("can you check whether the ssrf section of the wiki is up to date",
                  "the trigger regex for ssrf looks fine to me",
                  "can we reach consensus on how the idor keyword should be phrased"):
        out = run_hook("hunt-trigger.py", {"prompt": prose}, env).stdout
        assert "MANDATORY" not in out, prose


def test_hunt_trigger_added_offensive_verbs_fire(vault):
    env = _env(vault)
    out = run_hook("hunt-trigger.py",
                   {"prompt": "spoof the saml response to get into the oauth flow"}, env).stdout
    assert "Skill(hunt-federation)" in out and "Relevant skill" in out


def test_hunt_trigger_screenshot_no_overfire(vault):
    env = _env(vault)
    # bare 'screenshot' in ordinary prose must NOT force the MANDATORY load
    miss = run_hook("hunt-trigger.py", {"prompt": "add a screenshot to the README"}, env).stdout
    assert "Skill(screenshot)" not in miss
    # explicit capture intent still fires
    hit = run_hook("hunt-trigger.py", {"prompt": "grab a screenshot of the dashboard"}, env).stdout
    assert "Skill(screenshot)" in hit


def test_hunt_trigger_walkthrough_close_out_keyword(vault):
    env = _env(vault)
    for prompt in ("write the walkthrough for this box",
                   "close out the box now",
                   "assemble the walkthrough"):
        out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
        assert "Skill(walkthrough)" in out, prompt


def test_hunt_trigger_ics_no_overfire_on_company_suffix(vault):
    env = _env(vault)
    # 'Plc' (UK company suffix) and '.ics' must NOT fire the MANDATORY hunt-ics load
    miss = run_hook("hunt-trigger.py",
                    {"prompt": "Acme Plc is in scope per the .ics invite"}, env).stdout
    assert "Skill(hunt-ics)" not in miss
    # an unambiguous OT term still fires
    hit = run_hook("hunt-trigger.py",
                   {"prompt": "enumerate the modbus holding register"}, env).stdout
    assert "Skill(hunt-ics)" in hit


def test_hunt_trigger_ignores_keyword_in_fenced_code(vault):
    env = _env(vault)
    prompt = ("review this output\n```\ncurl 'http://x?url=http://169.254.169.254' # ssrf test\n"
              "```\nlooks fine")
    out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
    assert "Skill(hunt-ssrf)" not in out


def test_hunt_trigger_fires_on_prose_keyword(vault):
    env = _env(vault)
    out = run_hook("hunt-trigger.py", {"prompt": "check the api for ssrf via the redirect param"},
                   env).stdout
    assert "Skill(hunt-ssrf)" in out


def test_hunt_trigger_ignores_keyword_in_inline_code(vault):
    env = _env(vault)
    out = run_hook("hunt-trigger.py",
                   {"prompt": "does the string `ssrf` appear in this log line?"}, env).stdout
    assert "Skill(hunt-ssrf)" not in out


def test_hunt_trigger_mixed_prose_and_code_still_fires(vault):
    env = _env(vault)
    prompt = "hunt for ssrf here\n```\ngrep -i xss file\n```"
    out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
    assert "Skill(hunt-ssrf)" in out


def test_hunt_trigger_ignores_keyword_in_unclosed_fence(vault):
    env = _env(vault)
    prompt = "logs below\n```\nsome mcp tool poisoning output"
    out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
    assert "Skill(hunt-mcp)" not in out


def test_hunt_trigger_stray_midline_backticks_do_not_swallow_prose(vault):
    # a stray ``` mid-sentence is NOT a code block: the prose keyword after it must still fire
    env = _env(vault)
    prompt = "oops I typed ``` earlier, anyway check the api for ssrf via the redirect param"
    out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
    assert "Skill(hunt-ssrf)" in out


def test_recon_capture_silent_on_non_recon(vault):
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}, _env(vault)).stdout
    assert out.strip() == ""


def test_recon_capture_ignores_non_bash(vault):
    out = run_hook("recon-capture.py",
                   {"tool_name": "Read", "tool_input": {"file_path": "x"}}, _env(vault)).stdout
    assert out.strip() == ""


def test_recon_capture_malformed_exits_zero(vault):
    p = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                       input="garbage", capture_output=True, text=True,
                       env=_env(vault), timeout=20)
    assert p.returncode == 0


def test_recon_capture_ignores_quoted_tool_alternation(vault):
    # a grep alternation like 'certipy|kerbrute' must NOT be read as invoking those tools:
    # invokes() split on the quoted '|' and matched each name -> phantom .pending-capture
    # markers that made the loop-driver nag "kerbrute ran" (the recurring false-fire).
    cmd = "for f in a b; do grep -oiE '\\b(certipy|kerbrute|secretsdump)\\b' \"$f\"; done"
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": cmd}}, _env(vault)).stdout
    assert "kerbrute" not in out and "certipy" not in out          # no capture nudge fired
    assert not os.path.isfile(str(vault / "targets" / "acme" / ".pending-capture"))  # no marker


def test_engagement_init_reports_state(vault):
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "acme" in out
    assert "Recent engagement log" in out  # surfaces private log


def test_engagement_init_surfaces_tunnel_safe(vault):
    (vault / "targets" / "acme" / "scope.md").write_text(
        "---\ntype: engagement-scope\ntunnel_safe: true\n---\n\n"
        "# Scope\n\n## In scope\n- 10.0.0.5\n", encoding="utf-8")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "tunnel_safe: curl+nc only (scanners kill the pivot)" in out


def test_engagement_init_silent_when_tunnel_safe_unset(vault):
    (vault / "targets" / "acme" / "scope.md").write_text(
        "---\ntype: engagement-scope\ntunnel_safe: false\n---\n\n"
        "# Scope\n\n## In scope\n- 10.0.0.5\n", encoding="utf-8")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "tunnel_safe: curl+nc only" not in out


def _import_recon_capture():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "recon_capture", os.path.join(HOOKS, "recon-capture.py"))
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    return rc


def test_inner_cmds_extracts_vm_sh_wrapper():
    rc = _import_recon_capture()
    assert rc.inner_cmds("bash /root/vm.sh 'nmap -sV 10.0.0.5'") == ["nmap -sV 10.0.0.5"]


def test_inner_cmds_extracts_ssh_wrapper():
    rc = _import_recon_capture()
    assert rc.inner_cmds("sshpass -p x ssh kali@host 'nuclei -u https://x'") == ["nuclei -u https://x"]


def test_inner_cmds_extracts_wsl_wrapper():
    rc = _import_recon_capture()
    inners = rc.inner_cmds("wsl -d kali -u kali -- gobuster dir -u http://x")
    assert "gobuster dir -u http://x" in inners


def test_inner_cmds_empty_when_no_wrapper():
    rc = _import_recon_capture()
    assert rc.inner_cmds("nmap -sV x") == []


def test_inner_cmds_ignores_quoted_mention_not_at_command_position():
    # false positive guard: a vm.sh mention quoted inside an unrelated command's
    # argument (here, an echo string) must NOT be extracted -- vm.sh was never invoked.
    rc = _import_recon_capture()
    assert rc.inner_cmds("df -h; echo \"use vm.sh 'nmap -sV 10.0.0.5' for scanning\"") == []


def test_inner_cmds_extracts_vm_sh_wrapper_through_sudo():
    # command-position still works after peeling a leading sudo wrapper.
    rc = _import_recon_capture()
    assert rc.inner_cmds("sudo bash /root/vm.sh 'nmap -sV x'") == ["nmap -sV x"]


def test_inner_cmds_extracts_wsl_wrapper_multiline():
    # MULTILINE false-negative fix: wsl ... -- cmd followed by a newline + more text
    # must still extract the inner command (previously relied on `$` without re.MULTILINE).
    rc = _import_recon_capture()
    inners = rc.inner_cmds("wsl -d kali -u kali -- gobuster dir -u http://x\necho done")
    assert "gobuster dir -u http://x" in inners


# ---- Area 1 (always-capture-evidence): inner_cmds() loop/exec-shape awareness ----

def test_inner_cmds_strips_loop_do_prefix():
    # a `do <wrapper>; done` loop body segment was previously blind (the "do " prefix
    # made the vm.sh re.match, anchored at segment start, fail) -- a curl inside a
    # for...do...done loop must still get unwrapped.
    rc = _import_recon_capture()
    cmd = "for i in 1 2; do bash /root/vm.sh 'curl -s http://10.10.10.10/flag'; done"
    assert "curl -s http://10.10.10.10/flag" in rc.inner_cmds(cmd)


def test_inner_cmds_strips_then_prefix():
    rc = _import_recon_capture()
    cmd = "if true; then bash /root/vm.sh 'nmap -sV 10.0.0.5'; fi"
    assert "nmap -sV 10.0.0.5" in rc.inner_cmds(cmd)


def test_inner_cmds_recurses_into_bash_c():
    # bash -c '<payload>' is the same bridge-wrapper problem as vm.sh/ssh/wsl: the real
    # work sits inside the quoted -c argument.
    rc = _import_recon_capture()
    assert "curl -s http://10.10.10.10/flag" in rc.inner_cmds(
        "bash -c 'curl -s http://10.10.10.10/flag'")


def test_inner_cmds_recurses_into_sh_c_nested_wrapper():
    # a wrapper NESTED inside a -c payload (vm.sh called from inside a sh -c body) must
    # also unwrap -- inner_cmds recurses into the extracted -c payload.
    rc = _import_recon_capture()
    inners = rc.inner_cmds("sh -c \"bash /root/vm.sh 'nuclei -u https://x'\"")
    assert "nuclei -u https://x" in inners


def test_inner_cmds_recurses_into_heredoc():
    rc = _import_recon_capture()
    cmd = "bash <<'EOF'\ncurl -s http://10.10.10.10/flag\nEOF"
    assert "curl -s http://10.10.10.10/flag" in rc.inner_cmds(cmd)


def test_inner_cmds_still_empty_for_plain_command():
    # regression guard: the widening must not spuriously invent inners for a plain command.
    rc = _import_recon_capture()
    assert rc.inner_cmds("nmap -sV x") == []
    assert rc.inner_cmds("python3 solve.py") == []


def test_invokes_detects_probe_tool_through_wrappers():
    rc = _import_recon_capture()
    for cmd in (
        "bash /root/vm.sh 'nmap -sV 10.0.0.5'",
        "sshpass -p x ssh kali@host 'nuclei -u https://x'",
        "wsl -d kali -u kali -- gobuster dir -u http://x",
    ):
        inners = rc.inner_cmds(cmd)
        hit = rc.invokes(cmd, rc.PROBE_TOOLS) or next(
            (m for ic in inners if (m := rc.invokes(ic, rc.PROBE_TOOLS))), None)
        assert hit is not None, cmd
    # must stay a non-match: tool name merely mentioned in a path, no wrapper syntax
    assert rc.invokes("ls /root/nuclei-templates", rc.PROBE_TOOLS) is None
    no_inners = rc.inner_cmds("ls /root/nuclei-templates")
    assert not any(rc.invokes(ic, rc.PROBE_TOOLS) for ic in no_inners)


def test_recon_capture_recognizes_added_natives():
    rc = _import_recon_capture()
    # discovery tools now fire the recon/state + fingerprint path
    for t in ("naabu -host x", "dnsx -l hosts", "katana -u https://x", "gau target.com",
              "amass enum -d x", "gowitness scan -f urls", "arjun -u https://x",
              "masscan -p1-65535 10.0.0.0/8"):
        assert rc.invokes(t, rc.RECON_TOOLS) is not None, t
        assert rc.invokes(t, rc.PROBE_TOOLS) is not None, t
    # testers fingerprint their output
    for t in ("sqlmap -u 'http://x?id=1'", "dalfox url https://x", "swaks --to a@b --server mx"):
        assert rc.invokes(t, rc.PROBE_TOOLS) is not None, t
    # secret scanners route to loot.md
    for t in ("trufflehog filesystem ./src", "gitleaks detect -s ."):
        assert rc.invokes(t, rc.CRED_TOOLS) is not None, t
    # a bare mention in a path arg is still not an invocation
    assert rc.invokes("ls /opt/katana/", rc.RECON_TOOLS) is None


def test_recon_capture_flips_oob_on_callback_via_grep_poll(vault):
    # OOB auto-correlation (a KEPT behavior): a waiting oob.md row flips to HIT when its
    # token appears in a command's output. Polling a saved OAST/Collaborator log with grep
    # (a doc-command) must still flip it -- OOB correlation runs BEFORE the doc-command skip.
    eng = vault / "targets" / "acme"
    token = "oastxyz9k"
    (eng / "oob.md").write_text(
        "---\ntype: engagement-oob\n---\n\n# OOB\n\n"
        "| token | sink | class | planted | status | source |\n"
        "|-------|------|-------|---------|--------|--------|\n"
        "| %s | http://t/?url= | ssrf | 2026-07-16 | waiting | |\n" % token,
        encoding="utf-8")
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "grep %s /tmp/collab.log" % token},
               "tool_response": "1.2.3.4 - - GET /%s HTTP/1.1 200" % token}
    out = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "OOB HIT auto-correlated" in out
    assert "HIT" in (eng / "oob.md").read_text()      # row flipped to HIT on disk


def test_recon_capture_oob_silent_without_callback(vault):
    # no token in the output -> row stays waiting, no OOB block emitted
    eng = vault / "targets" / "acme"
    (eng / "oob.md").write_text(
        "---\ntype: engagement-oob\n---\n\n# OOB\n\n"
        "| token | sink | class | planted | status | source |\n"
        "|-------|------|-------|---------|--------|--------|\n"
        "| tok12345 | http://t/?url= | ssrf | 2026-07-16 | waiting | |\n",
        encoding="utf-8")
    payload = {"tool_name": "Bash", "tool_input": {"command": "nmap -sV t"},
               "tool_response": "80/tcp open http"}
    out = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "OOB HIT" not in out
    assert "waiting" in (eng / "oob.md").read_text()   # unchanged


def _write_board(eng, weaponize_body):
    (eng / "killchain.md").write_text(
        "---\ntype: engagement-killchain\n---\n\n# Board\n\n"
        "## 1. Recon\n- [x] nmap\n\n"
        "## 2. Weaponize\n" + weaponize_body + "\n\n"
        "## 3. Deliver\n- [ ] shell\n", encoding="utf-8")


def test_gate1_nudges_on_exploit_before_weaponize(vault):
    # exploit tool + Weaponize all [ ] -> GATE 1 nudge fires once, marker written
    eng = vault / "targets" / "acme"
    _write_board(eng, "- [ ] searchsploit + wiki CVE lookup\n- [ ] pick payload")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "sqlmap -u http://t/?id=1 --batch"},
                    "tool_response": "sqlmap testing"}, _env(vault)).stdout
    assert "GATE 1" in out and "Weaponize" in out
    assert (eng / ".gate1-nudged").exists()


def test_gate1_silent_when_weaponize_started(vault):
    eng = vault / "targets" / "acme"
    _write_board(eng, "- [~] searchsploit + wiki CVE lookup\n- [ ] pick payload")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "hydra -l admin -P rock ssh://t"},
                    "tool_response": "x"}, _env(vault)).stdout
    assert "GATE 1" not in out


def test_gate1_silent_on_recon_command(vault):
    # a recon tool is not exploitation -> no GATE 1 nudge even with Weaponize undone
    eng = vault / "targets" / "acme"
    _write_board(eng, "- [ ] searchsploit + wiki CVE lookup")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "nmap -sV t"},
                    "tool_response": "80 open"}, _env(vault)).stdout
    assert "GATE 1" not in out


def test_gate1_fires_once(vault):
    eng = vault / "targets" / "acme"
    _write_board(eng, "- [ ] searchsploit")
    (eng / ".gate1-nudged").write_text("")   # already nudged this engagement
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "sqlmap -u http://t --batch"},
                    "tool_response": "x"}, _env(vault)).stdout
    assert "GATE 1" not in out


def test_close_out_nudges_walkthrough_when_solved_stale(vault):
    # SOLVED state + no walkthrough.md (stale) -> Stop hook nudges to run walkthrough
    eng = vault / "targets" / "acme"
    (eng / "state.md").write_text(
        (eng / "state.md").read_text() + "\n## STATUS: SOLVED\n", encoding="utf-8")
    out = run_hook("close-out.py", {}, _env(vault)).stdout
    assert "Close-out" in out and "walkthrough" in out.lower()


def test_close_out_silent_when_not_solved(vault):
    out = run_hook("close-out.py", {}, _env(vault)).stdout
    assert out.strip() == ""


def test_close_out_nudges_learn_when_walkthrough_done(vault):
    # SOLVED + a real (non-stale) walkthrough + no .learn-done -> nudge to run learn
    eng = vault / "targets" / "acme"
    (eng / "state.md").write_text(
        (eng / "state.md").read_text() + "\n## STATUS: SOLVED\n", encoding="utf-8")
    (eng / "walkthrough.md").write_text(
        "# Walkthrough - acme\n\n## 1. Recon\nran nmap, found ssh + web\n\n"
        "## Evidence\n| shot | caption |\n|------|---------|\n| ![](poc/01.png) | login |\n",
        encoding="utf-8")
    out = run_hook("close-out.py", {}, _env(vault)).stdout
    assert "Close-out" in out and "learn" in out.lower()


def test_engagement_init_surfaces_wiki_candidates(vault):
    inbox = vault / "targets" / "acme" / "wiki-candidates"
    inbox.mkdir()
    (inbox / "foo-default.md").write_text(
        "---\ntarget_page: cheatsheets/default-credentials.md\nkind: default-cred\n"
        "slug: foo-default\nsource_eng: acme\ndate: 2026-07-06\nstatus: pending\n---\n\n"
        "| Foo | any | admin | admin | vendor | x |\n", encoding="utf-8")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    # collapsed into the one-line `harness:` maintenance summary
    assert "harness:" in out
    assert "wiki-candidates:1" in out
    assert "wiki-promote.py --list" in out


def test_engagement_init_silent_no_wiki_candidates(vault):
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "wiki-candidates" not in out


def test_engagement_init_counts_candidate_with_extra_spacing(vault):
    # FIX 1: 'status:  pending' (two spaces) must still count as pending.
    # wiki_candidate_count must PARSE frontmatter (via _engagement._frontmatter,
    # the same tolerant parser wiki-promote.py's pending-detection uses) instead
    # of a raw "status: pending" (single-space) substring match, which silently
    # undercounts a promotable candidate at SessionStart.
    inbox = vault / "targets" / "acme" / "wiki-candidates"
    inbox.mkdir()
    (inbox / "foo-default.md").write_text(
        "---\ntarget_page: cheatsheets/default-credentials.md\nkind: default-cred\n"
        "slug: foo-default\nsource_eng: acme\ndate: 2026-07-06\nstatus:  pending\n---\n\n"
        "| Foo | any | admin | admin | vendor | x |\n", encoding="utf-8")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "wiki-candidates:1" in out


def test_scope_guard_drops_deadend_arm():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "skills", "hooks", "scope-guard.py"), encoding="utf-8").read()
    assert "Deadends" not in src
    assert "deadend_hits" not in src
    assert "DEAD-END" not in src


def test_fingerprint_hits_is_routing_only():
    import os, re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "skills", "hooks", "recon-capture.py"), encoding="utf-8").read()
    body = re.search(r"def fingerprint_hits\(blob\):.*?\n    return out\n", src, re.S).group(0)
    for banned in ("try {tests}", "don't hand-roll", "arsenal: consult", "reuse: ", "tools: lean on"):
        assert banned not in body, banned
    assert "Skill(%s)" in body and "detected" in body


