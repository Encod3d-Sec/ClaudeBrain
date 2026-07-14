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


def test_recon_capture_nudges_when_stale(vault):
    # make state.md old so it counts as stale
    old = time.time() - 9999
    os.utime(str(vault / "targets" / "acme" / "state.md"), (old, old))
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "nmap -sV 10.0.0.0/24"}},
                   _env(vault)).stdout
    assert "ingest" in out and "nmap" in out


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


def test_recon_capture_ssrf_sink_fires(vault):
    cmd = 'curl -s "http://10.50.0.1/preview.php?url=http://127.0.0.1/"'
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": cmd}}, _env(vault)).stdout
    assert "SSRF sink detected" in out
    assert "seq 1 65535" in out and "127.0.0.1:$P" in out   # templated internal sweep
    assert "T=10.50.0.1;" in out                            # literal host inlined
    assert "gopher" in out and "Skill(hunt-ssrf)" in out


def test_recon_capture_ignores_quoted_tool_alternation(vault):
    # a grep alternation like 'certipy|kerbrute' must NOT be read as invoking those tools:
    # invokes() split on the quoted '|' and matched each name -> phantom .pending-capture
    # markers that made the loop-driver nag "kerbrute ran" (the recurring false-fire).
    cmd = "for f in a b; do grep -oiE '\\b(certipy|kerbrute|secretsdump)\\b' \"$f\"; done"
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": cmd}}, _env(vault)).stdout
    assert "kerbrute" not in out and "certipy" not in out          # no capture nudge fired
    assert not os.path.isfile(str(vault / "targets" / "acme" / ".pending-capture"))  # no marker


def test_recon_capture_ssrf_fires_inside_heredoc(vault):
    # the model's SSRF tests are often wrapped (SSH-to-VM driver) -> must still fire
    cmd = ("X=\"$(cat <<'PL'\nT=10.50.0.2\ncurl -s \"http://$T/preview.php?url=http://127.0.0.1/\"\n"
           "PL\n)\"\nbash /root/vm.sh \"$X\"")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": cmd}}, _env(vault)).stdout
    assert "SSRF sink detected" in out and "seq 1 65535" in out


def test_recon_capture_ssrf_silent_without_fetch(vault):
    # a sink URL merely mentioned, no curl/wget/requests -> not a real fetch -> silent
    cmd = "the sink is at preview.php?url=http://127.0.0.1/ somewhere in my notes"
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": cmd}}, _env(vault)).stdout
    assert "SSRF sink detected" not in out


def test_recon_capture_ssrf_dedup_per_sink(vault):
    payload = {"tool_name": "Bash",
               "tool_input": {"command": 'curl -s "http://10.50.0.3/preview.php?url=http://127.0.0.1/"'}}
    first = run_hook("recon-capture.py", payload, _env(vault)).stdout
    second = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "SSRF sink detected" in first
    assert "SSRF sink detected" not in second   # deduped via .ssrf-seen marker


def test_recon_capture_ssrf_passive_only_no_sweep(vault):
    # RoE passive_only -> surface the sink but NO active port sweep
    with open(os.path.join(str(vault), "targets", "acme", "scope.md"), "w") as f:
        f.write("---\ntype: engagement-scope\n---\n\n# Scope\n\npassive_only: true\n")
    cmd = 'curl -s "http://10.50.0.4/preview.php?url=http://127.0.0.1/"'
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": cmd}}, _env(vault)).stdout
    assert "SSRF sink detected" in out and "passive_only" in out
    assert "seq 1 65535" not in out             # no active sweep under passive RoE


def test_recon_capture_ssrf_no_fire_from_output_only(vault):
    # a sink URL present only in command OUTPUT (viewing ssrf.md / git show) must NOT fire
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "git show HEAD -- wiki/payloads/ssrf.md"},
               "tool_response": "example: curl -s 'http://t/preview.php?url=http://127.0.0.1/'"}
    out = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "SSRF sink detected" not in out


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


def test_recon_capture_stages_shot(tmp_path):
    # fixture setup mirrors conftest.py vault fixture: CLAUDEBRAIN_VAULT env var
    # passed to subprocess (OBSIDIAN_VAULT is not the var _engagement.py reads).
    eng = tmp_path / "targets" / "ENG"
    eng.mkdir(parents=True)
    (eng / "state.md").write_text("| host |\n|---|\n")
    (eng / "loot.md").write_text("| cred |\n|---|\n")
    (tmp_path / "targets" / "active.md").write_text("ENG\n")
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(tmp_path))
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "nmap -sV 10.10.10.10"},
               "tool_response": {"stdout": "22/tcp open ssh\n80/tcp open http\n"}}
    subprocess.run(
        ["python3", os.path.join(HOOKS, "recon-capture.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "recon" / ".pending"
    files = list(pend.glob("*-nmap-*.txt"))
    assert len(files) == 1
    body = files[0].read_text()
    assert "22/tcp open ssh" in body
    assert '{"stdout"' not in body        # raw terminal text, not JSON-wrapped
    # dedup: identical re-run must NOT add a second file (content-hash check)
    subprocess.run(
        ["python3", os.path.join(HOOKS, "recon-capture.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list(pend.glob("*-nmap-*.txt"))) == 1


def _import_recon_capture():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "recon_capture", os.path.join(HOOKS, "recon-capture.py"))
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    return rc


def test_shot_tool_matcher_direct():
    rc = _import_recon_capture()
    def tool(c):
        r = rc._shot_tool(c)
        return r[0] if r else None
    assert tool("./linpeas.sh") == "linpeas"
    assert tool("pspy64") == "pspy"
    assert tool("bash vm.sh 'nmap -sV t'") == "nmap"
    assert tool("ls /root/nuclei-templates") is None   # tool as path arg, not invoked
    assert tool("cat notes.txt") is None
    # command-position: a mere MENTION must NOT match (the double-fire fix)
    assert tool("for i in $(seq 1 5); do grep -q NMAP-DONE /tmp/x; done") is None
    assert tool("cd /opt/nmap-scripts && echo done") is None
    assert tool("grep -E 'a|nmap|b' file.txt") is None          # quoted alternation
    # title = the actual tool command segment, not the batch's first (cd) line
    r = rc._shot_tool("cd /tmp; bash /root/vm.sh 'whatweb http://t/'")
    assert r and r[0] == "whatweb" and "whatweb http://t/" in r[1]


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


def test_payload_page_maps_skill_to_arsenal_file():
    rc = _import_recon_capture()
    assert rc._payload_page("hunt-sqli") == os.path.join("wiki", "payloads", "sqli.md")
    assert rc._payload_page("hunt-auth").endswith("auth-bypass.md")
    assert rc._payload_page("hunt-rce").endswith("command-injection.md")
    assert rc._payload_page("hunt-secrets") is None   # no wiki/payloads/secrets.md


def test_tool_page_maps_tool_to_wiki_page():
    rc = _import_recon_capture()
    assert rc._tool_page("ffuf").endswith("ffuf.md")
    assert rc._tool_page("nmap").endswith("nmap.md")
    assert rc._tool_page("definitelynotatool") is None


def test_label_payload_pages_exact_match():
    rc = _import_recon_capture()
    assert rc._label_payload_pages("graphql") == [os.path.join("wiki", "payloads", "graphql.md")]


def test_label_payload_pages_contains_jwt():
    rc = _import_recon_capture()
    assert os.path.join("wiki", "payloads", "jwt.md") in rc._label_payload_pages("jwt")


def test_label_payload_pages_no_match():
    rc = _import_recon_capture()
    # no wiki/payloads/linux.md or wiki/payloads/type.md
    assert rc._label_payload_pages("linux") == []
    assert rc._label_payload_pages("type") == []


def test_recon_capture_nudge_fires_through_vm_sh_wrapper(vault):
    # end-to-end proof of the wrapper-unwrap fix: before it, a wrapped nmap call
    # was BLIND to is_recon (invokes() only checks command position) and never
    # nudged capture. The fixture vault doesn't ship scripts/playbook.json, so
    # this exercises the is_recon/capture-nudge path rather than fingerprint_hits
    # (see brief: unit-level is_probe coverage above is the required proof for
    # the fingerprint router itself).
    old = time.time() - 9999
    os.utime(str(vault / "targets" / "acme" / "state.md"), (old, old))
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash",
                    "tool_input": {"command": "bash /root/vm.sh 'nmap -sV 10.0.0.0/24'"}},
                   _env(vault)).stdout
    assert "ingest" in out and "nmap" in out


def _setup_eng(tmp_path):
    """Minimal vault + engagement for shot-staging subprocess tests."""
    eng = tmp_path / "targets" / "ENG"
    eng.mkdir(parents=True)
    (eng / "state.md").write_text("| host |\n|---|\n")
    (eng / "loot.md").write_text("| cred |\n|---|\n")
    (tmp_path / "targets" / "active.md").write_text("ENG\n")
    return eng


def test_shot_tool_linpeas_stages(tmp_path):
    """./linpeas.sh is NOT a recon/cred tool -- proves the hoist (Fix 1c)."""
    eng = _setup_eng(tmp_path)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(tmp_path))
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "./linpeas.sh"},
               "tool_response": {"stdout": "linpeas output: SUID bit found\n"}}
    subprocess.run(
        ["python3", os.path.join(HOOKS, "recon-capture.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "recon" / ".pending"
    files = list(pend.glob("*-linpeas-*.txt"))
    assert len(files) == 1


def test_shot_tool_wrapped_nmap_stages(tmp_path):
    """bash /root/vm.sh 'nmap ...' wrapper -- proves wrapper tolerance (Fix 1a)."""
    eng = _setup_eng(tmp_path)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(tmp_path))
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "bash /root/vm.sh 'nmap -sV 10.10.10.10'"},
               "tool_response": {"stdout": "22/tcp open ssh\n80/tcp open http\n"}}
    subprocess.run(
        ["python3", os.path.join(HOOKS, "recon-capture.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "recon" / ".pending"
    files = list(pend.glob("*-nmap-*.txt"))
    assert len(files) == 1


def test_shot_tool_non_tool_no_stage(tmp_path):
    """A plain ls command must NOT stage anything."""
    eng = _setup_eng(tmp_path)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(tmp_path))
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "ls -la /tmp"},
               "tool_response": {"stdout": "total 0\n"}}
    subprocess.run(
        ["python3", os.path.join(HOOKS, "recon-capture.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "recon" / ".pending"
    # no .pending dir created at all, or dir exists but no digit-prefixed .txt
    pending_txts = list(pend.glob("[0-9]*.txt")) if pend.exists() else []
    assert len(pending_txts) == 0


# ---- .pending-capture over-fire guard (marker gates on INVOCATION, never output text) ----


def _run_capture_marker(vault_root, cmd, stdout):
    """Set up a fresh isolated engagement under vault_root, fire recon-capture.py with
    (cmd, stdout), and return the .pending-capture marker text ('' if none written)."""
    eng = vault_root / "targets" / "ENG"
    eng.mkdir(parents=True)
    (eng / "state.md").write_text("| host |\n|---|\n")
    (eng / "loot.md").write_text("| cred |\n|---|\n")
    (vault_root / "targets" / "active.md").write_text("ENG\n")
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault_root))
    payload = {"tool_name": "Bash", "tool_input": {"command": cmd},
               "tool_response": {"stdout": stdout}}
    subprocess.run(
        ["python3", os.path.join(HOOKS, "recon-capture.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env)
    mp = eng / ".pending-capture"
    return mp.read_text() if mp.exists() else ""


def test_gui_capture_guidance_fires_on_burp():
    rc = _import_recon_capture()
    g = rc.gui_capture_guidance("bash /root/vm.sh 'burpsuite &'")
    assert g and "--window" in g[0] and "Burp Suite" in g[0]
    # shot.py needs -o PATH (or --step+--slug); --slug alone errors out. Lock the -o form.
    assert "-o /tmp/poc/burpsuite.png" in g[0]


def test_gui_capture_guidance_silent_on_cli():
    rc = _import_recon_capture()
    assert rc.gui_capture_guidance("nmap -sV 10.10.10.10") == []
    assert rc.gui_capture_guidance("ls /opt/burpsuite") == []   # path mention, not a launch


def test_tmux_capture_guidance_fires_on_vmscan():
    rc = _import_recon_capture()
    g = rc.tmux_capture_guidance("bash scripts/vm-scan.sh acme 10.10.10.10 'nmap -sV -Pn 10.10.10.10'")
    # sanitized tab name: dots -> - ; nudge points at --tmux <session>:<name>
    assert g and "--tmux acme:10-10-10-10" in g[0]
    # valid shot.py invocation: -o PATH, not --slug-alone (which errors "need -o PATH")
    assert "-o /tmp/poc/10-10-10-10.png" in g[0]


def test_tmux_capture_guidance_silent_otherwise():
    rc = _import_recon_capture()
    assert rc.tmux_capture_guidance("nmap -sV 10.10.10.10") == []
    # must NOT fire on a mere MENTION of vm-scan.sh (the misfire class) -- syntax check / read / grep
    assert rc.tmux_capture_guidance("bash -n scripts/vm-scan.sh && echo ok") == []
    assert rc.tmux_capture_guidance("cat scripts/vm-scan.sh") == []
    assert rc.tmux_capture_guidance("grep -n foo scripts/vm-scan.sh") == []
    # a real launch after a && still fires
    g = rc.tmux_capture_guidance("cd /x && bash scripts/vm-scan.sh eng 10.0.0.9 'nmap -sV 10.0.0.9'")
    assert g and "--tmux eng:10-0-0-9" in g[0]


def test_recon_capture_emits_tmux_nudge_and_skips_stage(tmp_path):
    """A vm-scan.sh launch: nudge the live-pane grab, and do NOT stage the launcher
    echo as a --term card (the real output is in the tmux pane, not this stdout)."""
    eng = _setup_eng(tmp_path)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(tmp_path))
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "bash scripts/vm-scan.sh ENG 10.10.10.10 'nmap -sV 10.10.10.10'"},
               "tool_response": {"stdout": "window=@2 name=10-10-10-10 session=ENG\n"}}
    r = subprocess.run(
        ["python3", os.path.join(HOOKS, "recon-capture.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert "--tmux ENG:10-10-10-10" in r.stdout        # live-pane grab nudged
    pend = eng / "recon" / ".pending"
    staged = list(pend.glob("[0-9]*.txt")) if pend.exists() else []
    assert staged == []                                 # launcher echo not carded


def test_recon_capture_emits_gui_nudge(tmp_path):
    eng = _setup_eng(tmp_path)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(tmp_path))
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "bash /root/vm.sh 'burpsuite &'"},
               "tool_response": {"stdout": ""}}
    r = subprocess.run(
        ["python3", os.path.join(HOOKS, "recon-capture.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert "--window" in r.stdout and "Burp Suite" in r.stdout


# --- lead auto-capture (request/response cards) -----------------------------

def _eng_vault(tmp_path):
    """Minimal active-engagement vault for the subprocess hook; returns (eng_dir, env)."""
    eng = tmp_path / "targets" / "ENG"
    eng.mkdir(parents=True)
    (eng / "state.md").write_text("| host |\n|---|\n")
    (eng / "loot.md").write_text("| cred |\n|---|\n")
    (tmp_path / "targets" / "active.md").write_text("ENG\n")
    return eng, dict(os.environ, CLAUDEBRAIN_VAULT=str(tmp_path))


def test_is_lead_matcher():
    rc = _import_recon_capture()
    assert rc.is_lead("THM{flag}")
    assert rc.is_lead('{"flag":"THM{x}"}')
    assert rc.is_lead("username=a&password=supersecret")
    assert rc.is_lead('"private_key":"0x6f1807cbd93720a61193b69816ca3a603b"')  # leaked wallet key
    assert rc.is_lead('mnemonic: "abandon abandon abandon"')
    assert rc.is_lead("-----BEGIN RSA PRIVATE KEY-----")
    assert rc.is_lead("<?php system($_GET[0]); ?>")
    assert rc.is_lead("<title>Index of /backup</title>")
    # must NOT fire on a login FORM, a 404, or plain html (the false-fire guards)
    assert not rc.is_lead('<input name="password" type="password">')
    assert not rc.is_lead("<title>404 Not Found</title>")
    assert not rc.is_lead("just a normal landing page")
    assert not rc.is_lead("")


def test_recon_capture_stages_lead_card(tmp_path):
    # a curl (through the vm.sh wrapper) whose response carries a flag -> a lead card staged
    # under poc/leads/.pending, showing BOTH the request and the response, + a nudge.
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "bash /root/vm.sh 'curl -s https://10.10.10.10:5000/login -d x=1'"},
               "tool_response": {"stdout": "result= Flag1: THM{abc.def}\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    pend = eng / "poc" / "leads" / ".pending"
    files = list(pend.glob("*-lead-*.txt"))
    assert len(files) == 1
    body = files[0].read_text()
    assert "THM{abc.def}" in body                                   # response captured
    assert "curl -s https://10.10.10.10:5000/login" in body        # request captured
    assert "LEAD auto-captured" in out                             # nudge emitted
    assert "reqshot" in out                                        # plain curl -> reqshot nudge
    # dedup: identical re-run adds no second card
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list(pend.glob("*-lead-*.txt"))) == 1


def test_recon_capture_no_lead_card_on_boring_response(tmp_path):
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s https://10.10.10.10/"},
               "tool_response": {"stdout": "<html><title>Welcome</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "leads" / ".pending"
    assert not pend.exists() or not list(pend.glob("*-lead-*.txt"))


def test_recon_capture_lead_with_iv_skips_reqshot_nudge(tmp_path):
    # a curl already run with -iv has the full request/response -> no "re-run via reqshot" nudge
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -sS -iv https://10.10.10.10/secret"},
               "tool_response": {"stdout": "< HTTP/1.1 200\npassword=hunter2\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "LEAD auto-captured" in out
    assert "reqshot" not in out
    assert list((eng / "poc" / "leads" / ".pending").glob("*-lead-*.txt"))


# ---- Area 1: code-exec shapes no longer blind the lead/recon path ----

def test_recon_capture_lead_inside_bash_c_now_captured(tmp_path):
    # bash -c '<curl>' previously hit the early-return gate (blind spot) -- now it falls
    # through into the same tool-test + lead-capture pipeline as a direct curl.
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "bash -c 'curl -s https://10.10.10.10/flag'"},
               "tool_response": {"stdout": "THM{bash_c_flag}\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "LEAD auto-captured" in out
    pend = eng / "poc" / "leads" / ".pending"
    files = list(pend.glob("*-lead-*.txt"))
    assert len(files) == 1
    assert "THM{bash_c_flag}" in files[0].read_text()


def test_recon_capture_lead_inside_loop_now_captured(tmp_path):
    # a curl wrapped in vm.sh, inside a for...do...done loop body -- previously blind
    # because inner_cmds() failed on the "do " prefixed segment.
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "for i in 1; do bash /root/vm.sh 'curl -s https://10.10.10.10/flag'; done"},
               "tool_response": {"stdout": "THM{loop_flag}\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "LEAD auto-captured" in out
    pend = eng / "poc" / "leads" / ".pending"
    assert list(pend.glob("*-lead-*.txt"))


def test_recon_capture_doc_commands_still_suppressed(tmp_path):
    # the split gate must keep suppressing pure documentation commands even after the
    # code-exec shapes stopped early-returning.
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "cat nmap-results.txt"},
               "tool_response": {"stdout": "THM{should_not_fire}\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert out.strip() == ""
    assert not (eng / "poc" / "leads" / ".pending").exists()


# ---- Task 5: a ;/| inside a wrapper's quoted arg must not shred inner_cmds() ----------
# Root cause: inner_cmds() split the RAW command on ;/|/&&/||/newline BEFORE its vm.sh/
# ssh/wsl wrapper regexes ran, so a quoted wrapper arg containing its OWN ;/| (a leading
# assignment + a piped curl|grep, both routine in exploitation one-liners) got shredded
# across bogus segments and the wrapper regex never saw the whole quoted arg -> [].

def test_recon_capture_wrapped_piped_curl_with_semicolon_lead_now_captured(tmp_path):
    # bash /root/vm.sh 'C="..."; curl ... | grep ...' -- a leading shell assignment and a
    # pipe INSIDE the vm.sh wrapper's single-quoted arg. Before the fix, inner_cmds() raw-
    # split on the inner ; and | first, shredding the quoted arg so the vm.sh regex never
    # matched -> inner_cmds() == [] -> no curl recognized -> no lead card staged, even
    # though the final stdout still carried a flag.
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "bash /root/vm.sh 'C=\"PHPSESSID=x\"; curl -s -b \"$C\" "
                   "http://10.0.0.9/dashboard.php | grep -oiE \"THM.[^}]+.\" '"},
               "tool_response": {"stdout": "THM{synthetic_flag}\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    pend = eng / "poc" / "leads" / ".pending"
    files = list(pend.glob("*-lead-*.txt"))
    assert len(files) == 1, "expected exactly one poc/leads card staged, found %r" % files
    body = files[0].read_text()
    assert "THM{synthetic_flag}" in body
    assert "LEAD auto-captured" in out


def test_recon_capture_wrapped_piped_curl_boring_response_no_card(tmp_path):
    # same wrapped+chained shape (assignment ; curl | grep) but the final stdout carries
    # no lead signal -> still no card. Locks the boundary so the fix does not over-fire.
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "bash /root/vm.sh 'C=\"PHPSESSID=x\"; curl -s -b \"$C\" "
                   "http://10.0.0.9/dashboard.php | grep -oiE \"Welcome\" '"},
               "tool_response": {"stdout": "Welcome back\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "leads" / ".pending"
    assert not pend.exists() or not list(pend.glob("*-lead-*.txt"))


# ---- Area 1: lead-net broadened beyond curl/wget to any probe/exec tool + listeners ----

def test_is_listener_matcher():
    rc = _import_recon_capture()
    assert rc.is_listener("nc -lvnp 4444")
    assert rc.is_listener("ncat -lvp 4444")
    assert rc.is_listener("python3 -m http.server 8000")
    assert rc.is_listener("socat TCP-LISTEN:4444 -")
    assert not rc.is_listener("nc 10.0.0.1 4444")      # outbound client, not a listener
    assert not rc.is_listener("nmap -sV 10.0.0.1")
    assert not rc.is_listener("")


def test_recon_capture_listener_stdout_lead_stages_card(tmp_path):
    # a flag/cookie landing on a LISTENER's stdout (not a curl response) must still card --
    # this is the exact thm_sequence failure mode (XSS beacon -> nc listener).
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "nc -lvnp 4444"},
               "tool_response": {"stdout": "connect from victim\nTHM{listener_flag}\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "LEAD auto-captured" in out
    pend = eng / "poc" / "leads" / ".pending"
    files = list(pend.glob("*-lead-*.txt"))
    assert len(files) == 1
    assert "nc -lvnp 4444" in files[0].read_text()


def test_recon_capture_http_server_stdout_lead_stages_card(tmp_path):
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "python3 -m http.server 8000"},
               "tool_response": {"stdout": "GET /?token=THM{server_flag} 200\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "LEAD auto-captured" in out
    pend = eng / "poc" / "leads" / ".pending"
    assert list(pend.glob("*-lead-*.txt"))


def test_recon_capture_probe_tool_stdout_lead_stages_card(tmp_path):
    # a lead landing on a non-curl PROBE_TOOLS command's stdout (e.g. nuclei) must also card.
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "nuclei -u https://10.10.10.10 -t exposures"},
               "tool_response": {"stdout": "[exposure] AKIAABCDEFGHIJKLMNOP found\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "LEAD auto-captured" in out


def test_stage_req_resp_falls_back_to_tool_line_for_non_curl_lead():
    rc = _import_recon_capture()
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = rc.stage_req_resp("nc -lvnp 4444", "connect!\nTHM{x}\n", d)
        assert p and os.path.isfile(p)
        body = open(p, encoding="utf-8").read()
        assert "nc -lvnp 4444" in body and "THM{x}" in body


# ---- FIX 2 (live-lead-capture): sqlmap (a real win) never became a lead card at all --

def test_lead_request_context_returns_sqlmap_line():
    # unit-style: a sqlmap win piped to grep, wrapped in the vm.sh bridge -- previously
    # _lead_request_context() returned None for this (sqlmap is not curl/wget, not a
    # _SHOT_NET_TOOLS scanner, not a listener), so the flag never became a card.
    rc = _import_recon_capture()
    cmd = ("bash /root/vm.sh 'sqlmap -u http://10.0.0.9/index.php?id=1 --batch --dump-all "
           '| grep -oE "flag\\{[^}]*\\}"\'')
    ctx = rc._lead_request_context(cmd)
    assert ctx is not None
    assert "sqlmap -u http://10.0.0.9/index.php?id=1" in ctx


def test_recon_capture_sqlmap_lead_now_staged(tmp_path):
    # subprocess, VM absent (conftest forces VM_SH nonexistent): a sqlmap command whose
    # stdout carries flag{synthetic} + an active engagement -> a poc/leads/.pending card
    # is staged. Before FIX 2a this was NOT staged (_lead_request_context returned None
    # for sqlmap) -- the exact live-box gap this branch fixes.
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "bash /root/vm.sh 'sqlmap -u http://10.0.0.9/index.php?id=1 --batch "
                   "--dump-all | grep -oE \"flag\\{[^}]*\\}\"'"},
               "tool_response": {"stdout": "[INFO] flag{synthetic}\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True,
                         env=env, timeout=30)
    assert out.returncode == 0                             # fail-open: never crashes
    pend = eng / "poc" / "leads" / ".pending"
    files = list(pend.glob("*-lead-*.txt"))
    assert len(files) == 1, "expected exactly one poc/leads card staged, found %r" % files
    body = files[0].read_text()
    assert "flag{synthetic}" in body
    assert "sqlmap -u http://10.0.0.9/index.php?id=1" in body
    assert "LEAD auto-captured" in out.stdout
    # the synchronous render was attempted and failed open (VM absent) -- the .txt is
    # still here for the (now-fixed) Stop-drain to pick up, not deleted/crashed.
    assert files[0].exists()


def test_recon_capture_sqlmap_lead_render_fail_open_exits_zero(tmp_path):
    # explicit fail-open check: the live synchronous render (loop-driver.py --drain)
    # must never crash or hang this PostToolUse hook even when it cannot reach a VM.
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "sqlmap -u http://10.0.0.9/id.php?id=1 --batch --dump"},
               "tool_response": {"stdout": "flag{synthetic}\n"}}
    result = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                            input=json.dumps(payload), text=True, capture_output=True,
                            env=env, timeout=30)
    assert result.returncode == 0
    pend = eng / "poc" / "leads" / ".pending"
    assert list(pend.glob("*-lead-*.txt"))                  # .txt remains staged


def test_recon_capture_probe_tool_lead_now_cardable_after_fix_2a(tmp_path):
    # FIX 2a (live-lead-capture): dig is a PROBE_TOOLS member outside the curl/wget/
    # _shot_tool/listener nets -- before the fix, _lead_request_context() returned None
    # for it, so stage_req_resp() could build no card. The broadened final fallback in
    # _lead_request_context() (any PROBE_TOOLS/CRED_TOOLS invocation) now gives it a
    # request-context line, so it gets a real poc/leads card. This is the same class of
    # gap that let a real sqlmap flag{...} win go un-cardable (see the sqlmap tests below).
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "dig TXT flag.example.com"},
               "tool_response": {"stdout": 'flag.example.com. 300 IN TXT "THM{dns_flag}"\n'}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "LEAD auto-captured" in out
    pend = eng / "poc" / "leads" / ".pending"
    files = list(pend.glob("*-lead-*.txt"))
    assert len(files) == 1
    body = files[0].read_text()
    assert "THM{dns_flag}" in body
    assert "dig TXT flag.example.com" in body


def test_lead_request_context_none_for_wholly_unrecognized_command():
    # A command that invokes NOTHING recognizable at all (no curl/wget, no _shot_tool
    # scanner, no listener, no PROBE_TOOLS/CRED_TOOLS member) -- _lead_request_context()
    # must still return None here, proving the broadened fallback did not turn into a
    # blanket "always cardable".
    rc = _import_recon_capture()
    assert rc._lead_request_context("ls -la /tmp") is None
    assert rc._lead_request_context("./custom_exploit.py 10.0.0.9") is None


def test_loop_driver_drain_area_fail_open(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "loop_driver", os.path.join(HOOKS, "loop-driver.py"))
    ld = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ld)
    pend = tmp_path / "targets" / "ENG" / "poc" / "leads" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-lead-abcd1234.txt"
    staged.write_text("# curl x\n$ curl x\n\nTHM{y}")
    # no reachable VM -> returns [] without raising, staged txt preserved for a later Stop
    res = ld.drain_pending(str(tmp_path / "targets" / "ENG"),
                           vm="/nonexistent/vm.sh", area="poc/leads", reqresp=True)
    assert res == []
    assert staged.exists()


# --- wiki-stage nudge (advisory, generic-knowledge distillation) ------------

def test_recon_capture_wiki_nudge_on_cred(tmp_path):
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "secretsdump.py u@10.0.0.1"},
               "tool_response": {"stdout": "admin:500:aad3b435:hashhashhash:::\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "wiki-stage.py" in out and "default-cred" in out


def test_recon_capture_wiki_nudge_on_lead(tmp_path):
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s https://10.0.0.1/api/users"},
               "tool_response": {"stdout": "password=hunter2\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "wiki-stage.py" in out and "api-pattern" in out


def test_recon_capture_no_wiki_nudge_on_plain_recon(tmp_path):
    eng, env = _eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "nmap -sV 10.0.0.1"},
               "tool_response": {"stdout": "22/tcp open ssh\n"}}
    out = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                         input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
    assert "wiki-stage.py" not in out


def test_engagement_init_surfaces_wiki_candidates(vault):
    inbox = vault / "targets" / "acme" / "wiki-candidates"
    inbox.mkdir()
    (inbox / "foo-default.md").write_text(
        "---\ntarget_page: cheatsheets/default-credentials.md\nkind: default-cred\n"
        "slug: foo-default\nsource_eng: acme\ndate: 2026-07-06\nstatus: pending\n---\n\n"
        "| Foo | any | admin | admin | vendor | x |\n", encoding="utf-8")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "wiki-candidates: 1 pending" in out
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
    assert "wiki-candidates: 1 pending" in out


# --- per-host hand-curl repetition nudge ------------------------------------

def test_recon_capture_curl_repeat_nudges_at_threshold(tmp_path):
    # a one-off curl is fine; repeatedly hand-curling the SAME in-scope host is the real
    # "reimplementing httpx/ffuf" signal -> nudge at the 4th (CURL_REPEAT_THRESHOLD).
    eng, env = _eng_vault(tmp_path)
    (eng / "scope.md").write_text(
        "---\ntype: engagement-scope\ntunnel_safe: false\n---\n\n"
        "# Scope\n\n## In scope\n- 10.10.10.10\n", encoding="utf-8")
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s http://10.10.10.10/robots.txt"}}
    outs = []
    for _ in range(4):
        outs.append(subprocess.run(
            ["python3", os.path.join(HOOKS, "recon-capture.py")],
            input=json.dumps(payload), text=True, capture_output=True, env=env).stdout)
    assert all("hand-curled" not in o for o in outs[:3])          # first three silent
    assert "hand-curled 10.10.10.10 4 times" in outs[3]           # fourth crosses threshold
    assert "httpx" in outs[3] and "ffuf" in outs[3] and "nuclei" in outs[3]
    counts = json.loads((eng / ".curl-counts.json").read_text())
    assert counts["10.10.10.10"] == 4


def test_recon_capture_curl_repeat_suppressed_under_tunnel_safe(tmp_path):
    eng, env = _eng_vault(tmp_path)
    (eng / "scope.md").write_text(
        "---\ntype: engagement-scope\ntunnel_safe: true\n---\n\n"
        "# Scope\n\n## In scope\n- 10.10.10.10\n", encoding="utf-8")
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s http://10.10.10.10/robots.txt"}}
    outs = [subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
            input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
            for _ in range(5)]
    assert all("hand-curled" not in o for o in outs)   # tunnel_safe: curl is correct, never nag
    assert not (eng / ".curl-counts.json").exists()    # not even counted


def test_recon_capture_curl_repeat_only_counts_in_scope(tmp_path):
    eng, env = _eng_vault(tmp_path)
    (eng / "scope.md").write_text(
        "---\ntype: engagement-scope\n---\n\n# Scope\n\n## In scope\n- 10.10.10.10\n",
        encoding="utf-8")
    # a curl to a host NOT in scope must not be counted or nudged
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s http://8.8.8.8/"}}
    outs = [subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
            input=json.dumps(payload), text=True, capture_output=True, env=env).stdout
            for _ in range(5)]
    assert all("hand-curled" not in o for o in outs)
    assert not (eng / ".curl-counts.json").exists()


def test_recon_capture_curl_repeat_survives_non_numeric_stored_count(tmp_path):
    # a corrupted/non-numeric stored count (e.g. "banana") must not raise inside
    # _bump_curl_count -- it is treated as a fresh 0, so the new count becomes 1
    # (no nudge yet, since CURL_REPEAT_THRESHOLD is 4). Regression for a bug where
    # int(...) sat outside the function's try/except, contradicting its
    # "Best-effort; never raises" docstring and dropping every other advisory
    # block already computed in the same hook invocation.
    eng, env = _eng_vault(tmp_path)
    (eng / "scope.md").write_text(
        "---\ntype: engagement-scope\ntunnel_safe: false\n---\n\n"
        "# Scope\n\n## In scope\n- 10.10.10.10\n", encoding="utf-8")
    (eng / ".curl-counts.json").write_text(
        json.dumps({"10.10.10.10": "banana"}), encoding="utf-8")
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s http://10.10.10.10/robots.txt"}}
    p = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                       input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert p.returncode == 0
    assert "hand-curled" not in p.stdout           # not yet at CURL_REPEAT_THRESHOLD
    counts = json.loads((eng / ".curl-counts.json").read_text())
    assert counts["10.10.10.10"] == 1              # non-numeric stored value treated as fresh 0


# ---- ctf discipline nudge (fire-once, off-script exploitation via vm.sh) ----


def _ctf_eng_vault(tmp_path):
    """Minimal active CTF-engagement vault for the subprocess hook (frontmatter
    engagement_type: ctf so _engagement.engagement_type() resolves to 'ctf')."""
    eng = tmp_path / "targets" / "ENG"
    eng.mkdir(parents=True)
    (eng / "state.md").write_text(
        "---\ntype: engagement-state\nengagement_type: ctf\n---\n\n# State\n\n"
        "| host |\n|---|\n", encoding="utf-8")
    (eng / "loot.md").write_text("| cred |\n|---|\n", encoding="utf-8")
    (tmp_path / "targets" / "active.md").write_text("ENG\n", encoding="utf-8")
    return eng, dict(os.environ, CLAUDEBRAIN_VAULT=str(tmp_path))


def _run_discipline(env, cmd):
    payload = {"tool_name": "Bash", "tool_input": {"command": cmd}}
    return subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                          input=json.dumps(payload), text=True, capture_output=True,
                          env=env).stdout


def test_discipline_nudge_fires_on_raw_listener_ctf(tmp_path):
    eng, env = _ctf_eng_vault(tmp_path)
    out = _run_discipline(env, "bash /root/vm.sh 'nc -lvnp 9001'")
    assert "DISCIPLINE" in out
    assert "vm-scan.sh" in out
    assert "ctf-box" in out
    assert (eng / ".discipline-nudged").exists()


# ---- Task 3: auto website-state + source capture (poc/pages/) --------------

def _scoped_eng_vault(tmp_path, in_scope_host="10.0.0.9"):
    """_eng_vault + a scope.md that puts in_scope_host in scope (poc/pages gate)."""
    eng, env = _eng_vault(tmp_path)
    (eng / "scope.md").write_text(
        "---\ntype: engagement-scope\n---\n\n# Scope\n\n## In scope\n- %s\n" % in_scope_host,
        encoding="utf-8")
    return eng, env


def test_recon_capture_stages_page_card(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -i http://10.0.0.9/login"},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><head><title>Login</title></head><body></body></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    files = list(pend.glob("*-page-*.txt"))
    assert len(files) == 1
    body = files[0].read_text()
    assert "Login" in body
    assert "10.0.0.9/login" in body
    # dedup: identical re-run (same URL, same anon auth-state) adds no second card
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list(pend.glob("*-page-*.txt"))) == 1


def test_recon_capture_page_card_second_cookie_new_auth_state(tmp_path):
    # same path fetched with a DIFFERENT session cookie -> a second, distinct card;
    # re-fetching with the SAME cookie again stays deduped.
    eng, env = _scoped_eng_vault(tmp_path)
    html = ("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
            "<html><head><title>Dashboard</title></head></html>\n")
    payload_abc = {"tool_name": "Bash",
                   "tool_input": {"command": "curl -i -b 'PHPSESSID=abc' http://10.0.0.9/dash"},
                   "tool_response": {"stdout": html}}
    payload_xyz = {"tool_name": "Bash",
                   "tool_input": {"command": "curl -i -b 'PHPSESSID=xyz' http://10.0.0.9/dash"},
                   "tool_response": {"stdout": html}}
    pend = eng / "poc" / "pages" / ".pending"
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload_abc), text=True, capture_output=True, env=env)
    assert len(list(pend.glob("*-page-*.txt"))) == 1
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload_xyz), text=True, capture_output=True, env=env)
    assert len(list(pend.glob("*-page-*.txt"))) == 2
    # re-fetch of the FIRST cookie again -> still 2 (deduped, not a third card)
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload_abc), text=True, capture_output=True, env=env)
    assert len(list(pend.glob("*-page-*.txt"))) == 2


def test_recon_capture_no_page_card_out_of_scope(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl http://8.8.8.8/"},
               "tool_response": {"stdout": "<html><title>Google</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert not (eng / "poc" / "pages" / ".pending").exists()


def test_recon_capture_no_page_card_for_cat(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "cat page.html"},
               "tool_response": {"stdout": "<html><title>Login</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert not (eng / "poc" / "pages" / ".pending").exists()


def test_recon_capture_stages_source_card_for_log_file(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl http://10.0.0.9/app.log"},
               "tool_response": {"stdout": "2026-07-06 ERROR db connection refused\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    files = list(pend.glob("*-source-*.txt"))
    assert len(files) == 1
    assert "app.log" in files[0].read_text()


def test_recon_capture_php_rendering_html_is_page_not_source(tmp_path):
    # a rendered .php that returns HTML is a PAGE (rule 1 precedence), not a source.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -i http://10.0.0.9/index.php"},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><title>Home</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert list(pend.glob("*-page-*.txt"))
    assert not list(pend.glob("*-source-*.txt"))


def test_stage_page_or_source_caps_at_40(tmp_path):
    rc = _import_recon_capture()
    d = str(tmp_path)
    pend = tmp_path / "poc" / "pages" / ".pending"
    pend.mkdir(parents=True)
    for i in range(40):
        (pend / ("%04d-page-%08x.txt" % (i + 1, i))).write_text("# x\n$ x\n\nx")
    html = "<html><title>New</title></html>\n"
    res = rc.stage_page_or_source("curl -i http://10.0.0.9/new", html, d)
    assert res is None
    assert len(list(pend.glob("*.txt"))) == 40   # no new card added
    manifest = pend / "manifest.md"
    assert manifest.exists()
    assert manifest.read_text().count("cap reached") == 1
    # a second capped call must not append a second note line
    rc.stage_page_or_source("curl -i http://10.0.0.9/new2", html, d)
    assert manifest.read_text().count("cap reached") == 1


# --- Task 1: browser-render hint (#meta line) in the staged page card ------------

def test_http_method_bare_curl_is_get():
    rc = _import_recon_capture()
    assert rc._http_method("curl http://10.0.0.9/x") == "GET"


def test_http_method_dash_x_post_is_post():
    rc = _import_recon_capture()
    assert rc._http_method("curl -X POST http://10.0.0.9/x") == "POST"


def test_http_method_wget_post_data_is_post():
    rc = _import_recon_capture()
    assert rc._http_method("wget --post-data=a http://10.0.0.9/x") == "POST"


def test_http_method_curl_get_override_with_data_flag_is_get():
    rc = _import_recon_capture()
    assert rc._http_method("curl --get -d a=b http://10.0.0.9/x") == "GET"


def test_http_method_empty_or_none_seg_is_get():
    rc = _import_recon_capture()
    assert rc._http_method(None) == "GET"
    assert rc._http_method("") == "GET"


def test_http_method_data_flag_is_post():
    rc = _import_recon_capture()
    assert rc._http_method("curl -d 'x=1' http://10.0.0.9/x") == "POST"


def test_http_method_explicit_get_verb_overrides_data_flag():
    rc = _import_recon_capture()
    assert rc._http_method("curl -X GET -d 'x=1' http://10.0.0.9/x") == "GET"


def test_http_method_data_as_url_substring_is_not_a_flag():
    # "-d" must be matched as a whole token, not a substring of a URL path segment
    # that happens to contain "-data" (the hyphen makes this actually exercise the
    # word-boundary anchor, unlike a path with no hyphen before "data").
    rc = _import_recon_capture()
    assert rc._http_method("curl http://10.0.0.9/user-data") == "GET"


# --- Critical fix: curl short flags are case-sensitive; re.I collides with
# unrelated short flags of the opposite case (-f/--fail vs -F/--form, -x/--proxy
# vs -X/--request, -g/--globoff vs -G/--get, -D/--dump-header vs -d/--data,
# -t/--telnet-option vs -T/--upload-file). ------------------------------------

def test_http_method_dash_f_fail_is_not_form_flag():
    rc = _import_recon_capture()
    assert rc._http_method("curl -s -f -i http://x/login") == "GET"


def test_http_method_dash_x_lower_proxy_is_not_request_flag():
    rc = _import_recon_capture()
    assert rc._http_method("curl -x proxy:8080 -i http://x/login") == "GET"


def test_http_method_dash_g_lower_globoff_is_not_get_override():
    # -g/--globoff must NOT trigger the -G/--get override; the real -X POST wins.
    rc = _import_recon_capture()
    assert rc._http_method("curl -g -X POST http://x/api") == "POST"


def test_http_method_dash_capital_d_dump_header_is_not_data_flag():
    rc = _import_recon_capture()
    assert rc._http_method("curl -D headers.txt -s http://x/login") == "GET"


def test_http_method_dash_t_lower_telnet_option_is_not_upload_file_flag():
    rc = _import_recon_capture()
    assert rc._http_method("curl -t 1 http://x/login") == "GET"


# --- confirm the positive (real flag) cases still trigger POST/GET correctly ---

def test_http_method_dash_x_post_still_post():
    rc = _import_recon_capture()
    assert rc._http_method("curl -X POST http://x") == "POST"


def test_http_method_dash_capital_f_form_still_post():
    rc = _import_recon_capture()
    assert rc._http_method("curl -F a=b http://x") == "POST"


def test_http_method_dash_capital_t_upload_file_still_post():
    rc = _import_recon_capture()
    assert rc._http_method("curl -T f http://x") == "POST"


def test_http_method_dash_capital_g_get_override_still_get():
    rc = _import_recon_capture()
    assert rc._http_method("curl -G -d a=b http://x") == "GET"


def test_stage_page_or_source_get_page_meta_browser_1(tmp_path):
    rc = _import_recon_capture()
    d = str(tmp_path)
    html = ("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
            "<html><head><title>Login</title></head></html>\n")
    out_path = rc.stage_page_or_source(
        "curl -i http://10.0.0.9/login", html, d,
        url="http://10.0.0.9/login", req_seg="curl -i http://10.0.0.9/login")
    assert out_path is not None
    lines = open(out_path, encoding="utf-8").read().splitlines()
    assert lines[1] == "#meta browser=1 url=http://10.0.0.9/login"


def test_stage_page_or_source_post_x_flag_meta_browser_0(tmp_path):
    rc = _import_recon_capture()
    d = str(tmp_path)
    html = ("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
            "<html><head><title>Login</title></head></html>\n")
    out_path = rc.stage_page_or_source(
        "curl -i -X POST http://10.0.0.9/login", html, d,
        url="http://10.0.0.9/login", req_seg="curl -i -X POST http://10.0.0.9/login")
    body = open(out_path, encoding="utf-8").read()
    assert body.splitlines()[1] == "#meta browser=0"
    assert "browser=1" not in body


def test_stage_page_or_source_post_data_flag_meta_browser_0(tmp_path):
    rc = _import_recon_capture()
    d = str(tmp_path)
    html = ("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
            "<html><head><title>Login</title></head></html>\n")
    out_path = rc.stage_page_or_source(
        "curl -i -d 'x=1' http://10.0.0.9/login", html, d,
        url="http://10.0.0.9/login", req_seg="curl -i -d 'x=1' http://10.0.0.9/login")
    body = open(out_path, encoding="utf-8").read()
    assert body.splitlines()[1] == "#meta browser=0"
    assert "browser=1" not in body


def test_stage_page_or_source_source_card_meta_browser_0(tmp_path):
    rc = _import_recon_capture()
    d = str(tmp_path)
    out_path = rc.stage_page_or_source(
        "curl http://10.0.0.9/config.env", "DB_PASSWORD=secret\n", d,
        url="http://10.0.0.9/config.env", req_seg="curl http://10.0.0.9/config.env")
    assert out_path is not None
    assert "-source-" in os.path.basename(out_path)
    body = open(out_path, encoding="utf-8").read()
    assert body.splitlines()[1] == "#meta browser=0"


def test_stage_page_or_source_exploit_post_non_html_cards_as_request(tmp_path):
    # An exploit/auth POST whose response is a 302 (neither an HTML page nor a lead) must
    # still auto-card the request/response -- the thm_tricipher standard. Regression for
    # "exploit POSTs were never captured as curl cards".
    rc = _import_recon_capture()
    d = str(tmp_path)
    cmd = "curl -sk -X POST -d 'user[username]=root' http://10.0.0.9/users/sign_in"
    resp = "HTTP/1.1 302 Found\r\nLocation: http://10.0.0.9/\r\n\r\n"
    out_path = rc.stage_page_or_source(cmd, resp, d, url="http://10.0.0.9/users/sign_in", req_seg=cmd)
    assert out_path is not None and "-request-" in os.path.basename(out_path)
    body = open(out_path, encoding="utf-8").read()
    assert body.startswith("# POST http://10.0.0.9/users/sign_in")
    assert body.splitlines()[1] == "#meta browser=0"       # never a browser render
    # re-firing the same POST dedupes; a GET with the same non-HTML response does NOT card
    assert rc.stage_page_or_source(cmd, resp, d, url="http://10.0.0.9/users/sign_in", req_seg=cmd) is None
    g = "curl -sk http://10.0.0.9/x"
    assert rc.stage_page_or_source(g, "HTTP/1.1 204 No Content\r\n\r\n", d,
                                   url="http://10.0.0.9/x", req_seg=g) is None


def test_stage_page_or_source_curl_g_override_is_browser(tmp_path):
    rc = _import_recon_capture()
    d = str(tmp_path)
    html = ("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
            "<html><head><title>Search</title></head></html>\n")
    out_path = rc.stage_page_or_source(
        "curl -i -G -d q=1 http://10.0.0.9/search", html, d,
        url="http://10.0.0.9/search",
        req_seg="curl -i -G -d q=1 http://10.0.0.9/search")
    assert out_path is not None
    body = open(out_path, encoding="utf-8").read()
    assert body.splitlines()[1] == "#meta browser=1 url=http://10.0.0.9/search"


def test_stage_page_or_source_meta_line_dedupe_unaffected(tmp_path):
    # re-fetch of the same path+auth-state still dedupes to a single card (the new
    # #meta line must not disturb the existing dedupe-by-key behavior).
    import glob
    rc = _import_recon_capture()
    d = str(tmp_path)
    html = ("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
            "<html><head><title>Login</title></head></html>\n")
    first = rc.stage_page_or_source(
        "curl -i http://10.0.0.9/login", html, d,
        url="http://10.0.0.9/login", req_seg="curl -i http://10.0.0.9/login")
    assert first is not None
    second = rc.stage_page_or_source(
        "curl -i http://10.0.0.9/login", html, d,
        url="http://10.0.0.9/login", req_seg="curl -i http://10.0.0.9/login")
    assert second is None
    pend = os.path.join(d, "poc", "pages", ".pending")
    assert len(glob.glob(os.path.join(pend, "*.txt"))) == 1
    body = open(first, encoding="utf-8").read()
    # existing card body (request line + response) still intact, unchanged shape
    assert "$ curl -i http://10.0.0.9/login" in body
    assert "Login" in body


def test_recon_capture_no_page_card_chained_out_of_scope_semicolon(tmp_path):
    # SCOPE LEAK regression: a chained in-scope + out-of-scope curl (one concatenated
    # stdout blob that cannot be attributed per-URL) must stage NOTHING -- otherwise the
    # out-of-scope host's response text would land on disk labeled under the in-scope URL.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "curl -s http://10.0.0.9/robots.txt; curl -s http://out-of-scope.example/"},
               "tool_response": {"stdout":
                   "User-agent: *\n<html><head><title>Evil</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_no_page_card_chained_out_of_scope_and(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "curl -s http://10.0.0.9/index && curl -s http://8.8.8.8/"},
               "tool_response": {"stdout":
                   "<html><title>Home</title></html>\n<html><title>Other</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_no_page_card_wrapped_chained_out_of_scope(tmp_path):
    # SYNERGY (Task 5 x Task 3): now that inner_cmds() unwraps a wrapped+chained curl
    # (the Task 5 fix), the poc/pages scope gate's _all_targets() (Task 3) -- which walks
    # [cmd] + inner_cmds(cmd) -- SEES both inner curls instead of inner_cmds() returning
    # [] and hiding the out-of-scope one. Must still fail closed: no card, because the
    # gate now correctly SEES the out-of-scope target (not because it's blind to it).
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "bash /root/vm.sh 'curl -s http://10.0.0.9/a; "
                   "curl -s http://out-of-scope.example/evil'"},
               "tool_response": {"stdout":
                   "<html><head><title>Evil</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_page_card_all_in_scope_chained_still_stages(tmp_path):
    # guard against over-tightening: a single in-scope curl (HTML) STILL stages one card.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -i http://10.0.0.9/login"},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><head><title>Login</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list((eng / "poc" / "pages" / ".pending").glob("*-page-*.txt"))) == 1


def test_recon_capture_no_card_for_plain_json_non_source_path(tmp_path):
    # an in-scope curl whose response is neither HTML nor a source-extension path nor a
    # lead (a plain JSON body at a non-.json path) -> no card.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s http://10.0.0.9/api/status"},
               "tool_response": {"stdout": '{"status":"ok","count":3}\n'}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert not (eng / "poc" / "pages" / ".pending").exists()


# SCOPE LEAK regression (2nd vector): a SINGLE curl/wget invocation with MULTIPLE URL
# args (native curl behavior: fetches all, concatenates bodies to stdout). Every URL in
# the segment must be scope-checked, not just the first -- else the out-of-scope 2nd
# target's response is staged under the in-scope 1st URL's label.

def test_recon_capture_no_page_card_multi_url_space_separated(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "curl -s http://10.0.0.9/robots.txt http://out-of-scope.example/"},
               "tool_response": {"stdout":
                   "User-agent: *\n<html><head><title>Evil</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_no_page_card_multi_url_flag_form(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "curl --url http://10.0.0.9/a --url http://out-of-scope.example/"},
               "tool_response": {"stdout":
                   "<html><title>A</title></html>\n<html><title>Evil</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_no_page_card_multi_url_wget(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "wget -qO- http://10.0.0.9/a http://out-of-scope.example/"},
               "tool_response": {"stdout":
                   "<html><title>A</title></html>\n<html><title>Evil</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_page_card_multi_url_all_in_scope_stages_one(tmp_path):
    # guard against over-tightening: BOTH URLs in scope -> still exactly one card.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -i http://10.0.0.9/a http://10.0.0.9/b"},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><head><title>A</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list((eng / "poc" / "pages" / ".pending").glob("*-page-*.txt"))) == 1


# SCOPE LEAK regression (3rd vector): a SCHEMELESS positional arg. curl/wget accept a
# bare host as a URL (default http://) and fetch it, concatenating its body to stdout. A
# http(s):// regex does not see the schemeless target, so it was never scope-checked.
# The robust gate enumerates POSITIONAL request targets (curl's own arg model), so a
# schemeless out-of-scope arg is caught.

def test_recon_capture_no_page_card_schemeless_out_of_scope_positional(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "curl -s http://10.0.0.9/robots.txt out-of-scope.example/evil"},
               "tool_response": {"stdout":
                   "User-agent: *\n<html><head><title>Evil</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_no_page_card_schemeless_out_of_scope_url_flag(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "curl --url http://10.0.0.9/a --url out-of-scope.example/evil"},
               "tool_response": {"stdout":
                   "<html><title>A</title></html>\n<html><title>Evil</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_no_page_card_schemeless_out_of_scope_wget(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "wget -qO- http://10.0.0.9/a out-of-scope.example/evil"},
               "tool_response": {"stdout":
                   "<html><title>A</title></html>\n<html><title>Evil</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_page_card_output_flag_value_not_a_target(tmp_path):
    # `-o out.html` filename must NOT be mistaken for a request target; the real fetch is
    # in-scope -> one card.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s -o out.html http://10.0.0.9/a"},
               "tool_response": {"stdout": "<html><title>A</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list((eng / "poc" / "pages" / ".pending").glob("*-page-*.txt"))) == 1


def test_recon_capture_page_card_external_host_in_header_not_a_target(tmp_path):
    # an external host inside a -H header VALUE is consumed by -H, not a request target ->
    # the only fetch (in-scope) stages one card.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   'curl -H "Referer: http://out-of-scope.example/x" http://10.0.0.9/a'},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><title>A</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list((eng / "poc" / "pages" / ".pending").glob("*-page-*.txt"))) == 1


# SCOPE LEAK regression (4th class - STRUCTURAL): a flag that pulls fetch targets from a
# source the argv parser cannot read (curl -K/--config config file, wget -i/--input-file
# URL list). curl fetches those targets IN ADDITION to the command-line URL and
# concatenates all bodies to stdout, so an out-of-scope target hidden in the file is
# invisible to argv enumeration. When a segment carries such an opaque-target flag we
# cannot POSITIVELY enumerate every target -> FAIL CLOSED (stage nothing).

def test_recon_capture_no_page_card_curl_config_file_opaque(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s -K /tmp/x.cfg http://10.0.0.9/a"},
               "tool_response": {"stdout":
                   "<html><title>A</title></html>\n<html><title>Evil</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_no_page_card_curl_config_long_opaque(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl --config /tmp/x.cfg http://10.0.0.9/a"},
               "tool_response": {"stdout":
                   "<html><title>A</title></html>\n<html><title>Evil</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_no_page_card_wget_input_file_opaque(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "wget -i /tmp/urls.txt http://10.0.0.9/a"},
               "tool_response": {"stdout":
                   "<html><title>A</title></html>\n<html><title>Evil</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


# wget recursive/mirror/page-requisites content-drive fetches to hosts NOT in argv
# (the crawl target is discovered from fetched HTML). These are argv-DETECTABLE boolean
# flags, so we fail closed on them -- same structural rule as -K/-i.

def test_recon_capture_no_page_card_wget_recursive(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "wget -r http://10.0.0.9/"},
               "tool_response": {"stdout":
                   "<html><title>A</title></html>\n<html><title>Evil</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_no_page_card_wget_mirror_page_requisites_clustered(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "wget -mp http://10.0.0.9/"},
               "tool_response": {"stdout":
                   "<html><title>A</title></html>\n<html><title>Evil</title></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_wget_non_recursive_positive_unaffected(tmp_path):
    # a plain in-scope wget with NO recursive/mirror/page-requisites flag still cards.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "wget -qO- http://10.0.0.9/a"},
               "tool_response": {"stdout": "<html><head><title>A</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list((eng / "poc" / "pages" / ".pending").glob("*-page-*.txt"))) == 1


# SCOPE LEAK regression (4th vector): dotted-scope-entry label-prefix confusion. A bare-IP
# (or FQDN) scope entry like "10.0.0.9" must NOT label-prefix-match "10.0.0.9.evil.com" --
# that would let an attacker-controlled host discovered during SSRF/redirect hunting
# (<scope>.attacker.tld) be judged in-scope, and the poc/pages gate would then write
# evil.com's response body to disk labeled as if it were the in-scope host.

def test_recon_capture_no_page_card_dotted_scope_label_confusion(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path)  # in-scope: 10.0.0.9
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -i http://10.0.0.9.evil.com/"},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><head><title>Evil</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_page_card_genuine_in_scope_still_stages(tmp_path):
    # guard against over-tightening: a genuine in-scope host still cards normally.
    eng, env = _scoped_eng_vault(tmp_path)  # in-scope: 10.0.0.9
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -i http://10.0.0.9/"},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><head><title>Home</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list((eng / "poc" / "pages" / ".pending").glob("*-page-*.txt"))) == 1


# SCOPE LEAK regression (5th vector): BARE-LABEL label-prefix confusion. A realistic
# shorthand in-scope entry like `- prod-db` (an internal host) must NOT label-prefix-match
# `prod-db.evil.com` -- the label-prefix arm is attacker-spoofable, so the poc/pages
# disk-write gate uses strict=True and drops it. Without the strict fix the gate would
# write evil.com's response body to a card labeled as the in-scope host.

def test_recon_capture_no_page_card_bare_label_scope_confusion(tmp_path):
    eng, env = _scoped_eng_vault(tmp_path, in_scope_host="prod-db")
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -i http://prod-db.evil.com/"},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><head><title>Evil</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_recon_capture_page_card_fqdn_exact_in_scope_still_stages(tmp_path):
    # guard against over-tightening: an FQDN in-scope entry still captures its exact host
    # (strict=True keeps the exact-match arm).
    eng, env = _scoped_eng_vault(tmp_path, in_scope_host="prod-db.corp.local")
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -i http://prod-db.corp.local/"},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><head><title>DB</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    assert len(list((eng / "poc" / "pages" / ".pending").glob("*-page-*.txt"))) == 1


# SCOPE LEAK regression (6th vector - a fail-SAFE-but-feature-defeating one): a shell
# redirect token (`2>&1`, `2>/dev/null`, `> out.html`, `>>log`, `>&2`) is not a flag and
# not a URL, but _curl_targets' walk treated every non-flag token as a positional request
# target -- so a redirect's derived "host" (e.g. "2>&1") failed the all(in_scope) check
# and NO card staged, even for a fully in-scope, real curl. Live-validated:
# `bash /root/vm.sh 'curl -s -i http://10.112.172.210/ 2>&1'` (in-scope) staged zero cards.
# Safety invariant: a redirect operator and its file are NEVER a URL curl/wget fetches (a
# local file or an fd dup), so skipping them can only fix a false-negative (a redirect
# mistaken for a target); it can never under-count a real fetch target, so it cannot
# introduce a scope leak (under-counting a real target is the only thing that leaks).

def test_curl_targets_skips_self_contained_redirect_2_and_1():
    rc = _import_recon_capture()
    assert rc._curl_targets("curl -s -i http://10.0.0.9/ 2>&1") == \
        [("10.0.0.9", "http://10.0.0.9/")]


def test_curl_targets_skips_self_contained_redirect_dev_null():
    rc = _import_recon_capture()
    assert rc._curl_targets("curl -s http://10.0.0.9/ 2>/dev/null") == \
        [("10.0.0.9", "http://10.0.0.9/")]


def test_curl_targets_skips_bare_redirect_to_file():
    rc = _import_recon_capture()
    assert rc._curl_targets("curl http://10.0.0.9/ > out.html") == \
        [("10.0.0.9", "http://10.0.0.9/")]


def test_curl_targets_skips_append_redirect_and_stderr_dup():
    rc = _import_recon_capture()
    assert rc._curl_targets("curl http://10.0.0.9/ >> log 2>&1") == \
        [("10.0.0.9", "http://10.0.0.9/")]


def test_curl_targets_skips_split_stdout_stderr_redirects():
    rc = _import_recon_capture()
    assert rc._curl_targets("curl -s http://10.0.0.9/ 1>body 2>err") == \
        [("10.0.0.9", "http://10.0.0.9/")]


def test_curl_targets_redirect_skip_does_not_swallow_real_out_of_scope_url():
    # SAFETY: a genuine second URL target next to a redirect must still be enumerated --
    # the redirect skip must never eat a real fetch target.
    rc = _import_recon_capture()
    targets = rc._curl_targets("curl http://10.0.0.9/ http://out.evil/ 2>&1")
    assert len(targets) == 2
    assert ("10.0.0.9", "http://10.0.0.9/") in targets
    assert ("out.evil", "http://out.evil/") in targets


def test_curl_targets_redirect_file_that_looks_like_a_url_is_not_fetched():
    # `> http://out.evil/x` is a redirect FILE (curl writes there, never fetches it) --
    # skipped as a target. Only the real fetch (10.0.0.9) is a target.
    rc = _import_recon_capture()
    assert rc._curl_targets("curl http://10.0.0.9/ > http://out.evil/x") == \
        [("10.0.0.9", "http://10.0.0.9/")]


def test_curl_targets_redirect_after_out_of_scope_fetch_still_fails_closed():
    # the FETCH (out.evil) precedes the redirect operator here, so it is a real target and
    # must still be enumerated -> gate stays closed.
    rc = _import_recon_capture()
    assert rc._curl_targets("curl http://out.evil/ > http://10.0.0.9/x") == \
        [("out.evil", "http://out.evil/")]


def test_curl_targets_existing_value_flag_and_opaque_paths_unaffected():
    rc = _import_recon_capture()
    assert rc._curl_targets("curl -s -o out.html http://10.0.0.9/a") == \
        [("10.0.0.9", "http://10.0.0.9/a")]
    assert rc._curl_targets("curl -s -K /tmp/x.cfg http://10.0.0.9/a") is None
    assert rc._curl_targets("wget -r http://10.0.0.9/") is None
    assert rc._curl_targets("curl -i http://10.0.0.9/a http://10.0.0.9/b") == \
        [("10.0.0.9", "http://10.0.0.9/a"), ("10.0.0.9", "http://10.0.0.9/b")]


def test_recon_capture_stages_page_card_curl_with_2_and_1_redirect(tmp_path):
    # INTEGRATION (the exact live-validated repro): a real in-scope curl with a trailing
    # `2>&1` now stages exactly one poc/pages card -- previously staged ZERO because
    # `2>&1` was mis-parsed as an out-of-scope positional target and the all(in_scope)
    # gate failed closed.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "bash /root/vm.sh 'curl -s -i http://10.0.0.9/ 2>&1'"},
               "tool_response": {"stdout":
                   "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n"
                   "<html><head><title>Home</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert len(list(pend.glob("*-page-*.txt"))) == 1


def test_recon_capture_no_page_card_out_of_scope_inner_with_redirect(tmp_path):
    # leak-preservation: an out-of-scope inner curl target chained alongside an in-scope
    # one, WITH a trailing redirect, must still fail closed (zero cards) -- the redirect
    # fix must not weaken the existing chained-scope-leak protection.
    eng, env = _scoped_eng_vault(tmp_path)
    payload = {"tool_name": "Bash",
               "tool_input": {"command":
                   "bash /root/vm.sh 'curl -s http://10.0.0.9/ "
                   "http://out-of-scope.example/evil 2>&1'"},
               "tool_response": {"stdout":
                   "<html><head><title>Evil</title></head></html>\n"}}
    subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                   input=json.dumps(payload), text=True, capture_output=True, env=env)
    pend = eng / "poc" / "pages" / ".pending"
    assert not pend.exists() or not list(pend.glob("*.txt"))


def test_discipline_nudge_fires_once(tmp_path):
    eng, env = _ctf_eng_vault(tmp_path)
    _run_discipline(env, "bash /root/vm.sh 'nc -lvnp 9001'")
    assert (eng / ".discipline-nudged").exists()
    out2 = _run_discipline(env, "bash /root/vm.sh 'nc -lvnp 9002'")
    assert "DISCIPLINE" not in out2


def test_discipline_nudge_silent_on_git_commit_message(tmp_path):
    """A git commit message that MENTIONS off-script tokens (nc -l / vm.sh / node -e) in a
    quoted arg must NOT fire -- detection matches command STRUCTURE (quotes blanked), not
    tokens in prose. This is the over-fire class the whole hook exists to prevent."""
    eng, env = _ctf_eng_vault(tmp_path)
    out = _run_discipline(env, 'git commit -m "add nc -l listener via vm.sh node -e"')
    assert "DISCIPLINE" not in out
    assert not (eng / ".discipline-nudged").exists()


def test_discipline_nudge_silent_on_heredoc_note(tmp_path):
    """A heredoc NOTE whose body mentions off-script tokens, written via a non-bridge
    command (cat/tee), must NOT fire. The `cd` prefix bypasses the hook's cat early-return,
    so this genuinely exercises the nudge: heredoc bodies are stripped before matching and
    inner tokens are inspected only when a real bridge wrapper is invoked."""
    eng, env = _ctf_eng_vault(tmp_path)
    out = _run_discipline(
        env, "cd /tmp && cat >> notes.md <<'EOF'\nreminder: nc -l listener via vm.sh node -e\nEOF")
    assert "DISCIPLINE" not in out
    assert not (eng / ".discipline-nudged").exists()


def test_discipline_nudge_fires_on_bare_top_level_listener(tmp_path):
    """A real top-level listener invocation (unquoted, unwrapped) still fires -- the
    quote-blanking must preserve an unquoted command-position listener."""
    eng, env = _ctf_eng_vault(tmp_path)
    out = _run_discipline(env, "nc -lvnp 9001")
    assert "DISCIPLINE" in out
    assert (eng / ".discipline-nudged").exists()


def test_discipline_nudge_fires_on_inline_code_exec(tmp_path):
    eng, env = _ctf_eng_vault(tmp_path)
    out = _run_discipline(env, 'bash /root/vm.sh \'node -e "new Image().src=x"\'')
    assert "DISCIPLINE" in out
    assert (eng / ".discipline-nudged").exists()


def test_discipline_nudge_silent_on_vm_scan_launch(tmp_path):
    # the disciplined tmux path (scripts/vm-scan.sh) must NOT be nudged, even though
    # the wrapped command is itself an exploitation shape.
    eng, env = _ctf_eng_vault(tmp_path)
    out = _run_discipline(env, "bash scripts/vm-scan.sh ENG 10.0.0.9 'nmap -sV 10.0.0.9'")
    assert "DISCIPLINE" not in out
    assert not (eng / ".discipline-nudged").exists()


def test_discipline_nudge_silent_on_plain_recon(tmp_path):
    eng, env = _ctf_eng_vault(tmp_path)
    out = _run_discipline(env, "nmap -sV 10.0.0.9")
    assert "DISCIPLINE" not in out
    assert not (eng / ".discipline-nudged").exists()


def test_discipline_nudge_silent_on_plain_curl(tmp_path):
    # a single curl is neither a listener nor code-exec -- must not fire.
    eng, env = _ctf_eng_vault(tmp_path)
    out = _run_discipline(env, "bash /root/vm.sh 'curl -s https://10.10.10.10/'")
    assert "DISCIPLINE" not in out
    assert not (eng / ".discipline-nudged").exists()


def test_discipline_nudge_silent_on_detached_command(tmp_path):
    # a detached listener (trailing &) is treated as already-disciplined (tmux-adjacent
    # background usage), not an off-script foreground exploit.
    eng, env = _ctf_eng_vault(tmp_path)
    out = _run_discipline(env, "bash /root/vm.sh 'nc -lvnp 9001' &")
    assert "DISCIPLINE" not in out
    assert not (eng / ".discipline-nudged").exists()


def test_discipline_nudge_scoped_to_ctf_only(tmp_path):
    # pentest engagement (default engagement_type) -- ctf-scoped, must not fire.
    eng, env = _eng_vault(tmp_path)
    out = _run_discipline(env, "bash /root/vm.sh 'nc -lvnp 9001'")
    assert "DISCIPLINE" not in out
    assert not (eng / ".discipline-nudged").exists()


def test_discipline_nudge_malformed_exits_zero(tmp_path):
    _eng, env = _ctf_eng_vault(tmp_path)
    p = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                       input="garbage", capture_output=True, text=True, env=env, timeout=20)
    assert p.returncode == 0


# ---- drainkick: PostToolUse mid-turn drain kick (_areas_to_kick / _kick_drains) ----

def test_areas_to_kick_stages_and_stamps(tmp_path):
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap\nout\n")
    areas = rc._areas_to_kick(str(d))
    assert areas == ["recon"]
    assert (pend / ".last-kick").exists()


def test_areas_to_kick_debounced_on_immediate_recall(tmp_path):
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap\nout\n")
    assert rc._areas_to_kick(str(d)) == ["recon"]
    assert rc._areas_to_kick(str(d)) == []      # debounced: stamp is fresh


def test_areas_to_kick_returns_again_after_stamp_backdated(tmp_path):
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap\nout\n")
    assert rc._areas_to_kick(str(d), debounce=8) == ["recon"]
    stamp = pend / ".last-kick"
    old = os.path.getmtime(str(stamp)) - 20    # > debounce window
    os.utime(str(stamp), (old, old))
    assert rc._areas_to_kick(str(d), debounce=8) == ["recon"]


def test_areas_to_kick_no_staged_card_never_returned(tmp_path):
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    (d / "recon" / ".pending").mkdir(parents=True)
    assert rc._areas_to_kick(str(d)) == []
    (d / "poc" / "pages" / ".pending").mkdir(parents=True)
    assert rc._areas_to_kick(str(d)) == []


def test_areas_to_kick_empty_or_garbage_never_raises(tmp_path):
    rc = _import_recon_capture()
    assert rc._areas_to_kick(str(tmp_path / "does-not-exist")) == []
    assert rc._areas_to_kick("") == []
    assert rc._areas_to_kick(None) == []


def test_areas_to_kick_multiple_areas(tmp_path):
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    (d / "recon" / ".pending").mkdir(parents=True)
    (d / "recon" / ".pending" / "0001-nmap-abcd1234.txt").write_text("# nmap\nout\n")
    (d / "poc" / "pages" / ".pending").mkdir(parents=True)
    (d / "poc" / "pages" / ".pending" / "0001-page-abcd1234.txt").write_text("# page\nout\n")
    areas = rc._areas_to_kick(str(d))
    assert set(areas) == {"recon", "poc/pages"}


def test_kick_drains_spawns_drain_for_staged_area(tmp_path, monkeypatch):
    import subprocess as real_subprocess
    import sys
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap\nout\n")
    calls = []

    def fake_popen(args, **kwargs):
        calls.append((args, kwargs))

        class _Dummy:
            pass
        return _Dummy()

    monkeypatch.setattr(real_subprocess, "Popen", fake_popen)
    rc._kick_drains(str(d))
    assert len(calls) == 1
    args, kwargs = calls[0]
    ld = os.path.join(HOOKS, "loop-driver.py")
    assert args == [sys.executable, ld, "--drain", str(d), "recon"]
    assert kwargs.get("start_new_session") is True
    assert kwargs.get("stdout") == real_subprocess.DEVNULL
    assert kwargs.get("stderr") == real_subprocess.DEVNULL
    assert kwargs.get("stdin") == real_subprocess.DEVNULL


def test_kick_drains_also_spawns_drain_tmux_when_pending_tmux_nonempty(tmp_path, monkeypatch):
    import subprocess as real_subprocess
    import sys
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\n")
    calls = []

    def fake_popen(args, **kwargs):
        calls.append(args)

        class _Dummy:
            pass
        return _Dummy()

    monkeypatch.setattr(real_subprocess, "Popen", fake_popen)
    rc._kick_drains(str(d))
    ld = os.path.join(HOOKS, "loop-driver.py")
    assert [sys.executable, ld, "--drain-tmux", str(d)] in calls


def test_kick_drains_nothing_staged_not_called(tmp_path, monkeypatch):
    import subprocess as real_subprocess
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    d.mkdir()
    calls = []

    def fake_popen(args, **kwargs):
        calls.append(args)

        class _Dummy:
            pass
        return _Dummy()

    monkeypatch.setattr(real_subprocess, "Popen", fake_popen)
    rc._kick_drains(str(d))
    assert calls == []


def test_recon_capture_main_kicks_drain_for_staged_recon_card(tmp_path, monkeypatch):
    """Integration: main() must call _kick_drains(d) just before _emit(blocks) when an
    engagement dir resolved -- proven by a staged recon/.pending card producing a
    monkeypatched Popen call for the --drain area, on an ordinary non-recon/cred command
    that reaches the end of main() (not an echo/cat/grep early-return)."""
    import io
    import subprocess as real_subprocess
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap\nout\n")
    (d / "state.md").write_text("| host |\n|---|\n")
    (d / "loot.md").write_text("| cred |\n|---|\n")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(d))
    calls = []

    def fake_popen(args, **kwargs):
        calls.append(args)

        class _Dummy:
            pass
        return _Dummy()

    monkeypatch.setattr(real_subprocess, "Popen", fake_popen)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "ls -la /tmp"},
               "tool_response": {"stdout": "total 0\n"}}
    monkeypatch.setattr(rc.sys, "stdin", io.StringIO(json.dumps(payload)))
    rc.main()
    ld = os.path.join(HOOKS, "loop-driver.py")
    assert [rc.sys.executable, ld, "--drain", str(d), "recon"] in calls


def test_recon_capture_main_no_kick_when_nothing_staged(tmp_path, monkeypatch):
    """main() must not spawn any drain when nothing is staged (fail-open, no-op)."""
    import io
    import subprocess as real_subprocess
    rc = _import_recon_capture()
    d = tmp_path / "ENG"
    d.mkdir(parents=True)
    (d / "state.md").write_text("| host |\n|---|\n")
    (d / "loot.md").write_text("| cred |\n|---|\n")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(d))
    calls = []

    def fake_popen(args, **kwargs):
        calls.append(args)

        class _Dummy:
            pass
        return _Dummy()

    monkeypatch.setattr(real_subprocess, "Popen", fake_popen)
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "ls -la /tmp"},
               "tool_response": {"stdout": "total 0\n"}}
    monkeypatch.setattr(rc.sys, "stdin", io.StringIO(json.dumps(payload)))
    rc.main()
    assert calls == []


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


# --- screenshot-on-finding reflex (Piece 1) ---------------------------------

def test_recon_capture_screenshot_nudge_on_shell(vault):
    # a shell/privesc landing (`id` output) -> prompt to screenshot the live state, once.
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "sshpass -p x ssh user@10.0.0.5 id"},
               "tool_response": "uid=0(root) gid=0(root) groups=0(root)"}
    out1 = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "FINDING landed" in out1 and "Skill(screenshot)" in out1
    assert os.path.isfile(str(vault / "targets" / "acme" / ".screenshot-nudged"))
    out2 = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "FINDING landed" not in out2          # fire-once per engagement


def test_recon_capture_screenshot_nudge_on_flag(vault):
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "sshpass -p x ssh user@10.0.0.5 cat /root/root.txt"},
               "tool_response": "THM{some_root_flag_value}"}
    out = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "FINDING landed" in out


def test_recon_capture_no_screenshot_nudge_on_plain_output(vault):
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "sshpass -p x ssh user@10.0.0.5 ls -la"},
               "tool_response": "total 8\ndrwxr-xr-x 2 user user 4096 file.txt"}
    out = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "FINDING landed" not in out
    assert not os.path.isfile(str(vault / "targets" / "acme" / ".screenshot-nudged"))


# --- recon-completeness reflex (Piece 2) ------------------------------------

def _scope_in(vault, host):
    (vault / "targets" / "acme" / "scope.md").write_text(
        "---\ntype: engagement-scope\n---\n## In scope\n- %s\n## Out of scope\n-\n" % host)


def test_recon_capture_recon_completeness_fires_before_discovery(vault):
    _scope_in(vault, "10.0.0.5")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "curl -s http://10.0.0.5/"}},
                   _env(vault)).stdout
    assert "RECON COMPLETENESS" in out
    # fire-once: a second in-scope curl stays silent
    out2 = run_hook("recon-capture.py",
                    {"tool_name": "Bash", "tool_input": {"command": "curl -s http://10.0.0.5/x"}},
                    _env(vault)).stdout
    assert "RECON COMPLETENESS" not in out2


def test_recon_capture_recon_completeness_silent_after_ffuf(vault):
    _scope_in(vault, "10.0.0.5")
    # ffuf runs first -> recorded in .recon-tools
    run_hook("recon-capture.py",
             {"tool_name": "Bash",
              "tool_input": {"command": "ffuf -u http://10.0.0.5/FUZZ -w wl.txt"}}, _env(vault))
    assert os.path.isfile(str(vault / "targets" / "acme" / ".recon-tools"))
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "curl -s http://10.0.0.5/"}},
                   _env(vault)).stdout
    assert "RECON COMPLETENESS" not in out          # discovery already ran -> silent


def test_recon_capture_recon_completeness_silent_out_of_scope(vault):
    _scope_in(vault, "10.0.0.5")
    # probing a host NOT in scope (e.g. the attacker's own listener) -> no nudge
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "curl -s http://192.168.1.9/pspy"}},
                   _env(vault)).stdout
    assert "RECON COMPLETENESS" not in out
