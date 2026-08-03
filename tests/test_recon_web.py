import os, subprocess, pathlib

VAULT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = VAULT / "scripts" / "recon-web.sh"


def test_exists_executable():
    assert SCRIPT.exists()
    assert os.access(SCRIPT, os.X_OK)


def test_usage_no_args():
    r = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode != 0


def _run(tmp_path, scope_body="", url="http://x/"):
    eng = "demo"
    d = tmp_path / "targets" / eng
    d.mkdir(parents=True)
    (d / "scope.md").write_text(scope_body)
    env = dict(os.environ, RECON_WEB_DRYRUN="1")
    return subprocess.run(["bash", str(SCRIPT), eng, url], cwd=tmp_path,
                          env=env, capture_output=True, text=True)


def test_dryrun_lists_all_tools(tmp_path):
    out = _run(tmp_path).stdout
    assert "ffuf" in out                     # feroxbuster is not installed on the VM
    assert "feroxbuster" not in out
    assert "nuclei" in out
    assert "whatweb" in out
    assert "capture.sh web" in out          # render goes through the chromium render-into-poc path


def test_passive_only_drops_active(tmp_path):
    out = _run(tmp_path, "passive_only: true\n").stdout
    assert "whatweb" in out and "capture.sh web" in out
    assert "ffuf" not in out and "nuclei" not in out


def test_no_dos_rate_caps_but_keeps_discovery(tmp_path):
    # no_dos means "low rate", not "no discovery": every scope.md that sets it also permits
    # ffuf/nuclei at low rate. A mid-range rate is what got wholesale-blocked in the field.
    out = _run(tmp_path, "no_dos: true\n").stdout
    assert "ffuf" in out and "nuclei" in out
    assert "-rate 5" in out
    assert "-rl 10" in out
    assert "Mozilla/5.0" in out and "Accept-Language" in out   # stock UA draws a blanket edge 403
