"""build-walkthrough.py hardwire: at close-out it (1) sweeps every tmux tab into the gallery via
AUTOCARD_ALL (skipped here with BUILD_WT_NO_SWEEP=1, no live VM in tests) and (2) warns when
reproduction steps exist but poc/scripts/ is empty, so the exploit scripts get preserved."""
import os
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BW = os.path.join(REPO, "scripts", "build-walkthrough.py")
WT = "# Walkthrough\n\n## 1. Recon\n```sh\nnmap -sCV 10.0.0.1\n```\n- result: x\n\n## Flags\n"


def _run(eng_dir):
    return subprocess.run(["python3", BW, str(eng_dir)], capture_output=True, text=True,
                          env=dict(os.environ, BUILD_WT_NO_SWEEP="1"), timeout=30)


def test_warns_when_scripts_dir_empty(tmp_path):
    eng = tmp_path / "boxwt"
    (eng / "poc" / "scripts").mkdir(parents=True)      # exists but empty
    (eng / "walkthrough.md").write_text(WT)
    r = _run(eng)
    assert r.returncode == 0, r.stderr
    assert "poc/scripts/ is empty" in r.stdout, r.stdout


def test_no_warn_when_scripts_present(tmp_path):
    eng = tmp_path / "boxwt2"
    sd = eng / "poc" / "scripts"
    sd.mkdir(parents=True)
    (sd / "shell.ps1.md").write_text("payload")
    (eng / "walkthrough.md").write_text(WT)
    r = _run(eng)
    assert r.returncode == 0, r.stderr
    assert "poc/scripts/ is empty" not in r.stdout, r.stdout
