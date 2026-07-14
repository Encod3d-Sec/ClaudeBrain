"""Unit tests for stack_vertical (skills/hooks/loop-driver.py): a fail-open helper that
stacks two PNGs vertically (top above bottom) into a single combined image. Imported via
importlib (loop-driver.py has a hyphenated filename), matching the pattern already used
in tests/test_loop_driver.py."""
import importlib.util
import os
import shutil
import subprocess

from PIL import Image

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _import_ld():
    spec = importlib.util.spec_from_file_location(
        "loop_driver_stack", os.path.join(REPO, "skills", "hooks", "loop-driver.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _make_png(path, width, height, color):
    Image.new("RGB", (width, height), color).save(path)


def _force_no_convert(monkeypatch):
    """stack_vertical does `import shutil; shutil.which("convert")` internally -- that
    `import shutil` just rebinds to the same cached sys.modules entry this test file
    already imported, so patching the shutil module object here forces the PIL branch
    regardless of whether the host actually has ImageMagick installed."""
    monkeypatch.setattr(shutil, "which", lambda name: None)


def test_stack_vertical_same_width(tmp_path, monkeypatch):
    """Two same-width PNGs stack to width == max(widths), height == sum(heights). Forces
    the PIL branch (convert reported missing) so the dimension assertions are deterministic
    across hosts, whether or not ImageMagick is installed."""
    _force_no_convert(monkeypatch)
    ld = _import_ld()
    top = str(tmp_path / "top.png")
    bottom = str(tmp_path / "bottom.png")
    out = str(tmp_path / "out.png")
    _make_png(top, 100, 40, "red")
    _make_png(bottom, 100, 60, "blue")

    result = ld.stack_vertical(top, bottom, out)

    assert result == out
    assert os.path.isfile(out)
    assert os.path.getsize(out) > 0
    with Image.open(out) as im:
        assert im.size == (100, 100)


def test_stack_vertical_differing_widths_picks_max(tmp_path, monkeypatch):
    """Differing widths -> combined width is the max of the two, not a sum/crop/distort.
    Forces the PIL branch so this is deterministic across hosts."""
    _force_no_convert(monkeypatch)
    ld = _import_ld()
    top = str(tmp_path / "top.png")
    bottom = str(tmp_path / "bottom.png")
    out = str(tmp_path / "out.png")
    _make_png(top, 120, 40, "red")
    _make_png(bottom, 80, 60, "blue")

    result = ld.stack_vertical(top, bottom, out)

    assert result == out
    with Image.open(out) as im:
        assert im.size == (120, 100)


def test_stack_vertical_missing_input_returns_none(tmp_path):
    """A missing top PNG -> None, no exception, no out file written."""
    ld = _import_ld()
    top = str(tmp_path / "does-not-exist.png")
    bottom = str(tmp_path / "bottom.png")
    out = str(tmp_path / "out.png")
    _make_png(bottom, 100, 60, "blue")

    result = ld.stack_vertical(top, bottom, out)

    assert result is None
    assert not os.path.exists(out)


def test_stack_vertical_garbage_input_never_raises(tmp_path, monkeypatch):
    """A non-PNG text file passed as an image input -> None, never raises. Forces the PIL
    branch so this doesn't shell out to a real `convert` binary on hosts that have
    ImageMagick installed."""
    _force_no_convert(monkeypatch)
    ld = _import_ld()
    top = str(tmp_path / "top.txt")
    bottom = str(tmp_path / "bottom.png")
    out = str(tmp_path / "out.png")
    with open(top, "w", encoding="utf-8") as fh:
        fh.write("this is not a png\n")
    _make_png(bottom, 100, 60, "blue")

    result = ld.stack_vertical(top, bottom, out)

    assert result is None


class _FakeCompletedProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.stdout = b""
        self.stderr = b""


def test_stack_vertical_uses_convert_branch_when_available(tmp_path, monkeypatch):
    """Real branch-selection test: when shutil.which('convert') resolves to a path,
    stack_vertical must attempt the ImageMagick `convert ... -append` invocation before
    ever touching PIL. Stubs subprocess.run (never a real ImageMagick invocation) to record
    the argv it was called with and write a valid PNG to out_png, then asserts the stub was
    actually invoked with a convert/-append argv and that the function returned out_png via
    that branch."""
    ld = _import_ld()
    top = str(tmp_path / "top.png")
    bottom = str(tmp_path / "bottom.png")
    out = str(tmp_path / "out.png")
    _make_png(top, 100, 40, "red")
    _make_png(bottom, 100, 60, "blue")

    calls = []

    def fake_which(name):
        return "/usr/bin/convert" if name == "convert" else None

    def fake_run(argv, **kwargs):
        calls.append(argv)
        _make_png(out, 100, 100, "green")
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)

    result = ld.stack_vertical(top, bottom, out)

    assert result == out
    assert len(calls) == 1
    assert calls[0][0] == "convert"
    assert "-append" in calls[0]


def test_stack_vertical_rgba_input_converts_to_rgb(tmp_path, monkeypatch):
    """An RGBA-mode top PNG (alpha channel) alongside an RGB bottom PNG exercises the
    `.convert("RGB")` mode-handling path in stack_vertical's PIL branch. Forces the PIL
    branch for determinism and asserts the combined image opens cleanly with the expected
    dimensions."""
    _force_no_convert(monkeypatch)
    ld = _import_ld()
    top = str(tmp_path / "top.png")
    bottom = str(tmp_path / "bottom.png")
    out = str(tmp_path / "out.png")
    Image.new("RGBA", (100, 40), (255, 0, 0, 128)).save(top)
    Image.new("RGB", (100, 60), "blue").save(bottom)

    result = ld.stack_vertical(top, bottom, out)

    assert result == out
    assert os.path.isfile(out)
    assert os.path.getsize(out) > 0
    with Image.open(out) as im:
        assert im.width == max(100, 100)
        assert im.height == 40 + 60
