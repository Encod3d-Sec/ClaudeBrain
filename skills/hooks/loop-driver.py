#!/usr/bin/env python3
"""Stop hook: render-only evidence-capture drain.

When the model stops, spawn detached render subprocesses for any evidence cards
recon-capture staged during the turn (recon scans, poc/leads, poc/pages, and any
tmux scan tabs) so PoC images render at turn-end. This is CAPTURE, not enforcement:
it NEVER blocks the turn or forces continuation, and it is idempotent/self-gating
(a no-op when nothing is staged). Fails open: any error -> exit 0.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

VM_SH = os.environ.get("VM_SH", "/root/vm.sh")
_RENDER_RETRIES = 3   # bounded per-card render retry: a transient/reaped remote render
                       # (VM slow, process cut short) gets this many attempts before a card
                       # is left staged for a later drain (fail-open, never raises).



def _shq(s):
    """Single-quote a string for a remote shell arg."""
    return "'" + s.replace("'", "'\\''") + "'"


def _try_lock(lockpath, stale=600):
    """Best-effort per-area render lock (prevents two drains rendering the same cards).
    Returns True if the caller may proceed (acquired the lock, reclaimed a STALE one, or ANY
    error - never block rendering on a lock problem). Returns False ONLY when a FRESH lock is
    held by another live drain. Never raises.

    stale=600: each remote render is bounded by a 90s subprocess.run timeout, so a single
    card (term render, plus an optional browser render for a poc/pages combined card) takes
    <= ~180s. drain_pending/drain_pending_tmux heartbeat (touch) the lock's mtime at the top
    of every per-item loop iteration, so a live drain refreshes it at least every ~180s and
    can never reach 600s while still running. A drain that crashed/hung (stopped
    heartbeating) is still reclaimed, just after a wider, safer window."""
    try:
        try:
            fd = os.open(lockpath, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, str(os.getpid()).encode()); os.close(fd)
            return True
        except FileExistsError:
            try:
                age = time.time() - os.path.getmtime(lockpath)
            except OSError:
                return True
            if age > stale:                      # crashed drain -> reclaim
                try: os.remove(lockpath)
                except OSError: pass
                try:
                    fd = os.open(lockpath, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                    os.write(fd, str(os.getpid()).encode()); os.close(fd)
                    return True
                except OSError:
                    return True                  # lost the reclaim race -> still proceed
            return False                          # fresh lock held -> another drain active
    except Exception:
        return True


def _unlock(lockpath):
    try: os.remove(lockpath)
    except Exception: pass


def _parse_card_meta(lines):
    """(cmd, meta, body_text) for a staged card's lines. Line 0 ('# ...') is the
    caption/cmd; an optional line-1 of the form '#meta k=v k=v ...' is parsed to a dict
    and dropped from the body. A card with no leading '#' keeps today's behavior (cmd=None
    -> caller uses the stem; whole content is the body). meta is {} when absent. Never
    raises."""
    try:
        if lines and lines[0].startswith("#"):
            cmd = lines[0].lstrip("# ").strip()
            rest = lines[1:]
            if rest and rest[0].startswith("#meta "):
                meta = {}
                for tok in rest[0][len("#meta "):].split():
                    if "=" in tok:
                        k, v = tok.split("=", 1)
                        meta[k] = v
                body = rest[1:]
            else:
                meta = {}
                body = rest
        else:
            cmd = None
            meta = {}
            body = lines
        return cmd, meta, "\n".join(body)
    except Exception:
        return None, {}, ""


def drain_pending(d, vm=None, area="recon", reqresp=False):
    """Render any staged <area>/.pending/*.txt to terminal-card PNGs on the Kali host
    (chromium lives there) and pull them into <area>/. area='recon' = the bulk scan-card
    firehose (kept out of the curated poc/ arc); area='poc/leads' = curated request/response
    LEAD cards (reqresp coloring, full length). Batched at Stop so the cross-host round-trip
    is amortized. No-op when nothing staged or Kali is unreachable (fail open: leave the
    staged txt for a later Stop)."""
    import base64
    import glob
    import subprocess
    import tempfile
    vm = vm or VM_SH
    parts = area.split("/")
    pend = os.path.join(d, *parts, ".pending")
    if not os.path.isdir(pend):
        return []
    staged = sorted(glob.glob(os.path.join(pend, "[0-9]*.txt")))
    if not staged:
        return []
    lock = os.path.join(pend, ".draining")
    if not _try_lock(lock):
        return []            # a fresh lock is held by another live drain -> skip, don't double-render
    try:
        if not os.path.exists(vm):
            return []
        # push shot.py to Kali once (base64 into the command; vm.sh does not forward stdin)
        shot = os.path.join(os.path.dirname(os.path.dirname(HERE)), "scripts", "shot.py")
        try:
            b64 = base64.b64encode(open(shot, "rb").read()).decode()
            subprocess.run([vm, "mkdir -p /tmp/poc; echo %s | base64 -d > /tmp/shot.py" % b64],
                           capture_output=True, timeout=30)
        except Exception:
            return []
        rendered, manifest = [], []
        for txt in staged:
            try: os.utime(lock, None)   # heartbeat: keep the lock fresh through a slow render
            except Exception: pass
            base = os.path.basename(txt)                    # NNNN-tool-hash.txt
            stem = base[:-4]
            png = stem + ".png"                             # deterministic; matches -o below
            try:
                lines = open(txt, encoding="utf-8", errors="ignore").read().splitlines()
                cmd, meta, body_text = _parse_card_meta(lines)
                if cmd is None:
                    cmd = stem
                # render with explicit -o so the remote PNG name == `png` we read back.
                # lead cards (and, as of Task 2, poc/pages cards) get --reqresp (request/
                # response coloring) + a higher line cap so a full response is not truncated.
                extra = " --reqresp --maxlines 600" if reqresp else ""
                combined_target = (
                    area == "poc/pages" and meta.get("browser") == "1" and meta.get("url"))
                url = meta.get("url") if combined_target else None

                term_data = b""
                if combined_target:
                    # Task 2: the BOTTOM half of a combined page card must be a CLEAN
                    # re-fetch of the URL (a pristine `curl -i`), not the raw staged body --
                    # the staged body is whatever stdout triggered the capture and can carry
                    # shell noise (debug echoes, chained commands). Always request/response
                    # colored: this render is specifically an HTTP request/response, unlike
                    # the general `reqresp` flag which governs the staged-body path below.
                    clean_remote = (
                        "curl -sSi %s > /tmp/poc/%s.txt 2>/dev/null; "
                        "python3 /tmp/shot.py --term /tmp/poc/%s.txt --cmd %s "
                        "--reqresp --maxlines 600 -o /tmp/poc/%s >/dev/null 2>&1; "
                        "base64 -w0 /tmp/poc/%s"
                        % (_shq(url), stem, stem, _shq("curl -sSi " + url), png, png)
                    )
                    try:
                        cp = subprocess.run([vm, clean_remote], capture_output=True, timeout=90)
                        term_data = base64.b64decode(cp.stdout or b"", validate=False)
                    except Exception:
                        term_data = b""

                if len(term_data) < 100:
                    # Not a combined card, or the clean re-fetch failed: fail open to
                    # rendering the staged body, exactly as before Task 2. Bounded retry:
                    # a transient/reaped remote render (VM slow, detached process cut
                    # short) gets up to _RENDER_RETRIES attempts before the card is left
                    # staged for a later drain.
                    tb = base64.b64encode(body_text.encode("utf-8", "ignore")).decode()
                    remote = (
                        "echo %s | base64 -d > /tmp/poc/%s.txt; "
                        "python3 /tmp/shot.py --term /tmp/poc/%s.txt --cmd %s%s "
                        "-o /tmp/poc/%s >/dev/null 2>&1; "
                        "base64 -w0 /tmp/poc/%s"
                        % (tb, stem, stem, _shq(cmd), extra, png, png)
                    )
                    for attempt in range(_RENDER_RETRIES):
                        p = subprocess.run([vm, remote], capture_output=True, timeout=90)
                        term_data = base64.b64decode(p.stdout or b"", validate=False)
                        if len(term_data) >= 100:
                            break
                        if attempt < _RENDER_RETRIES - 1:
                            time.sleep(1)   # tiny bounded backoff between attempts
                    if len(term_data) < 100:            # all attempts failed -> keep staged
                        continue
                final_data = term_data
                # Task 3: poc/pages cards flagged browser=1 get a COMBINED card (a chromium
                # render of the page stacked on top of this term card). Any failure anywhere
                # in this attempt falls back to the plain term_data card computed above --
                # never `continue` here, the text card must still land.
                if combined_target:
                    combined = None
                    try:
                        top_remote = (
                            "python3 /tmp/shot.py %s -o /tmp/poc/%s-top.png >/dev/null 2>&1; "
                            "base64 -w0 /tmp/poc/%s-top.png" % (_shq(url), stem, stem)
                        )
                        tp = subprocess.run([vm, top_remote], capture_output=True, timeout=90)
                        top_data = base64.b64decode(tp.stdout or b"", validate=False)
                        if len(top_data) >= 100:
                            tdir = tempfile.mkdtemp(prefix="ldstack-")
                            top_tmp = os.path.join(tdir, stem + ".top.png")
                            bot_tmp = os.path.join(tdir, stem + ".bot.png")
                            out_tmp = os.path.join(tdir, stem + ".combined.png")
                            try:
                                with open(top_tmp, "wb") as fh:
                                    fh.write(top_data)
                                with open(bot_tmp, "wb") as fh:
                                    fh.write(term_data)
                                out_path = stack_vertical(top_tmp, bot_tmp, out_tmp)
                                if out_path and os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
                                    with open(out_path, "rb") as fh:
                                        combined = fh.read()
                            finally:
                                for tmp in (top_tmp, bot_tmp, out_tmp):
                                    try:
                                        os.remove(tmp)
                                    except OSError:
                                        pass
                                try:
                                    os.rmdir(tdir)
                                except OSError:
                                    pass
                    except Exception:
                        combined = None
                    if combined:
                        final_data = combined
                png_path = os.path.join(d, *parts, png)
                with open(png_path, "wb") as fh:
                    fh.write(final_data)
                # on-disk VERIFY: only clear the staged card once the PNG actually landed
                # (non-empty). A missing/empty file (crashed write, reaped process) means
                # NOT rendered -- leave the txt staged and skip the manifest row so a later
                # drain retries it.
                if not (os.path.isfile(png_path) and os.path.getsize(png_path) > 0):
                    continue
                os.remove(txt)
                rendered.append(png)
                manifest.append("| ![](%s/%s) | %s |" % (area, png, cmd.replace("|", "\\|")[:80]))
            except Exception:
                continue
        if manifest:
            try:
                with open(os.path.join(pend, "manifest.md"), "a", encoding="utf-8") as fh:
                    fh.write("\n".join(manifest) + "\n")
            except OSError:
                pass
        return rendered
    finally:
        _unlock(lock)


def drain_pending_tmux(d, vm=None):
    """Area 2 (always-capture-evidence): for each <session>:<tab> entry staged in
    .pending-tmux (by scripts/vm-scan.sh at launch), render the LIVE tmux pane to a
    terminal-card PNG on the Kali host (shot.py --tmux) and pull it into recon/, then
    clear that entry. Removes reliance on the operator following the
    tmux_capture_guidance() nudge by hand. FAIL-OPEN: if the VM/tmux/shot is
    unreachable or a render errors, the entry is left staged (retried at a later Stop)
    and this returns without raising. Returns the list of PNG basenames rendered."""
    import base64
    import subprocess
    vm = vm or VM_SH
    marker = os.path.join(d, ".pending-tmux")
    if not os.path.isfile(marker):
        return []
    try:
        entries = [ln.strip() for ln in
                   open(marker, encoding="utf-8").read().splitlines() if ln.strip()]
    except OSError:
        return []
    if not entries:
        return []
    lock = os.path.join(d, ".draining-tmux")
    if not _try_lock(lock):
        return []            # a fresh lock is held by another live drain -> skip, don't double-render
    try:
        if not os.path.exists(vm):
            return []
        # push shot.py to Kali once (base64 into the command; vm.sh does not forward stdin)
        shot = os.path.join(os.path.dirname(os.path.dirname(HERE)), "scripts", "shot.py")
        try:
            b64 = base64.b64encode(open(shot, "rb").read()).decode()
            subprocess.run([vm, "mkdir -p /tmp/poc; echo %s | base64 -d > /tmp/shot.py" % b64],
                           capture_output=True, timeout=30)
        except Exception:
            return []
        recon = os.path.join(d, "recon")
        try:
            os.makedirs(recon, exist_ok=True)
        except OSError:
            pass
        rendered, remaining = [], []
        for entry in entries:
            try: os.utime(lock, None)   # heartbeat: keep the lock fresh through a slow render
            except Exception: pass
            tab = entry.strip()
            if ":" not in tab:
                continue   # malformed entry -> drop it, never block on garbage
            try:
                name = "tmux-" + tab.replace(":", "-").replace("/", "-")
                png = name + ".png"
                remote = (
                    "python3 /tmp/shot.py --tmux %s -o /tmp/poc/%s >/dev/null 2>&1; "
                    "base64 -w0 /tmp/poc/%s" % (_shq(tab), png, png)
                )
                data = b""
                for attempt in range(_RENDER_RETRIES):
                    p = subprocess.run([vm, remote], capture_output=True, timeout=90)
                    data = base64.b64decode(p.stdout or b"", validate=False)
                    if len(data) >= 100:
                        break
                    if attempt < _RENDER_RETRIES - 1:
                        time.sleep(1)   # tiny bounded backoff between attempts
                if len(data) < 100:          # all attempts failed -> keep staged, retry later
                    remaining.append(entry)
                    continue
                png_path = os.path.join(recon, png)
                with open(png_path, "wb") as fh:
                    fh.write(data)
                # on-disk VERIFY: only count this entry rendered once the PNG actually
                # landed (non-empty); otherwise keep it in `remaining` for a later drain.
                if not (os.path.isfile(png_path) and os.path.getsize(png_path) > 0):
                    remaining.append(entry)
                    continue
                rendered.append(png)
            except Exception:
                remaining.append(entry)
        try:
            if remaining:
                with open(marker, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(remaining) + "\n")
            else:
                os.remove(marker)
        except OSError:
            pass
        return rendered
    finally:
        _unlock(lock)


def stack_vertical(top_png, bottom_png, out_png):
    """Stack two PNGs vertically (top above bottom) into out_png. Tries ImageMagick
    `convert -append`, then PIL, then gives up. Returns out_png on success, None on any
    failure (caller keeps the two images separate / falls back to the single card). Never
    raises."""
    try:
        if not (os.path.isfile(top_png) and os.path.isfile(bottom_png)):
            return None
        import shutil
        if shutil.which("convert"):
            try:
                import subprocess
                p = subprocess.run(["convert", top_png, bottom_png, "-append", out_png],
                                    capture_output=True, timeout=60)
                if p.returncode == 0 and os.path.isfile(out_png) and os.path.getsize(out_png) > 0:
                    return out_png
            except Exception:
                pass
        try:
            from PIL import Image
            with Image.open(top_png) as top, Image.open(bottom_png) as bottom:
                w = max(top.width, bottom.width)
                h = top.height + bottom.height
                canvas = Image.new("RGB", (w, h), "white")
                canvas.paste(top.convert("RGB"), (0, 0))
                canvas.paste(bottom.convert("RGB"), (0, top.height))
                canvas.save(out_png)
            if os.path.isfile(out_png) and os.path.getsize(out_png) > 0:
                return out_png
        except Exception:
            return None
        return None  # intentional: PIL save succeeded but out_png failed the isfile/size check above
    except Exception:
        return None


def main():
    try:
        sys.stdin.read()          # drain the payload pipe; the render runs regardless of it
    except Exception:
        pass
    # Render any staged evidence cards at turn-end. CAPTURE, not enforcement: spawn
    # detached render subprocesses (a cross-host render would blow the Stop hook budget)
    # and return immediately. Idempotent/self-gating -- a no-op when nothing is staged.
    # NEVER blocks the turn or forces continuation.
    try:
        import _engagement
        d = _engagement.active_dir()
    except Exception:
        d = None
    if not d:
        return
    try:
        import subprocess
        for area in ("recon", "poc/leads", "poc/pages"):  # scan firehose + curated lead/page cards
            pend = os.path.join(d, *area.split("/"), ".pending")
            if os.path.isdir(pend) and any(
                    f.endswith(".txt") and f[:1].isdigit() for f in os.listdir(pend)):
                subprocess.Popen(
                    [sys.executable, os.path.abspath(__file__), "--drain", d, area],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, start_new_session=True)
        tm = os.path.join(d, ".pending-tmux")
        if os.path.isfile(tm) and os.path.getsize(tm) > 0:
            subprocess.Popen(
                [sys.executable, os.path.abspath(__file__), "--drain-tmux", d],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        pass


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--drain":
        try:
            area = sys.argv[3] if len(sys.argv) > 3 else "recon"
            drain_pending(sys.argv[2], area=area, reqresp=(area in ("poc/leads", "poc/pages")))
        except Exception:
            pass
        sys.exit(0)
    if len(sys.argv) >= 3 and sys.argv[1] == "--drain-tmux":
        try:
            drain_pending_tmux(sys.argv[2])
        except Exception:
            pass
        sys.exit(0)
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
