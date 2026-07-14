# The Kali attack VM and `vm.sh`

Claude Code runs in WSL, which has **no VPN route** to targets and no offensive
tooling. A separate **Kali VM** holds the VPN, the tools (nmap/ffuf/nuclei/nxc,
linpeas, chromium), and is reached over SSH by a one-line driver, `vm.sh`.

```
Claude (WSL) --ssh (vm.sh)--> Kali VM --VPN--> targets
```

## Configure it: one file, `/root/creds.txt`

IP, username, and password all live in `/root/creds.txt` (git-ignored, device-local).
Edit the value on the line under each header:

```
# IP
192.168.1.1
# Username
kali
# Password
your-password
```

`vm.sh` reads all three from here and hardcodes nothing. To point at a new VM, edit
this file only. The script lives at `/root/vm.sh` (device-local, one copy per machine).

## Use it

```bash
bash /root/vm.sh '<remote bash command>'   # runs as root on the VM, output streamed back
bash /root/vm.sh 'nmap -sV -Pn TARGET'
```

## Gotchas

- **No stdin is forwarded.** `local-cmd | vm.sh 'cat > f'` writes an EMPTY file. Push a
  file by base64-ing it INTO the command:
  `B64=$(base64 -w0 f); bash /root/vm.sh "echo $B64 | base64 -d > /tmp/f"`.
  Pull one back: `bash /root/vm.sh 'base64 -w0 /tmp/f' | base64 -d > local`.
- **No persistent state.** Each call is a fresh SSH session; `cd` and vars do not carry.
  Chain steps with `;` / `&&` in one call.
- **Long FOREGROUND commands get dropped (exit 255, no output).** A single `vm.sh '<cmd>'`
  running more than ~2 min (scan / crack / spray / brute) has its SSH cut mid-run. Detach and
  poll a file instead: a tmux tab (`scripts/vm-scan.sh <eng> <target> '<cmd>'`), or
  `nohup <cmd> >/tmp/out 2>&1 &` then poll `for i in $(seq 1 60); do grep -q DONE /tmp/out && break; sleep 3; done`.
  When pushing a script then running it, do BOTH in one call (write races the run otherwise).
- **Runs as root**, `ConnectTimeout=10` (fails fast). A `Permission denied` means
  `/root/creds.txt` is stale.

## Running scans in tmux + capturing the desktop

Scans run in a root tmux session on the VM (persistent across `vm.sh` calls), one named
tab per target: `bash scripts/vm-scan.sh <eng> <target> '<scan>'`. Capture a tab as a
terminal card with `shot.py --tmux <eng>:<target>`; capture a GUI app / the desktop with
`shot.py --window "Name"` / `--screen`. Capture by the `window=@NN` id (or the sanitized
tab name) that `vm-scan.sh` prints, not the raw dotted target (a dot in the target
collides with tmux's `session:window.pane` syntax).

GUI grabs need the desktop's X session: shot.py resolves the seat user/display from `who`,
unlocks via `loginctl unlock-session`, wakes with `xset dpms force on`, and grabs as that
user with `XAUTHORITY` (a bare `scrot` as root-over-SSH fails with "Can't open X display").
Install the deps once with `bash scripts/vm-provision.sh` (also run by `setup/bootstrap.sh`).
This installs the screenshot/tmux capture deps AND the recon + test toolchain the
recon-capture nudges point at (apt-first; `bash scripts/vm-provision.sh --list` prints the set,
and the final line prints a verify one-liner). It is per-package tolerant, so a name that is not
in your Kali release's repo is reported `MISS` rather than aborting the run.

## Secrets boundary

The VM IP and password live only in `/root/creds.txt` (device-local). Never write them
into `docs/`, `wiki/`, `session/`, scripts, or commits. Target specifics stay under
`targets/<eng>/`.
