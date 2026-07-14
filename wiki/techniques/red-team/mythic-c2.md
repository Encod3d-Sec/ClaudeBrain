---
title: Mythic C2
type: technique
tags: [c2, linux, mythic, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Mythic C2

## What it is

Technical reference for **Mythic C2** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Mythic is an open-source, cross-platform command-and-control framework with a web-based UI that supports multiple agent types (called agents or payloads) and transport profiles (HTTP, WebSocket, DNS). Operators install agents written in various languages and communication profiles (C2 profiles) as Docker containers, then generate payloads for specific targets and manage active sessions through the Mythic web interface. Its modular architecture and plugin-based design make it a flexible alternative to Cobalt Strike for red team operations, supporting diverse evasion and lateral movement capabilities.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Summary

* [Installation](#installation)
* [Agents](#agents)
* [Profiles](#profiles)
* [References](#references)

## Installation

```ps1
sudo apt-get install build-essential
git clone https://github.com/its-a-feature/Mythic --depth 1
./install_docker_ubuntu.sh
./install_docker_debian.sh
cd Mythic
sudo make
sudo ./mythic-cli start
```

## Agents

* [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)

Agents can be found at: [https://github.com/MythicAgents](https://github.com/MythicAgents)

```ps1
./mythic-cli install github https://github.com/MythicAgents/Medusa # A Mythic Agent compatible Python 2.7 and 3.8
./mythic-cli install github https://github.com/MythicAgents/Hannibal # A Mythic Agent written in PIC C
./mythic-cli install github https://github.com/MythicAgents/thanatos # A Mythic C2 agent targeting Linux and Windows hosts written in Rust
./mythic-cli install github https://github.com/MythicAgents/poseidon # A Mythic Agent written in Golang for Linux/MacOS
./mythic-cli install github https://github.com/MythicAgents/Apollo # # A Mythic Agent written in C# using the 4.0 .NET Framework 
./mythic-cli install github https://github.com/MythicAgents/Athena # A Mythic Agent written in .NET
./mythic-cli install github https://github.com/MythicAgents/Xenon # A Mythic Agent written in C, compatible with httpx profiles
```

## Profiles

C2 Profiles can be found at: [https://github.com/MythicC2Profiles](https://github.com/MythicC2Profiles)

```ps1
./mythic-cli install github https://github.com/MythicC2Profiles/httpx
./mythic-cli install github https://github.com/MythicC2Profiles/http
./mythic-cli install github https://github.com/MythicC2Profiles/websocket
./mythic-cli install github https://github.com/MythicC2Profiles/dns
./mythic-cli install github https://github.com/MythicC2Profiles/dynamichttp
./mythic-cli install github https://github.com/MythicC2Profiles/smb
./mythic-cli install github https://github.com/MythicC2Profiles/tcp
```

## SSL

If you want to use SSL, put your key and cert in the `C2_Profiles/HTTP/c2_code` folder and update the `key_path` and `cert_path` variables to have the `names` of those files.

Use Let's Encrypt certbot to get both the key and certificate for your domain:

```ps1
sudo apt install certbot
certbot certonly --standalone -d "example.com" --register-unsafely-without-email --non-interactive --agree-tos
```

Add the file in the Agent container:

```ps1
docker cp /etc/letsencrypt/archive/example.com/fullchain1.pem http:/Mythic/http/c2_code/fullchain.pem
docker cp /etc/letsencrypt/archive/example.com/privkey1.pem http:/Mythic/http/c2_code/privkey.pem
```

Alternatively, if you specify `use_ssl` as true and you don't have any certs already placed on disk, then the profile will automatically generate some self-signed certs for you to use.

## References

* [Mythic Documentation](https://docs.mythic-c2.net)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[httpx]]
- [[medusa]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
