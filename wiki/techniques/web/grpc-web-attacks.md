---
title: "gRPC-Web Attacks"
type: technique
tags: [grpc, grpc-web, api, cors, transcoder, protobuf, web]
phase: exploitation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-web]
---

# gRPC-Web Attacks

## What it is

gRPC-Web is browser-compatible gRPC carried over HTTP/1.1 or HTTP/2 through a proxy (Envoy, APISIX, grpcwebproxy). Two content types: `application/grpc-web` (binary) and `application/grpc-web-text` (base64). Attack surface: reflection-based method enumeration, CORS misconfiguration on the proxy, and gRPC-JSON transcoders that expose methods as unauthenticated HTTP JSON. Related: [[api]], [[parser-differentials]].

## How it works

Each message is a 5-byte frame (1 flag byte + a 4-byte big-endian length) followed by the protobuf payload. Trailers (`grpc-status`, `grpc-message`) ride in a body frame whose first byte has the MSB set (`0x80`). Text mode survives HTTP/1.1 intermediaries that break binary streaming.

## Methodology

### Enumerate and call with buf

```bash
# enumerate methods via server reflection
buf curl --protocol grpcweb https://host.tld --list-methods
# call a method with JSON; framing handled automatically
buf curl --protocol grpcweb -H 'Origin: https://evil.tld' \
  -d '{"field":"value"}' https://host.tld/pkg.svc.v1.Service/Method
```

### Hand-craft and tamper frames

Decode, edit, and re-encode with grpc-coder from the grpc-pentest-suite:

```bash
echo "AAAAABYSC0FtaW4gTmFzaXJp..." | python3 grpc-coder.py --decode --type grpc-web-text | protoscope > out.txt
# edit field values in out.txt, inject payloads e.g. 7: {"<script>alert(origin)</script>"}
protoscope -s out.txt | python3 grpc-coder.py --encode --type grpc-web-text
```

Recover services/methods/field-numbers from the shipped JS bundle:

```bash
python3 grpc-scan.py --file main.js
```

### Transcoder and CORS abuse

Test the gRPC-JSON transcoder by hitting the gRPC path with plain JSON (auth/route mismatches are common) and check whether unknown methods are forwarded upstream:

```bash
curl -i https://host.tld/pkg.svc.v1.Service/Method -H 'Content-Type: application/json' -d '{"field":"value"}'
# CORS preflight - vulnerable proxies reflect Origin + Allow-Credentials: true
curl -i -X OPTIONS https://host.tld/pkg.svc.v1.Service/Method -H 'Origin: https://evil.tld' \
  -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type,x-grpc-web,x-user-agent'
```

## Tools
- `buf` - reflection listing and JSON calls with automatic framing.
- grpc-pentest-suite (`grpc-coder.py`, `grpc-scan.py`), `protoscope` - frame decode/encode and JS-bundle method recovery.

## Sources
- HackTricks (pentesting-web) (slug: hacktricks-web).
