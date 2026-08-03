---
title: "Web Cache Attacks (Overview)"
type: technique
tags: [web, web-cache, poisoning, deception, cdn, exploitation]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-wcd]
---

# Web Cache Attacks

## What it is

Umbrella for the two distinct cache bug classes that share one root cause - the **cache key**. Driven by the `hunt-cache` skill. Deep pages: [[web-cache-poisoning]] and [[web-cache-deception]].

- **Cache poisoning** - you find an **unkeyed** input that changes the response (harmful), and the cache serves your poisoned response to everyone. Full detail: [[web-cache-poisoning]].
- **Cache deception** - you trick the cache into storing a **victim's private** response as if it were a static asset, then fetch it. Full detail: [[web-cache-deception]].

## The cache key (root of both)

The cache stores/serves by a **key**, usually `method + host + path + (some) query`. Everything else - most headers, some params, the path *suffix* interpretation - is **unkeyed**. Poisoning abuses unkeyed input that still affects the response; deception abuses a key/origin disagreement about the path.

Fingerprint the cache and its key first:
```
Age: / X-Cache: hit|miss / CF-Cache-Status: / Cache-Control: / Vary:
# vary one input at a time with a cache-buster, watch hit/miss + whether the change persists to a clean request
```
`Param Miner` (Burp) brute-forces unkeyed headers/params (`Guess headers`, `Guess params`).

## Path-confusion detection (deception)
```
/settings/profile;script.js        # cache keys on ;script.js, origin sees /settings/profile
/wcd/..%2fprofile                  # cache stores literal, origin normalizes the traversal
/profile/nonexistent.css           # static suffix -> cache stores the private page
```
Cache stores it as static + origin returns private content = deception.

## CDN / Cloudflare specifics
Cloudflare does not cache HTML by default and caches by **file extension**, not MIME type. Cached extensions: `css js jpg png gif swf pdf zip ...`. **Cache Deception Armor** (off by default) checks that the URL extension matches the returned `Content-Type`. Known gaps:
- `application/octet-stream` bypasses the check.
- `.jpg` may be served as `image/webp`.
Other CDNs (Akamai, Fastly, Varnish, Azure CDN) each have their own key/normalization quirks - test the specific one in front of the target.

## Detection and defence
Cache only truly static, non-personalized responses; mark private responses `Cache-Control: no-store/private`; normalize the path identically at cache and origin; include security-relevant inputs in the cache key or strip them; enable Cache Deception Armor equivalents.

## Tools
`Param Miner` (Burp - unkeyed input discovery), `Web Cache Vulnerability Scanner` (Hackmanit `wcvs`). See [[web-cache-poisoning]], [[web-cache-deception]], [[http-host-header-attacks]].

## Sources
- PayloadsAllTheThings - Web Cache Deception
