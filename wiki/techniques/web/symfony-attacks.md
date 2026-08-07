---
title: "Symfony Attacks"
type: technique
tags: [symfony, php, framework, access-control, information-disclosure, web, exploitation]
phase: exploitation
date_created: 2026-08-04
date_updated: 2026-08-04
sources: []
---

## What it is

Symfony is a PHP framework whose request lifecycle creates a small set of recurring, framework-specific
weaknesses. They are not bugs in Symfony; they are consequences of default behaviour that applications
inherit unless they opt out. Most are information disclosure or authorization-ordering issues.

## Fingerprinting

- Error bodies are JSON in an envelope the app defines, commonly `{"error":{"code":...,"message":...},"formErrors":[]}`.
- Assets under `/build/` (Webpack Encore) or `/bundles/<bundlename>/`.
- `/js/routing` present means FOSJsRoutingBundle (see below).
- Debug surface, one request each, all normally absent in prod: `/_profiler`, `/_profiler/latest`,
  `/_wdt/x`, `/app_dev.php`, `/config.php`, `/_fragment`.
- `/_fragment` deserves BOTH branches: no `_hash`, and a wrong `_hash`. The ESI fragment handler is
  signed with the app secret, so "accepts an unsigned fragment" and "rejects everything" are different
  findings and one observation cannot tell them apart.

## Argument resolution runs before authorization

**The highest-value Symfony-specific check.** `EntityValueResolver` loads an entity from the database
while resolving controller arguments, in `kernel.controller_arguments` - *before*
`IsGrantedAttributeListener`. Any controller type-hinting an entity (`public function show(User $user)`)
therefore performs a DB lookup before the authorization decision.

The observable result is an existence oracle, no credentials needed:

```
GET /api/admin/user/500      -> 401 "You are not authenticated"     # record EXISTS
GET /api/admin/user/500000   -> 404 "\"App\\Entity\\User\" object not found by
                                     \"...\\ArgumentResolver\\EntityValueResolver\"."  # record ABSENT
```

Three things that are easy to get wrong:

1. **It is not verb-specific.** The ordering is global, so the same leak appears on `DELETE`, `PUT`,
   `POST` and `PATCH` wherever an entity is type-hinted. Probe write verbs with an id **proven not to
   exist** - a missing gate cannot damage a record that is not there.
2. **Reaching the resolver is NOT reaching the mutation.** On the absent-id branch the resolver runs a
   `SELECT`, fails, and the controller body never executes. "The flaw extends to write operations"
   overstates it; what extends is the lookup.
3. **The fix is class-level, not route-level.** `#[IsGranted]` on the controller *class*, or a
   `security.yaml` `access_control` pattern, is evaluated before argument resolution and fixes every
   verb on that controller at once. A per-route fix leaves siblings open - so a report that enumerates
   only the routes it happened to test invites under-scoped remediation.

## Route map disclosure (FOSJsRoutingBundle)

`GET /js/routing` returns every route the bundle exposes, with names, path patterns, methods and
parameter requirements. With `expose: true` left on admin routes this publishes the application's whole
internal API inventory unauthenticated, bulk-export endpoints included.

Two follow-ups worth doing every time:

- **Diff the authenticated map against the anonymous one.** The bundle serves whatever set the app
  exposes, so a larger authenticated map means the public one is a partial disclosure. Byte-identical is
  also a result, and closes the question.
- **Route names the client references but the map omits are usually DEAD, not hidden.** The SPA resolves
  URLs via `Routing.generate(name)` against a singleton populated *only* from `/js/routing`. A name
  absent from the map makes `generate()` throw, so the feature cannot work in the deployed client. Treat
  it as dead front-end code unless a path can be derived another way, and do not fuzz for it.

Paths are stored as a REVERSED token array, not strings: `["text","/api/foo"]` contributes literally,
`["variable","/","[^/]++","id",true]` contributes `/{id}`. Walk the list in reverse to reconstruct.

**Free-text parameters are findable from the map alone.** Routes with no `requirements` entry use the
default `[^/]++` (any non-slash byte); everything else is regex-locked (`\d+`, `\d{11}`, `[\w]+`). Only
the unconstrained ones can carry free text to a controller, so they are the entire reflected-injection
surface, and the map identifies them before you send a single request.

## Telling Symfony's error classes apart

A Symfony app commonly returns three different 404s meaning opposite things. Byte size separates them
reliably; status alone does not.

| Class | Body | Means |
|---|---|---|
| **Router 404** | JSON `No route found for "GET https://..."` | Path is NOT registered. Never reached a controller |
| **Resolver 404** | JSON naming `EntityValueResolver` | Path IS registered; DB queried before authorization |
| **Application 404** | the app's own branded page | A controller ran and threw a generic not-found |

The router 404 is a reliable **path-existence oracle** and the cheapest way to clear guessed paths
without fuzzing. Its size tracks request-URL length, because the message reflects the URL.

Related traps: a `405` with an `Allow` header proves the path matched and only the method was wrong; and
forcing `Accept: application/json` on a non-API route can manufacture a `406` unrelated to the app's real
behaviour - re-issue without your own header before recording anything.

## Verbose exception disclosure

Symfony in production (`APP_DEBUG=0`) returns a *generic* error with no exception text. So a response
containing a class name, method name or filesystem path means the application's own exception listener is
substituting `$exception->getMessage()` into its envelope - an application choice, not framework
behaviour, and so not a third-party-component issue.

The reliable trigger is a **type mismatch on a scalar controller argument**: a route with no `\d+`
requirement feeding `int $id` throws an uncaught `TypeError`, rendered verbatim, disclosing the
fully-qualified class, method, argument name, an absolute deployment path, and a `vendor/...` file and
line usable for version fingerprinting.

- **It tracks argument TYPE, not route.** String-typed parameters degrade gracefully. That is what makes
  it one configuration defect rather than several local bugs, and why a per-route fix misses the rest.
- **A repository method name in the message is extra disclosure** (`findWithSoftDeleted`,
  `findOneIncludingDeleted`): internal API surface, and often that soft-deletion exists.
- If the frame is `expression-language/Node/GetAttrNode.php`, an ExpressionLanguage expression was being
  evaluated. Security expressions are the common case, but routing conditions, DI and validation also use
  it - do not claim the authorization check crashed without establishing which expression threw.

## Mass assignment and the Forms layer

Symfony Forms default to `allow_extra_fields: false`, which **rejects the whole request** when an unknown
field is present rather than ignoring it. A response along the lines of "the form cannot have additional
fields" is a strong *negative*: mass assignment is closed at the form layer and further field-guessing
will not change it. Recognise it and stop.

Where an endpoint does not use the Forms component, the usual check applies: submit the client's own
legitimate key set plus one injected privilege key at a time, and treat a *changed validation error* as
evidence the field was bound.

## HTTP method override

`Request::enableHttpMethodParameterOverride()` makes Symfony honour `X-HTTP-Method-Override` and a
`_method` parameter. Test it by sending `POST` to a route registered only for `DELETE`:

- plain `POST` -> `405` with `Allow: DELETE` (router refuses)
- `POST` + `X-HTTP-Method-Override: DELETE` -> whatever the native `DELETE` would return

If the second reaches the authorization gate, the override **is active**. That is not itself a bypass; it
matters only if some gate keys on the HTTP verb. Distinguish "the override is disabled" from "the
override works but every gate is verb-agnostic" - they look identical from a single observation, and only
the second leaves a latent hazard for any future verb-keyed rule (a firewall `methods:` entry, a proxy
ACL, a WAF rule). See [[csrf]] for the override's other uses.

## Related

- [[access-control]] - the class the argument-resolution ordering belongs to
- [[api-security]], [[api-testing]] - route-map-driven API enumeration
- [[information-disclosure]] - verbose error handling generally
- [[csrf]] - `X-HTTP-Method-Override` as a CSRF primitive

<!-- promoted-slug: symfony-attacks -->
