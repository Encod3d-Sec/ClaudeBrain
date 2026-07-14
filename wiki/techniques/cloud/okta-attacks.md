---
title: "Okta Attacks"
type: technique
tags: [okta, federation, identity, account-takeover, phishing, mfa, cloud, lateral-movement]
phase: exploitation
date_created: 2026-06-18
date_updated: 2026-07-02
sources: [okta-security-docs, crowdstrike-okta-attacks]
---

# Okta Attacks

## What it is

Okta is the dominant enterprise IdP; compromising it yields SSO access to every downstream app (AWS, GCP, M365, internal apps) in one move. Attacks split into pre-auth (recon, phishing for a session) and post-compromise (admin abuse for persistence + lateral movement). Complements [[oauth-attacks]], [[saml-attacks]], generic SSO in `hunt-federation`, and Entra in `hunt-m365`.

## Recon

```bash
# org exists / config (unauth)
curl -s https://ORG.okta.com/.well-known/okta-organization
curl -s https://ORG.okta.com/.well-known/openid-configuration   # endpoints, supported flows
# user enumeration via the auth primer / login (timing + error differences)
curl -s https://ORG.okta.com/api/v1/authn -d '{"username":"a@x.com","password":"x"}' -H 'content-type: application/json'
# app + IdP discovery from the login page / OIDC metadata; find custom domains (login.company.com CNAME -> okta)
```

Find the org: SSO links in JS/email headers, `company.okta.com`, custom domains via CT logs / CNAME to `*.okta.com`. Classic (pre-OIE) orgs expose `/api/v1/authn`; Okta Identity Engine (OIE) orgs run the interaction flow at `/idp/idx/introspect` and issue an `idx` interaction handle, so probe both. `.well-known/okta-organization` returns the org `id` and pipeline (`v1` classic vs `idx` OIE), which tells you which auth surface to attack.

## Session and token model (what to steal)

Okta identity is carried by a few artefacts; stealing any live one usually skips MFA:
- **`sid`** cookie on `ORG.okta.com` (or the custom domain): the Okta session. Replay it to hit the dashboard and to silently mint app assertions. This is the crown jewel of an AiTM capture.
- **`DT`** (device token) cookie: binds "remember this device" / reduces MFA prompts; pairs with `sid`.
- **`idx`** interaction handle (OIE) / **`stateToken`** (classic): mid-flow tokens from `/idp/idx/*` or `/api/v1/authn`; a captured `stateToken` mid-MFA can sometimes be advanced without the factor.
- **`sessionToken`**: one-time token from a successful `/api/v1/authn`, redeemable at `/login/sessionCookieRedirect?token=...&redirectUrl=...` to bootstrap a `sid` cookie.
- **OAuth/OIDC**: `access_token`/`id_token`/`refresh_token` from `/oauth2/v1/token` (or a custom authz server `/oauth2/{asId}/v1/token`); refresh tokens are long-lived persistence.
- **`SSWS`** admin API token: `Authorization: SSWS <token>`, survives password and MFA change (see persistence).

## Pre-auth: capture a session

- **AiTM phishing** ([[phishing]] Evilginx/BitB / Muraena): proxy the real Okta login (classic `/api/v1/authn` or OIE `/idp/idx`), capture the post-MFA `sid` session cookie plus `DT`/`idx`. Replaying `sid` bypasses MFA entirely. The highest-success Okta attack; only phishing-resistant factors (FIDO2, Okta FastPass with device binding) break the proxy because the assertion is bound to the real origin.
- **Session/HAR token theft**: stolen browser sessions or HAR files (the 2023 Okta support-case breach pattern) contain live `sid`/OAuth tokens; replay against `ORG.okta.com`. Grep HARs/logs for `sid=`, `Authorization: Bearer`, `access_token`, `idx`.
- **`sessionToken` redemption**: if you obtain a `sessionToken` (e.g. from a leaked `/api/v1/authn` response or ROPC), redeem it: `GET /login/sessionCookieRedirect?token=<sessionToken>&redirectUrl=https://ORG.okta.com/app/UserHome` to plant a full `sid`.
- **MFA fatigue / number-less push**: spam Okta Verify push (`/api/v1/authn/factors/<id>/verify`) until approved, only where number matching is disabled.
- **Help-desk factor reset** (social engineering): convince support to reset a target's MFA, then enroll an attacker factor (the Scattered Spider / LAPSUS$ pattern). See factor abuse below.
- **Phish OIDC/SAML downstream**: open `redirect_uri` / RelayState issues in an Okta-integrated app can leak the SSO assertion or auth code (see [[oauth-attacks]], [[saml-attacks]]).

## Post-compromise: admin abuse + persistence

With a Super Admin (or via privilege-escalation of an over-scoped custom admin role) you drive the Okta API. All calls below take `Authorization: SSWS <token>` or a stolen admin `sid`.

### Persistence
- **Long-lived API token**: `POST /api/v1/api-tokens` (or create in the admin console under Security -> API -> Tokens). An `SSWS` token survives password and MFA change and is not tied to a browser session, the stealthiest backdoor. OAuth service apps with `private_key_jwt` are an even quieter alternative (no visible token, scopes like `okta.users.manage`).
- **Rogue admin / user**: `POST /api/v1/users` an attacker account, then grant a role via `POST /api/v1/users/{id}/roles` (e.g. `SUPER_ADMIN`). Or add your role binding to an existing low-profile service account.
- **Inline/event hooks (token exfil)**: register an `inlineHook` (`POST /api/v1/inlineHooks`, type `com.okta.oauth2.tokens.transform` or `com.okta.saml.tokens.transform`) or an `eventHook` (`POST /api/v1/eventHooks`) pointing at attacker infra. Token-transform hooks see every issued token; password-import hooks (`com.okta.user.credential.password.import`) see cleartext passwords at login.

### Impersonation and factor abuse
- **Sign-in as user** (admin console impersonation): emits `user.session.impersonation.initiate`; noisy but instant access to any user's app tiles.
- **Factor reset + enroll**: `POST /api/v1/users/{id}/lifecycle/reset_factors` wipes the victim's MFA, then enroll an attacker factor via `POST /api/v1/users/{id}/factors` (or let the victim re-enroll through a phished flow). The programmatic version of the help-desk attack.
- **Password + recovery**: `POST /api/v1/users/{id}/lifecycle/reset_password` (returns a reset link, or `sendEmail=false` to get the token silently), or read/replace recovery questions.

### Cross-tenant / inbound federation ("AddFedAdmin")
- Add an **attacker-controlled IdP** as a trusted inbound federation source: `POST /api/v1/idps` (SAML2/OIDC), then map its assertions so an attacker IdP identity resolves to any Okta user. You can now sign in as arbitrary users from your own IdP. This is the Okta cross-tenant impersonation / "second IdP" persistence pattern; pairs with SAML XSW ([[saml-attacks]]) if the trust is misconfigured.
- **Routing rules** (`/api/v1/policies` type `IDP_DISCOVERY`) can silently divert a user population to the rogue IdP.

### Weaken guardrails
- Relax sign-on / MFA policies (`/api/v1/policies`, `/api/v1/policies/{id}/rules`), add an allowlisted **network zone** for your IP (`POST /api/v1/zones`), add a **trusted origin** (`POST /api/v1/trustedOrigins`) to enable CORS token theft, disable ThreatInsight (`/api/v1/threats/configuration`).

### Downstream pivot (the real prize)
- Enumerate integrated apps: `GET /api/v1/apps`. Each is an SSO target reachable from a live `sid` with no further auth.
- **Okta -> AWS**: assume the SAML/OIDC role behind the AWS app; or, without Okta admin, **AWS IAM Identity Center device-code phishing** yields role credentials directly.
- **Okta -> M365 / Entra**: if Okta federates to Entra, pivot with `roadtools` / `hunt-m365`. **Okta -> GCP / internal apps**: same assertion-replay via the app tile.
- Mint app assertions programmatically for any user via an app-embed link / the token-transform hook you planted.

## Detection and defence

- Enforce phishing-resistant MFA (FIDO2/WebAuthn) and Okta FastPass with device binding, defeats AiTM cookie theft because the assertion is origin-bound.
- Number-matching push; bind sessions to device; short session lifetimes; disable persistent `DT`.
- Alert on the System Log (`/api/v1/logs`) for: `system.api_token.create`, new IdP (`system.idp.lifecycle.create`), routing-rule/policy changes, `user.mfa.factor.reset_all` + `user.mfa.factor.activate`, `user.session.impersonation.*`, `user.account.privilege.grant` (admin role grants), new network zone / trusted origin, inline/event hook creation.
- Restrict admin console to trusted network zones; review `user.authentication.*` anomalies; monitor for `SSWS` tokens created outside change windows.

## Tools

`evilginx` / Muraena ([[phishing]]) for AiTM, Okta API (`/api/v1/users`, `/api/v1/apps`, `/api/v1/idps`, `/api/v1/api-tokens`, `/api/v1/logs`, `/api/v1/inlineHooks`) with a stolen `SSWS`/`sid`, `awscli` + SSO for the AWS pivot, `roadtools` + `hunt-m365` if it federates to Entra, `curl`/`jq` for raw API abuse.

## Sources

- Okta security documentation (slug: okta-security-docs) (`https://developer.okta.com/docs/`).
- CrowdStrike / industry write-ups on Okta abuse (Scattered Spider, cross-tenant impersonation) (slug: crowdstrike-okta-attacks).
