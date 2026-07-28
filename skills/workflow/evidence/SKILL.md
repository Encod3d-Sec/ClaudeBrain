---
name: evidence
description: Evidence hygiene before any FIND moves to Completed or enters a report. Cookie redaction, PII black-bar, HAR sanitization, screenshot metadata strip. Run after /triage passes and before final report assembly.
---

# Evidence: PoC Capture & Redaction Discipline

Run this BEFORE attaching any screenshot, HAR, or request/response to a finding report.

---

## Pre-Screenshot Checklist
```
[ ] Network tab Headers panel collapsed or out of frame
[ ] Burp Request panel hidden behind divider
[ ] No "Copy as cURL" output visible on screen
[ ] DevTools Application -> Cookies tab closed
[ ] Browser URL bar does not show a session token in query string
```

## Cookie / Token Redaction

**Must redact:**
- Session cookie value (authn, session, sid, __Secure-id, etc.)
- CSRF tokens bound to the session
- Authorization headers (Bearer tokens, JWT)
- Cookie and Set-Cookie header values for session-bearing cookies

**Safe to leave:**
- Cloudflare cookies (__cf_bm, _cfuvid)
- Analytics cookies (_ga, ajs_anonymous_id)
- Trace IDs (x-datadog-trace-id, x-request-id) - help triager correlate logs

**Redaction method:** black rectangle annotation over the cookie value in your image editor. OR use DevTools `credentials: 'include'` in fetch PoC so cookies never appear in the screenshot.

## HAR Sanitization
```bash
# Save this as ~/bin/sanitize_har
sanitize_har() {
  local input="$1"
  local output="${1%.har}.sanitized.har"
  jq '
    .log.entries |= map(
      (.request.headers |= map(
        if .name | ascii_downcase | IN("cookie", "authorization", "x-csrf-token")
        then .value = "<REDACTED>" else . end
      )) |
      (.response.headers |= map(
        if .name | ascii_downcase | IN("set-cookie") then .value = "<REDACTED>" else . end
      )) |
      (.request.cookies |= map(.value = "<REDACTED>")) |
      (.response.cookies |= map(.value = "<REDACTED>"))
    )
  ' "$input" > "$output"
  echo "Sanitized: $output"
}
# Verify:
grep -i 'authorization\|"cookie"\|set-cookie' "${1%.har}.sanitized.har" | head -5
```

## PII Black-Bar Protocol

When PoC exposes another user's data (IDOR, etc.):
- Mask: real names, email local part, phone last 7 digits, addresses, faces
- Leave: JSON key names, your own test-account UID, trace IDs, request shape

In report body: state "Real PII fields masked with black rectangles per responsible-disclosure hygiene. Unredacted version available on request."

## Screenshot Filename Convention
```
FIND-XXX-step1-pre-state.png
FIND-XXX-step2-exploitation.png
FIND-XXX-step3-post-state.png
```

## Post-Capture
```
[ ] Open screenshot at full resolution -- search for cookie name substring
[ ] Confirm no internal IPs visible that shouldn't be in report
[ ] Rotate test account credentials after report submission
```
