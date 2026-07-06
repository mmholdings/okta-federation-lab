# Federation Troubleshooting — 6 Failures You Will Actually Hit

Each is symptom → diagnosis → fix. These are the ones that eat afternoons; knowing them
cold is most of what separates "I've read about SAML" from "I've debugged SAML."

## 1. Clock skew

**Symptom:** intermittent auth failures, worse right after a server reboot or on one
node of a load-balanced SP. SAML: "assertion not yet valid" / "assertion expired."
OIDC: "token expired" moments after issue.
**Diagnosis:** the SP/RP clock disagrees with the IdP. SAML assertions live ~5 minutes
(`NotBefore`/`NotOnOrAfter`); a 3-minute clock drift eats most of that window and any
network latency tips it over. The give-away is that it's intermittent and correlates
with one host.
**Fix:** NTP on every SP/RP host — this is the actual root cause 90% of the time.
Allow a small validation skew (my validators use ±120s) but don't paper over a real
drift with a huge tolerance; fix the clock.

## 2. Audience mismatch

**Symptom:** SAML "audience mismatch" / assertion rejected; OIDC `aud` validation fails.
Auth at the IdP succeeds, the SP/RP refuses the token.
**Diagnosis:** the IdP's configured Audience/Client ID doesn't equal what the SP/RP
expects. In Okta's SAML app the "Audience URI (SP Entity ID)" field must byte-match the
SP's EntityID — including trailing slash and http-vs-https. For OIDC, the token's `aud`
must contain your client ID.
**Fix:** make them identical. Copy-paste, don't retype. `http://localhost:5002/metadata`
≠ `http://localhost:5002/metadata/`. This is a config typo 99% of the time.

## 3. Certificate rotation

**Symptom:** SSO worked for months, then every user fails signature validation at once,
starting at a specific timestamp.
**Diagnosis:** the IdP rotated its signing certificate and the SP is still pinned to the
old one. SAML SPs that store the IdP cert as a static file are the usual victims. OIDC
is more resilient because the RP fetches the current key from `jwks_uri` by `kid` —
unless someone cached JWKS forever.
**Fix:** update the SP's stored IdP cert (Okta publishes rotation schedules; some SPs
support consuming IdP metadata by URL so rotation is automatic — prefer that). For OIDC,
never cache JWKS beyond its `Cache-Control`; re-fetch on an unknown `kid`. Longer term:
subscribe to the IdP's cert-rotation notifications so this is planned, not a Sunday
outage.

## 4. Redirect URI / ACS URL mismatch

**Symptom:** OIDC: Okta shows "The redirect URI is not registered." SAML: assertion
posts to the wrong place, or "Recipient" validation fails.
**Diagnosis:** the callback URL the app sends doesn't exactly match what's registered in
Okta. OIDC redirect URIs are matched exactly — scheme, host, port, path, no wildcards.
SAML's ACS URL and the assertion's `Recipient` must line up with what the SP sent.
**Fix:** register the exact URL. `http://localhost:5001/authorization-code/callback`
must be listed verbatim in the Okta app's Sign-in redirect URIs. Watch for
`localhost` vs `127.0.0.1` (different origins), and http vs https.

## 5. Attribute mapping

**Symptom:** the user logs in successfully but the app misbehaves — missing role, blank
name, authorization decisions wrong. Auth worked; data is wrong.
**Diagnosis:** the SP/RP expects an attribute/claim by a specific name and the IdP isn't
sending it, or is sending it under a different name. SAML: the app wants `department`,
Okta emits `Department` or `user.department` unmapped. OIDC: the app wants a `groups`
claim but the scope/claim wasn't configured on the authorization server.
**Fix:** align names exactly in the IdP's attribute-statement (SAML) or claims (OIDC)
config. Case-sensitive. For OIDC group/role claims you often must add a custom claim on
the Okta authorization server *and* request the right scope — it won't appear just
because the user has groups.

## 6. Signature validation failure

**Symptom:** SAML "invalid signature" / "signature verification failed" even though the
assertion looks right; or OIDC RS256 verification fails.
**Diagnosis:** several distinct causes wear the same error. (a) Wrong cert — see #3.
(b) The assertion was modified in transit or the SP is verifying the wrong element
(response vs assertion — Okta signs the assertion; verify *that*). (c) Canonicalization
mismatch — the #1 reason hand-rolled SAML verification fails, because the bytes you hash
must be canonicalized exactly per the c14n algorithm. (d) OIDC: `alg` confusion, or JWKS
`kid` not found (→ #3).
**Fix:** use a vetted library for the actual crypto+canonicalization (python3-saml/
xmlsec for SAML, a real JWT lib for OIDC) — this is the one place "roll your own" is a
genuine security bug, not just extra work. Confirm you're verifying the signed element,
against the current IdP cert, with the algorithm the IdP actually used. My SP fails
*closed* — no verified signature means the assertion is rejected, never trusted.

---

**Meta-tip:** the fastest SAML debugging tool is a browser SAML tracer extension (or the
Okta System Log) to capture the raw base64 assertion, then decode it and read the
elements from the annotated guide. For OIDC, decode the JWT at a local decoder (never
paste real tokens into a public site) and check the claims one by one. Nine times out
of ten the decoded token tells you exactly which value doesn't match.
