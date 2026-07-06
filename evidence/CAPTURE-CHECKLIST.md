# Evidence Capture Checklist — Okta Federation Lab

## Already committed (no-Okta proof)

- `local-runs/federation-selftests.txt` / `.png` — both apps' offline validation suites:
  OIDC (PKCE + ID-token checks, 8 assertions) and SAML (request build + assertion
  validation, 11 assertions), all passing, minting and mutating tokens locally.

## To capture from a live Okta Developer org (redact first)

**Redaction rules:** blur the org subdomain (`dev-XXXXXX`), any real UPN/email, the
client secret, and never commit a raw ID token or SAML assertion base64. Decode tokens
**locally** — never paste a real token into a public online decoder.

- [ ] `okta-oidc-app-config.png` — the OIDC app's grant type + redirect URI (secret hidden)
- [ ] `okta-saml-app-config.png` — the SAML app's ACS URL, Audience URI, attribute statements
- [ ] `oidc-profile-validated.png` — the RP's `/profile` showing validated ID token claims
- [ ] `oidc-pkce-authorize-request.png` — browser dev tools / network showing the
      `code_challenge` + `code_challenge_method=S256` on the /authorize call (proves PKCE)
- [ ] `saml-profile-validated.png` — the SP's `/profile` showing validated assertion attributes
- [ ] `saml-tracer-assertion.png` — SAML tracer capture of the Response (decode + annotate
      against docs/ANNOTATED-SAML-ASSERTION.md; redact NameID)
- [ ] `okta-system-log-sso.png` — Okta System Log showing the successful SSO events
