# Live Setup Log — Okta Developer Org

Both federation apps in this repo were configured for real against a live Okta org.
Org-specific identifiers (org URL, client ID, SAML app ID, IdP metadata URL) are
**omitted from this public repo** per the security-hygiene rule — they live only in the
Okta org. Redacted screenshots go in this folder (see `CAPTURE-CHECKLIST.md`).

## OIDC app — `iam-portfolio-oidc-rp` (verified on screen)

Matches `src/oidc-rp/` exactly:
- Sign-in method: **OIDC – OpenID Connect**, application type **Single-Page Application**
  (public client).
- **Client authentication: None** and **"Require PKCE as additional verification"
  enabled** — this is the public-client-with-PKCE design the repo leads with; there is no
  client secret to leak.
- Grant type: **Authorization Code** (Auth Code + PKCE).
- Sign-in redirect URI: `http://localhost:5001/authorization-code/callback` — the exact
  callback route the Flask RP serves.
- Sign-out redirect URI: `http://localhost:5001`.
- Assignment: everyone in the org (Federation Broker Mode) so the test user can sign in.

To run the RP against it: `export OKTA_ISSUER=https://<your-org>.okta.com/oauth2/default`
and `export OKTA_CLIENT_ID=<the client id>`, then `python3 src/oidc-rp/app.py`. No secret
needed — the app runs as a public client with PKCE.

## SAML app — `iam-portfolio-saml-sp` (verified on screen)

Matches `src/saml-sp/` exactly:
- Sign-in method: **SAML 2.0**.
- **Single sign-on URL (ACS):** `http://localhost:5002/acs` (also used as Recipient and
  Destination) — the SP's Assertion Consumer Service route.
- **Audience URI (SP Entity ID):** `http://localhost:5002/metadata` — matches the SP's
  EntityID and the `<Audience>` the SP validates against.
- **Name ID format: EmailAddress** — matches the `emailAddress` NameID the SP expects and
  the annotated assertion in `docs/ANNOTATED-SAML-ASSERTION.md`.
- Okta publishes an IdP metadata URL and signing certificate for the app; point
  `SAML_IDP_SSO_URL` at the app's SSO URL and save the cert to `./okta.cert`, then
  `python3 src/saml-sp/app.py`.

## Attestation

Both app integrations above were created interactively in the live Okta admin console
for this portfolio, with the ACS / redirect / audience / PKCE settings wired to match the
SP and RP code in this repo. The reproducible steps are in `docs/EXECUTION-GUIDE.md`; this
log plus the redacted screenshots are the evidence they were actually performed.
