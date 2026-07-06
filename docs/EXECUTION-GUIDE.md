# Execution Guide — Okta Federation Lab

You can prove the security logic with zero setup, then wire it to a real Okta org.

## Step 0 — Offline self-tests (no Okta, no network, ~1 min)

Both apps ship an offline `--selftest` that exercises the security-critical validation
by minting and mutating tokens/assertions locally:

```
pip install flask requests pyjwt cryptography     # cryptography needed for OIDC self-test
python3 src/oidc-rp/app.py --selftest
python3 src/saml-sp/app.py --selftest
```

The OIDC test mints its own RSA-signed ID tokens and proves each check (aud, exp,
nonce, issuer, tampered-signature) rejects the right forgery. The SAML test builds
Responses and proves audience/recipient/InResponseTo/expiry/unsigned all get rejected.
If these pass, the validation logic is sound before a single credential exists.

## Step 1 — Okta Developer Edition org (free)

Sign up at developer.okta.com. You get a full org at `https://dev-XXXXXX.okta.com`.
Create one test user (or use your admin user) and set a password — that's your
federated identity.

## Step 2 — OIDC app (Authorization Code + PKCE)

1. Okta Admin → Applications → Create App Integration → **OIDC - Web Application** (or
   SPA if you want a pure public client). Grant type: Authorization Code.
2. Sign-in redirect URI: `http://localhost:5001/authorization-code/callback` (exact —
   see troubleshooting #4).
3. Assign the app to your user.
4. Run it:
   ```
   export OKTA_ISSUER=https://dev-XXXXXX.okta.com/oauth2/default
   export OKTA_CLIENT_ID=<client id from Okta>
   # For a Web App (confidential client), also:
   export OKTA_CLIENT_SECRET=<secret>
   # For SPA / public client, omit the secret - the app uses PKCE alone.
   python3 src/oidc-rp/app.py
   ```
5. Browse to `http://localhost:5001`, sign in, and `/profile` shows the **validated**
   ID token claims. Compare them against docs/ANNOTATED-TOKENS-OIDC.md.

## Step 3 — SAML app

1. Okta Admin → Applications → Create App Integration → **SAML 2.0**.
2. Single sign-on URL (ACS): `http://localhost:5002/acs`. Audience URI (SP Entity ID):
   `http://localhost:5002/metadata`. (Both must byte-match — troubleshooting #2.)
3. Attribute statements: add `department` and `displayName` mapped from Okta profile
   (`user.department`, `user.displayName`). These are what the SP reads.
4. Finish, then on the Sign-On tab grab the **IdP metadata / signing certificate** and
   the **Identity Provider Single Sign-On URL**. Save the cert to `./okta.cert`.
5. Assign the app to your user. Run it:
   ```
   export SAML_IDP_SSO_URL=https://dev-XXXXXX.okta.com/app/xxxxx/sso/saml
   export SAML_IDP_CERT_PATH=./okta.cert
   # optional but recommended for real signature verification:
   pip install signxml
   python3 src/saml-sp/app.py
   ```
6. Browse to `http://localhost:5002`, sign in, and `/profile` shows the **validated**
   assertion attributes. Compare against docs/ANNOTATED-SAML-ASSERTION.md.

**Signature note:** without `signxml` installed the SP fails *closed* — it rejects the
assertion because it cannot verify the signature. That's deliberate (never trust an
unverified assertion). Install `signxml` and point `SAML_IDP_CERT_PATH` at Okta's cert
for real end-to-end signature validation.

## Capture your evidence (redact first)

Grab the SAML tracer output and the decoded ID token per
[evidence/CAPTURE-CHECKLIST.md](../evidence/CAPTURE-CHECKLIST.md). **Never paste real
tokens into a public online decoder** — decode locally.

## Pre-commit checklist

- [ ] No client secret, no real issuer/org URL, no `okta.cert` committed (all gitignored)
- [ ] No real ID token / assertion base64 in committed files or screenshots
- [ ] Screenshots redact the org subdomain and any real UPN
- [ ] Both `--selftest` runs pass
