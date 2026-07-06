# SAML 2.0 vs OIDC — When I Reach for Which

Plain-language version, the way I'd explain it to a hiring manager or a developer
picking a protocol for a new app.

## The one-paragraph answer

SAML and OIDC solve the same core problem — let an app trust an identity provider to
authenticate users — but they come from different eras and shapes. SAML (2005, XML,
built for browser-based enterprise web SSO) is the incumbent for established SaaS and
internal web apps. OIDC (2014, JSON/JWT, built on OAuth 2.0) is the default for
anything new, especially mobile apps, single-page apps, and APIs. If I'm integrating a
legacy enterprise SaaS that offers SAML, I use SAML. If I'm building or integrating
anything modern — mobile, SPA, or an app that also needs to call APIs — I use OIDC.

## Side by side

| | SAML 2.0 | OIDC |
|---|---|---|
| Format | XML assertions | JSON / JWT |
| Built on | Standalone (SOAP-era) | OAuth 2.0 |
| Token | Assertion | ID token (+ access token) |
| "Is this for me?" | `<Audience>` | `aud` claim |
| Anti-replay | `InResponseTo`, `Recipient` | `nonce`, `state` |
| Transport | Browser POST/redirect, front-channel heavy | Redirect + back-channel token exchange |
| Signature | XML-DSig (canonicalization is hard) | JWS (simpler, JWKS key rotation) |
| Sweet spot | Enterprise web SSO, legacy SaaS | Mobile, SPA, APIs, anything new |
| Native mobile | Painful (browser assertions) | Designed for it (PKCE) |
| API authorization | Not its job | Yes (that's the access token) |

## How I actually decide

**Use SAML when:** the target app only speaks SAML (a lot of enterprise SaaS still
does), or it's an internal web app in a shop already standardized on SAML. Don't fight
it — SAML SSO to a browser web app is mature and works.

**Use OIDC when:** it's a mobile or single-page app (SAML's XML-in-the-browser model
fits these badly; OIDC + PKCE was designed for exactly them), the app also needs to
call APIs on the user's behalf (OIDC gives you the OAuth access token in the same
motion — SAML has no equivalent, you'd bolt on a second protocol), or it's simply new
and you get to choose. OIDC is the strategic default.

**The PKCE point**, because it comes up: PKCE (Proof Key for Code Exchange) is what
makes OIDC's Authorization Code flow safe for public clients — mobile apps and SPAs
that can't hold a secret. The app generates a random `code_verifier`, sends its SHA-256
hash up front, and reveals the verifier only at token exchange. An attacker who
intercepts the authorization code can't redeem it without the verifier. The old
Implicit flow (tokens straight in the redirect) is deprecated; **Auth Code + PKCE is
the modern answer for everyone**, confidential clients included. My OIDC app uses it.

## The honest caveats

- SAML isn't "insecure" and OIDC isn't automatically "more secure." SAML's hard part is
  XML signature validation and canonicalization (signature-wrapping attacks are real) —
  which is exactly why you use a vetted library, never hand-rolled XML crypto. OIDC's
  hard parts are validating the ID token correctly (alg confusion, skipping `aud`/
  `nonce`) and not misusing the access token. Both fail the same way: someone skips a
  validation step.
- "Just use OIDC for everything" ignores that you rarely get to choose for existing
  SaaS — the vendor's SSO page decides. Analyst reality is supporting both.
- Provisioning is a separate axis from SSO. Both often pair with **SCIM** for user
  lifecycle (that's the JML repo's territory); SSO logs a user in, SCIM creates and
  deletes the account. Don't confuse authentication with provisioning.
