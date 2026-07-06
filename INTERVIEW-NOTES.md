# Interview Defense Notes — okta-federation-lab

## Whiteboard: draw BOTH flows (practice each in ~60s)

**OIDC Auth Code + PKCE**
```
App --(1) /authorize: client_id, scope=openid, state, nonce,
             code_challenge=S256(verifier) ------------------> Okta
User authenticates at Okta
Okta --(2) redirect back: ?code=...&state=... --------------> App (verify state)
App --(3) POST /token: code + code_verifier ----------------> Okta
Okta --(4) id_token + access_token -------------------------> App
App validates id_token: sig(JWKS by kid), iss, aud, exp, nonce
```

**SAML SP-initiated**
```
App --(1) AuthnRequest (deflate+redirect), store request ID -> Okta
User authenticates at Okta
Okta --(2) signed Assertion, POST to ACS -------------------> App
App validates: signature, audience, Conditions window,
   Recipient=our ACS, InResponseTo=our request ID
```

## Q1. SAML or OIDC — how do you choose?
Legacy/enterprise SaaS that speaks SAML → SAML, don't fight it. Anything new, especially
mobile/SPA or an app that also calls APIs → OIDC, because it's JSON/JWT, built on OAuth
so you get the access token in the same motion, and PKCE makes it safe for public
clients. Reality is you rarely choose — the vendor's SSO page decides — so an analyst
supports both. (Full matrix in SAML-VS-OIDC.md.)

## Q2. What is PKCE and what attack does it stop?
Proof Key for Code Exchange. The client generates a random `code_verifier`, sends
`SHA256(verifier)` as the challenge on the authorize request, and reveals the verifier
only at token exchange. If an attacker intercepts the authorization code (malicious app
on a phone, redirect interception), they still can't redeem it — they don't have the
verifier. It replaced the deprecated Implicit flow, and Auth Code + PKCE is now the
recommendation for confidential clients too, not just public ones.

## Q3. How do you validate an OIDC ID token? Order matters.
Signature first — fetch JWKS, match the `kid` from the header, verify RS256; reject
`alg:none` and any algorithm the token tries to dictate. Then `iss` equals my Okta auth
server, `aud` contains my client ID, `exp` not passed (small skew), and `nonce` equals
the one I generated at login. Only after all of that do I trust any claim. My RP's
self-test proves each check rejects the matching forgery, including a tampered payload.

## Q4. ID token vs access token?
ID token = authentication, it's for me the client, `aud` is my client ID, I validate it.
Access token = authorization, it's for an API, `aud` is the resource, and the *resource
server* validates it — I just carry it. Conflating them (reading the access token's
claims to make decisions in the client, or validating the ID token as an API token) is
the most common OIDC mistake.

## Q5. In a SAML assertion, what do you validate and why?
Signature (an unsigned assertion is an anonymous claim — cardinal rule, fail closed).
Audience = my SP EntityID ("is this for me"). Conditions NotBefore/NotOnOrAfter (the
clock-skew classic). Recipient = my ACS. InResponseTo = the AuthnRequest ID I sent
(kills unsolicited/replayed assertions). Status = Success. NameID becomes the username.

## Q6. Name three ways federation breaks and how you'd diagnose.
Clock skew (intermittent, correlates to one host → NTP). Cert rotation (worked for
months, then everyone fails signature at once → IdP rotated its signing cert, update the
SP's copy or consume metadata by URL). Attribute mapping (login works but role/name
wrong → IdP claim name ≠ what the app expects, case-sensitive). Diagnosis tool: SAML
tracer or Okta System Log to grab the raw assertion, decode, read it against my
annotated guide — the decoded token almost always names the mismatch.

## Q7. Why did you hand-roll these instead of using an SDK?
To be able to explain every step — which is the interview, and the point of a portfolio.
In production I'd use python3-saml and a mature OIDC middleware. The one thing I did NOT
hand-roll is XML signature verification with canonicalization, because that's a genuine
security minefield (signature-wrapping, c14n bugs) — the app defers that to xmlsec and
fails closed without it. That line — "here's where hand-rolling stops being educational
and starts being a vulnerability" — is one I want to be able to draw.

## Rapid-fire
- Okta signs the SAML *assertion* (not just the response) — verify the assertion element.
- `nonce` (OIDC) and `InResponseTo` (SAML) are the same idea: bind the response to my request.
- Redirect URIs match exactly — localhost ≠ 127.0.0.1, http ≠ https, trailing slash matters.
- SSO ≠ provisioning. SCIM handles lifecycle (that's the JML repo); SSO just authenticates.
- Deprecated Implicit flow put tokens in the URL fragment; Auth Code + PKCE replaced it.
