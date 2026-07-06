# Annotated OIDC Tokens

Okta's Authorization Code + PKCE flow returns an **ID token** and an **access token**.
They do different jobs and get validated differently. Below is each one decoded, claim
by claim, from the lab.

## ID token (a JWT) — proves *who authenticated*

The ID token is for the RP (my app). It answers "who is this user and did they just
authenticate here." Three base64url segments: `header.payload.signature`.

**Header**
```json
{ "alg": "RS256", "kid": "k8sT...Q2", "typ": "JWT" }
```
- `alg` — RS256. My validator rejects anything else; accepting `alg: none` or letting
  the token pick its own algorithm is a classic JWT vulnerability.
- `kid` — which key in Okta's JWKS signed this. I fetch `jwks_uri`, find the matching
  `kid`, verify with that public key. When Okta rotates signing keys, the `kid` changes
  and my JWKS lookup follows it automatically — hard-coding a key is how federation
  breaks silently three months later.

**Payload (claims)**
```json
{
  "iss": "https://dev-1234.okta.com/oauth2/default",   // (1) issuer
  "aud": "0oa1b2c3EXAMPLE",                             // (2) MY client id
  "sub": "00u9xr4...",                                  // (3) stable user id
  "iat": 1750000002,                                    // (4) issued at
  "exp": 1750003602,                                    // (5) expires (1h)
  "auth_time": 1750000000,
  "nonce": "kY2...fromMyLoginRequest",                  // (6) anti-replay
  "email": "jsmith@bayline.example",
  "email_verified": true,
  "name": "Jordan Smith",
  "preferred_username": "jsmith@bayline.example"
}
```
1. **iss** — must be exactly my Okta authorization server. Guards against a token from
   some other issuer.
2. **aud** — must contain my client ID. "Is this token minted for me?" A token for a
   different app is not mine to trust.
3. **sub** — the stable, opaque user identifier. This is what I key the account on, not
   email (emails change; `sub` doesn't).
4/5. **iat / exp** — issued-at and expiry. Reject expired tokens (small skew allowed).
6. **nonce** — I generated this at `/login` and stored it in the session; the token
   must echo it back. This binds the token to *my* specific login request and kills
   replay of a captured token. It's the OIDC equivalent of SAML's InResponseTo.

My RP validates all six plus the RS256 signature before it trusts a single claim —
`validate_id_token()` in `src/oidc-rp/app.py`, and the offline self-test proves each
check rejects the corresponding forgery.

## Access token — proves *what you're allowed to call*

The access token is for calling APIs (e.g. Okta's `/userinfo`, or your own resource
server). Critical distinction that trips people up: **the RP does not validate the
access token as if it were an ID token.** In Okta's default authorization server the
access token is also a JWT and looks like this:

```json
{
  "iss": "https://dev-1234.okta.com/oauth2/default",
  "aud": "api://default",                    // the RESOURCE, not my client id
  "sub": "jsmith@bayline.example",
  "scp": ["openid", "profile", "email"],     // granted scopes - what it authorizes
  "cid": "0oa1b2c3EXAMPLE",                  // the client that got it
  "exp": 1750003602
}
```

- `aud` here is the **resource/API**, not my client ID — because the token is meant to
  be *presented to* that API, which validates it.
- `scp` (scopes) is the authorization payload: it says what the bearer may do.
- Whoever *receives* this token (the resource server) validates it. As the RP that
  merely obtained it, I treat it as opaque and just forward it — reading its claims to
  make authz decisions in the client is an anti-pattern.

## The one-sentence version for an interview

"ID token = authentication, audience is my client, I validate it (sig/iss/aud/exp/
nonce). Access token = authorization, audience is the API, the resource server
validates it, I just carry it. Conflating the two is the most common OIDC mistake."
