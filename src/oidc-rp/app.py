#!/usr/bin/env python3
"""
Minimal OIDC Relying Party (RP) that federates to Okta using Authorization Code
flow WITH PKCE. Self-contained: standard-library HTTP client + Flask, no OIDC
SDK, specifically so every step of the flow is visible and defensible in an
interview. An SDK is the right production choice; hand-rolling is the right
learning choice.

Flow implemented:
  1. /login  -> build authz request with state, nonce, PKCE code_challenge (S256)
  2. Okta authenticates the user, redirects to /authorization-code/callback
  3. we validate state, exchange code + code_verifier at the token endpoint
  4. we validate the ID token (signature via Okta JWKS, iss, aud, exp, nonce)
  5. /profile shows the decoded claims

Config comes from environment (never hard-coded). Client secret is optional:
this is written to work as a PUBLIC client with PKCE and no secret, which is
the modern default; if you register a confidential client, set OKTA_CLIENT_SECRET
and it'll be used at the token endpoint too.

Run:
  pip install flask requests pyjwt cryptography
  export OKTA_ISSUER=https://dev-XXXX.okta.com/oauth2/default
  export OKTA_CLIENT_ID=0oaXXXX
  # optional: export OKTA_CLIENT_SECRET=...
  python3 app.py      # http://localhost:5001

There's also a self-test that needs no Okta at all:
  python3 app.py --selftest      # exercises PKCE + ID-token validation offline
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import time

# ---- PKCE + validation primitives (pure stdlib; unit-tested by --selftest) ----

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_pkce():
    """RFC 7636: high-entropy verifier, S256 challenge. This pair is what stops
    an intercepted authorization code from being redeemed by an attacker."""
    verifier = b64url(secrets.token_bytes(64))          # 43-128 chars, unreserved
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def validate_id_token(id_token, jwks, issuer, client_id, nonce, now=None):
    """
    Validate an OIDC ID token the way an RP must, and explain each check. Returns
    the decoded claims or raises ValueError. Signature verification uses the RS256
    public key from Okta's JWKS by kid.
    """
    now = now or int(time.time())
    header_b64, payload_b64, sig_b64 = id_token.split(".")
    header = json.loads(b64url_decode(header_b64))
    claims = json.loads(b64url_decode(payload_b64))

    # 1. signature - the token is worthless if we don't verify Okta actually signed it
    key = next((k for k in jwks["keys"] if k["kid"] == header["kid"]), None)
    if not key:
        raise ValueError(f"no JWKS key matches kid {header['kid']} (cert rotation?)")
    _verify_rs256(f"{header_b64}.{payload_b64}".encode(), b64url_decode(sig_b64), key)

    # 2. issuer - must be exactly our Okta authorization server
    if claims["iss"] != issuer:
        raise ValueError(f"iss mismatch: {claims['iss']} != {issuer}")
    # 3. audience - the token must be minted FOR us, not some other app
    aud = claims["aud"]
    if client_id not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError(f"aud mismatch: {aud} does not contain {client_id}")
    # 4. expiry (with small skew) - reject stale tokens
    if now >= claims["exp"] + 60:
        raise ValueError("token expired")
    if claims.get("iat", now) > now + 300:
        raise ValueError("iat is in the future beyond skew (clock problem)")
    # 5. nonce - binds this token to OUR login request; kills replay
    if nonce is not None and claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch - possible token replay")
    return claims


def _verify_rs256(signing_input, signature, jwk):
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    n = int.from_bytes(b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    pub.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())


# --------------------------------- self-test ---------------------------------

def selftest():
    """Exercises PKCE and the full ID-token validation offline: we mint our own
    RSA key, publish it as a JWKS, sign a token, and prove each validation check
    fires. No Okta, no network."""
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and cond
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")

    v, c = make_pkce()
    check("PKCE verifier length in 43..128", 43 <= len(v) <= 128)
    check("PKCE S256 challenge reproducible",
          c == b64url(hashlib.sha256(v.encode()).digest()))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_numbers()
    jwks = {"keys": [{
        "kid": "test-1", "kty": "RSA", "alg": "RS256", "use": "sig",
        "n": b64url(pub.n.to_bytes(256, "big")), "e": b64url(pub.e.to_bytes(3, "big")),
    }]}
    iss, aud, nonce = "https://issuer.example/oauth2/default", "0oaTEST", "nonce-123"

    def mint(claims, kid="test-1"):
        h = b64url(json.dumps({"alg": "RS256", "kid": kid}).encode())
        p = b64url(json.dumps(claims).encode())
        sig = key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{b64url(sig)}"

    now = int(time.time())
    good = {"iss": iss, "aud": aud, "exp": now + 3600, "iat": now,
            "nonce": nonce, "sub": "00uABC", "email": "user@bayline.example"}
    claims = validate_id_token(mint(good), jwks, iss, aud, nonce, now)
    check("valid token accepted", claims["email"] == "user@bayline.example")

    for name, mutate in [
        ("wrong aud rejected", lambda c: {**c, "aud": "someone-else"}),
        ("expired token rejected", lambda c: {**c, "exp": now - 3600}),
        ("bad nonce rejected", lambda c: {**c, "nonce": "attacker"}),
        ("wrong issuer rejected", lambda c: {**c, "iss": "https://evil.example"}),
    ]:
        try:
            validate_id_token(mint(mutate(good)), jwks, iss, aud, nonce, now)
            check(name, False)
        except ValueError:
            check(name, True)

    # tampered payload must fail signature
    h, p, s = mint(good).split(".")
    forged_payload = b64url(json.dumps({**good, "email": "admin@bayline.example"}).encode())
    try:
        validate_id_token(f"{h}.{forged_payload}.{s}", jwks, iss, aud, nonce, now)
        check("tampered payload rejected", False)
    except Exception:
        check("tampered payload rejected", True)

    print("ALL CHECKS PASSED" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


# ----------------------------------- app -------------------------------------

def build_app():
    from flask import Flask, session, redirect, request, url_for, jsonify
    import requests

    ISSUER = os.environ["OKTA_ISSUER"].rstrip("/")
    CLIENT_ID = os.environ["OKTA_CLIENT_ID"]
    CLIENT_SECRET = os.environ.get("OKTA_CLIENT_SECRET")  # optional (public client if unset)
    REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:5001/authorization-code/callback")

    meta = requests.get(f"{ISSUER}/.well-known/openid-configuration", timeout=10).json()
    jwks = requests.get(meta["jwks_uri"], timeout=10).json()

    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

    @app.route("/")
    def home():
        who = session.get("claims", {}).get("email")
        return (f"Signed in as {who}. <a href='/profile'>profile</a> | <a href='/logout'>logout</a>"
                if who else "OIDC RP demo. <a href='/login'>Sign in with Okta</a>")

    @app.route("/login")
    def login():
        verifier, challenge = make_pkce()
        session["pkce_verifier"] = verifier
        session["state"] = secrets.token_urlsafe(24)
        session["nonce"] = secrets.token_urlsafe(24)
        params = {
            "client_id": CLIENT_ID, "response_type": "code",
            "scope": "openid profile email", "redirect_uri": REDIRECT_URI,
            "state": session["state"], "nonce": session["nonce"],
            "code_challenge": challenge, "code_challenge_method": "S256",
        }
        from urllib.parse import urlencode
        return redirect(f"{meta['authorization_endpoint']}?{urlencode(params)}")

    @app.route("/authorization-code/callback")
    def callback():
        if request.args.get("state") != session.get("state"):
            return "state mismatch - possible CSRF, request rejected", 400
        if "error" in request.args:
            return f"Okta returned error: {request.args['error']} - {request.args.get('error_description')}", 400
        data = {
            "grant_type": "authorization_code", "code": request.args["code"],
            "redirect_uri": REDIRECT_URI, "client_id": CLIENT_ID,
            "code_verifier": session["pkce_verifier"],
        }
        auth = (CLIENT_ID, CLIENT_SECRET) if CLIENT_SECRET else None
        tok = requests.post(meta["token_endpoint"], data=data, auth=auth, timeout=10).json()
        if "id_token" not in tok:
            return f"token endpoint error: {tok}", 400
        try:
            claims = validate_id_token(tok["id_token"], jwks, ISSUER, CLIENT_ID, session["nonce"])
        except ValueError as e:
            return f"ID token validation failed: {e}", 400
        session["claims"] = claims
        session["raw_id_token"] = tok["id_token"]
        return redirect(url_for("profile"))

    @app.route("/profile")
    def profile():
        if "claims" not in session:
            return redirect(url_for("login"))
        return jsonify({"validated_id_token_claims": session["claims"]})

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    return app


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    build_app().run(host="0.0.0.0", port=5001, debug=False)
