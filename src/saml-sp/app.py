#!/usr/bin/env python3
"""
Minimal SAML 2.0 Service Provider (SP) that federates to Okta via SP-initiated
SSO with HTTP-Redirect (request) + HTTP-POST (response) bindings.

Like the OIDC app, this is deliberately dependency-light so the security-critical
steps are visible rather than hidden in a library. The one thing I will NOT
hand-roll for real is XML signature verification with full XML canonicalization -
that's a minefield (XML canonicalization + signature-wrapping attacks), and in
production I'd use python3-saml/xmlsec, which this app documents and can defer to
if installed. What I DO implement and test offline is the assertion-validation
LOGIC an analyst must be able to reason about: audience, conditions/NotOnOrAfter,
InResponseTo, recipient, and the fact that an unsigned assertion is worthless.

Endpoints:
  /login    -> build + deflate + redirect a SAML AuthnRequest to Okta SSO URL
  /acs      -> Assertion Consumer Service: parse the POSTed Response, validate,
               establish a session
  /metadata -> serve SP metadata XML for pasting into Okta
  /profile  -> show the validated assertion attributes

Config from environment. Run:
  pip install flask
  export SAML_IDP_SSO_URL=https://dev-XXXX.okta.com/app/XXX/sso/saml
  export SAML_IDP_ENTITY_ID=http://www.okta.com/XXX
  export SAML_IDP_CERT_PATH=./okta.cert   # X.509 the IdP signs with
  python3 app.py    # http://localhost:5002

Offline self-test (no Okta, no network):
  python3 app.py --selftest
"""
import base64
import os
import sys
import zlib
from datetime import datetime, timezone, timedelta

SP_ENTITY_ID = os.environ.get("SAML_SP_ENTITY_ID", "http://localhost:5002/metadata")
SP_ACS_URL = os.environ.get("SAML_SP_ACS_URL", "http://localhost:5002/acs")


# ---------------------------- request construction ---------------------------

def build_authn_request(idp_sso_url, request_id=None, issue_instant=None):
    """A SAML AuthnRequest. In HTTP-Redirect binding it's DEFLATE-compressed then
    base64+URL-encoded into the SAMLRequest query param. request_id must be
    retained by the SP and matched against the response's InResponseTo."""
    request_id = request_id or "_" + base64.b16encode(os.urandom(16)).decode().lower()
    issue_instant = issue_instant or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'Destination="{idp_sso_url}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'AssertionConsumerServiceURL="{SP_ACS_URL}">'
        f'<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>'
        f'<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" '
        f'AllowCreate="true"/>'
        f'</samlp:AuthnRequest>'
    )
    return request_id, xml


def deflate_and_encode(xml):
    """HTTP-Redirect binding wire format: raw DEFLATE (no zlib header) -> base64."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    deflated = compressor.compress(xml.encode()) + compressor.flush()
    return base64.b64encode(deflated).decode()


# ---------------------------- response validation ----------------------------

class SamlValidationError(Exception):
    pass


def validate_assertion(root, expected_audience, expected_acs, in_response_to_sent,
                       now=None, require_signature=True, signed_ok=True):
    """
    Validate a parsed SAML Response's assertion against the SP's expectations.
    `root` is an ElementTree Element for samlp:Response. `signed_ok` stands in for
    the cryptographic signature result (see module docstring): the point of this
    function is the CLAIM validation an analyst reasons about, and it enforces that
    an unsigned/invalid-signature assertion is rejected when require_signature.
    Returns dict of attributes on success; raises SamlValidationError otherwise.
    """
    now = now or datetime.now(timezone.utc)
    NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          "saml": "urn:oasis:names:tc:SAML:2.0:assertion"}

    status = root.find(".//samlp:StatusCode", NS)
    if status is None or not status.get("Value", "").endswith(":Success"):
        raise SamlValidationError("SAML status is not Success")

    assertion = root.find("saml:Assertion", NS)
    if assertion is None:
        raise SamlValidationError("no assertion in response")

    if require_signature and not signed_ok:
        # An unsigned assertion (or one whose signature didn't verify) is an
        # anonymous claim. This is THE cardinal SAML rule.
        raise SamlValidationError("assertion signature missing or invalid")

    # Audience: this assertion must be intended for US, not another SP.
    aud = assertion.find(".//saml:AudienceRestriction/saml:Audience", NS)
    if aud is None or aud.text != expected_audience:
        raise SamlValidationError(
            f"audience mismatch: {getattr(aud, 'text', None)} != {expected_audience}")

    # Conditions window: NotBefore <= now < NotOnOrAfter (this is the clock-skew classic).
    cond = assertion.find("saml:Conditions", NS)
    if cond is not None:
        nb, noa = cond.get("NotBefore"), cond.get("NotOnOrAfter")
        skew = timedelta(seconds=120)
        if nb and now + skew < _dt(nb):
            raise SamlValidationError("assertion not yet valid (NotBefore in future beyond skew)")
        if noa and now - skew >= _dt(noa):
            raise SamlValidationError("assertion expired (past NotOnOrAfter beyond skew)")

    # SubjectConfirmationData: Recipient must be our ACS, InResponseTo must match
    # the request we sent (kills replay of a stolen/forwarded assertion).
    scd = assertion.find(".//saml:SubjectConfirmationData", NS)
    if scd is not None:
        if scd.get("Recipient") and scd.get("Recipient") != expected_acs:
            raise SamlValidationError(
                f"recipient mismatch: {scd.get('Recipient')} != {expected_acs}")
        irt = scd.get("InResponseTo")
        if in_response_to_sent is not None and irt != in_response_to_sent:
            raise SamlValidationError(
                f"InResponseTo mismatch: {irt} != {in_response_to_sent} (unsolicited/replayed)")
        noa = scd.get("NotOnOrAfter")
        if noa and now - timedelta(seconds=120) >= _dt(noa):
            raise SamlValidationError("subject confirmation expired")

    nameid = assertion.find(".//saml:Subject/saml:NameID", NS)
    attrs = {"NameID": nameid.text if nameid is not None else None}
    for a in assertion.findall(".//saml:AttributeStatement/saml:Attribute", NS):
        vals = [v.text for v in a.findall("saml:AttributeValue", NS)]
        attrs[a.get("Name")] = vals[0] if len(vals) == 1 else vals
    return attrs


def _dt(s):
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s)


# --------------------------------- self-test ---------------------------------

def selftest():
    import xml.etree.ElementTree as ET
    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and cond
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")

    rid, xml = build_authn_request("https://idp.example/sso")
    check("AuthnRequest carries our ACS", SP_ACS_URL in xml)
    check("AuthnRequest ID starts with _ (xs:ID rule)", rid.startswith("_"))
    encoded = deflate_and_encode(xml)
    reinflated = zlib.decompress(base64.b64decode(encoded), -zlib.MAX_WBITS).decode()
    check("DEFLATE round-trips", "<samlp:AuthnRequest" in reinflated)

    aud, acs = "http://localhost:5002/metadata", "http://localhost:5002/acs"
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    def resp(audience=aud, recipient=acs, irt=rid, nb_off=-5, noa_off=5, status_ok=True):
        nb = (now + timedelta(minutes=nb_off)).strftime("%Y-%m-%dT%H:%M:%SZ")
        noa = (now + timedelta(minutes=noa_off)).strftime("%Y-%m-%dT%H:%M:%SZ")
        st = "urn:oasis:names:tc:SAML:2.0:status:Success" if status_ok else \
             "urn:oasis:names:tc:SAML:2.0:status:Responder"
        s = f'''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0">
          <samlp:Status><samlp:StatusCode Value="{st}"/></samlp:Status>
          <saml:Assertion ID="_a1" Version="2.0">
            <saml:Issuer>http://www.okta.com/exk1</saml:Issuer>
            <saml:Subject><saml:NameID
              Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">jsmith@bayline.example</saml:NameID>
              <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData Recipient="{recipient}" InResponseTo="{irt}"
                  NotOnOrAfter="{noa}"/>
              </saml:SubjectConfirmation></saml:Subject>
            <saml:Conditions NotBefore="{nb}" NotOnOrAfter="{noa}">
              <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AttributeStatement>
              <saml:Attribute Name="department"><saml:AttributeValue>Finance</saml:AttributeValue></saml:Attribute>
              <saml:Attribute Name="displayName"><saml:AttributeValue>Jordan Smith</saml:AttributeValue></saml:Attribute>
            </saml:AttributeStatement>
          </saml:Assertion></samlp:Response>'''
        return ET.fromstring(s)

    attrs = validate_assertion(resp(), aud, acs, rid, now=now, signed_ok=True)
    check("valid assertion accepted", attrs.get("NameID") == "jsmith@bayline.example")
    check("attributes extracted", attrs.get("department") == "Finance")

    for name, kwargs, extra in [
        ("unsigned assertion rejected", {}, {"signed_ok": False}),
        ("wrong audience rejected", {"audience": "http://other-sp/meta"}, {}),
        ("wrong recipient rejected", {"recipient": "http://evil/acs"}, {}),
        ("bad InResponseTo rejected", {"irt": "_someoneelse"}, {}),
        ("expired assertion rejected", {"noa_off": -10}, {}),
        ("failed status rejected", {"status_ok": False}, {}),
    ]:
        try:
            validate_assertion(resp(**kwargs), aud, acs, rid, now=now, signed_ok=extra.get("signed_ok", True))
            check(name, False)
        except SamlValidationError:
            check(name, True)

    print("ALL CHECKS PASSED" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


# ----------------------------------- app -------------------------------------

def build_app():
    from flask import Flask, session, redirect, request, Response, url_for, jsonify
    import xml.etree.ElementTree as ET

    IDP_SSO_URL = os.environ["SAML_IDP_SSO_URL"]
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET", base64.b16encode(os.urandom(16)).decode())

    @app.route("/")
    def home():
        who = session.get("attrs", {}).get("NameID")
        return (f"Signed in as {who}. <a href='/profile'>profile</a>"
                if who else "SAML SP demo. <a href='/login'>Sign in with Okta</a>")

    @app.route("/login")
    def login():
        rid, xml = build_authn_request(IDP_SSO_URL)
        session["authn_request_id"] = rid
        from urllib.parse import urlencode
        return redirect(f"{IDP_SSO_URL}?{urlencode({'SAMLRequest': deflate_and_encode(xml)})}")

    @app.route("/acs", methods=["POST"])
    def acs():
        raw = base64.b64decode(request.form["SAMLResponse"])
        root = ET.fromstring(raw)
        # signature verification: use xmlsec/python3-saml here in production.
        signed_ok = _verify_signature_if_available(raw)
        try:
            attrs = validate_assertion(root, SP_ENTITY_ID, SP_ACS_URL,
                                       session.get("authn_request_id"),
                                       signed_ok=signed_ok)
        except SamlValidationError as e:
            return f"SAML assertion rejected: {e}", 400
        session["attrs"] = attrs
        return redirect(url_for("profile"))

    @app.route("/profile")
    def profile():
        if "attrs" not in session:
            return redirect(url_for("login"))
        return jsonify({"validated_saml_attributes": session["attrs"]})

    @app.route("/metadata")
    def metadata():
        md = (f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
              f'entityID="{SP_ENTITY_ID}"><SPSSODescriptor '
              f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
              f'WantAssertionsSigned="true" AuthnRequestsSigned="false">'
              f'<AssertionConsumerService '
              f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
              f'Location="{SP_ACS_URL}" index="0"/></SPSSODescriptor></EntityDescriptor>')
        return Response(md, mimetype="application/xml")

    return app


def _verify_signature_if_available(raw_xml):
    """Use xmlsec via python3-saml if installed; otherwise return False so the
    validator refuses the assertion (fail closed). Never return True blindly."""
    try:
        from signxml import XMLVerifier  # optional dependency
    except ImportError:
        # No verifier installed. Fail closed: the validator will reject on
        # signed_ok=False when require_signature is on. Documented in README.
        return False
    try:
        idp_cert = open(os.environ["SAML_IDP_CERT_PATH"]).read()
        XMLVerifier().verify(raw_xml, x509_cert=idp_cert)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    build_app().run(host="0.0.0.0", port=5002, debug=False)
