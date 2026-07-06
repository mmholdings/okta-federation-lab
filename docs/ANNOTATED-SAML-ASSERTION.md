# Annotated SAML Assertion

A representative SAML 2.0 Response from Okta to my SP, decoded and marked up. Values are
from the lab (synthetic user `jsmith@bayline.example`); the signature block is
abbreviated. What matters is knowing which element does what and which ones you validate.

```xml
<samlp:Response ID="_8e2f..." Version="2.0"
    IssueInstant="2026-06-15T12:00:03Z"
    Destination="http://localhost:5002/acs">        <!-- (1) must equal our ACS URL -->
  <saml:Issuer>http://www.okta.com/exk1a2b3</saml:Issuer>  <!-- (2) the IdP EntityID -->
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>  <!-- (3) not-Success = stop -->
  </samlp:Status>

  <saml:Assertion ID="_a1b2..." Version="2.0" IssueInstant="2026-06-15T12:00:03Z">
    <saml:Issuer>http://www.okta.com/exk1a2b3</saml:Issuer>

    <ds:Signature>                                  <!-- (4) THE signature. No valid sig = anonymous claim -->
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm=".../xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm=".../rsa-sha256"/>
        <ds:Reference URI="#_a1b2...">              <!-- signs THIS assertion by ID -->
          <ds:DigestValue>...</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>...</ds:SignatureValue>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID...</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </ds:Signature>

    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        jsmith@bayline.example                       <!-- (5) NameID: who the user is -->
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            Recipient="http://localhost:5002/acs"     <!-- (6) must be our ACS -->
            InResponseTo="_reqid_we_sent"             <!-- (7) must match our AuthnRequest ID -->
            NotOnOrAfter="2026-06-15T12:05:03Z"/>     <!-- (8) short-lived bearer window -->
      </saml:SubjectConfirmation>
    </saml:Subject>

    <saml:Conditions NotBefore="2026-06-15T11:59:03Z"
                     NotOnOrAfter="2026-06-15T12:05:03Z">  <!-- (9) validity window -->
      <saml:AudienceRestriction>
        <saml:Audience>http://localhost:5002/metadata</saml:Audience>  <!-- (10) must be US -->
      </saml:AudienceRestriction>
    </saml:Conditions>

    <saml:AuthnStatement AuthnInstant="2026-06-15T12:00:02Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>                            <!-- how they authenticated -->
    </saml:AuthnStatement>

    <saml:AttributeStatement>                         <!-- (11) the attributes I mapped in Okta -->
      <saml:Attribute Name="department"><saml:AttributeValue>Finance</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayName"><saml:AttributeValue>Jordan Smith</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

## What each callout means and why my SP checks it

1. **Destination** — where the IdP sent this. Should match our ACS. Weak check on its
   own; the recipient check (6) is the enforced one.
2. **Issuer** — identifies the IdP. The SP is configured to trust exactly this
   EntityID; anything else is an unknown IdP and rejected.
3. **StatusCode** — anything but `Success` (e.g. `Requester`, `Responder`,
   `AuthnFailed`) means no valid authentication happened. Stop.
4. **Signature** — the whole game. An assertion is just XML; without a signature that
   verifies against the IdP's known cert, anyone who can POST to the ACS can claim to
   be anyone. My validator refuses to accept an assertion unless the signature verifies
   (fail-closed). Note `Reference URI="#_a1b2..."` — the signature covers the assertion
   by its ID, which is why signature-wrapping attacks (injecting a second, unsigned
   assertion) are a real SAML threat class and why you use a vetted library for the
   crypto+canonicalization.
5. **NameID** — the subject identifier, here an email. This becomes the SP's username.
6. **Recipient** — must be our ACS URL. Stops an assertion minted for one SP from being
   replayed at another.
7. **InResponseTo** — must match the ID of the AuthnRequest *we* sent. This is what
   distinguishes a response to our login from an unsolicited (or replayed) assertion.
8/9. **NotBefore / NotOnOrAfter** — the validity window. Reject outside it (with a small
   clock-skew allowance). Skew mismatch here is the single most common federation break.
10. **Audience** — must be our SP EntityID. "Is this token for me?" — the SAML sibling
   of OIDC's `aud`.
11. **AttributeStatement** — the claims. My SP reads `department`/`displayName`; these
   are configured in Okta's SAML app under attribute statements and must match what the
   SP expects by name, exactly.
