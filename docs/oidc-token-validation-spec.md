# OIDC Token Validation and Claim-Mapping Specification

**Project:** LTL-001 — Multi-Cloud Zero-Trust Identities & Guardrails  
**Environment:** ludbA Bank (fictional, isolated simulation)  
**Status:** Implementation specification — code and runtime evidence pending  
**Architecture baseline:** [OIDC-to-OPA Trust Architecture](oidc-opa-trust-architecture.md)

## 1. Purpose

Define the token-validation and claim-normalization behavior required at the trusted policy gateway before any identity attributes are sent to Open Policy Agent (OPA).

The gateway is the security boundary between OIDC tokens issued by Keycloak and the authorization input consumed by OPA. It must reject invalid tokens before policy evaluation and must never treat decoded JWT claims as trusted until signature and semantic validation have succeeded.

This document is a design specification. It does not claim that a gateway, token verifier, or end-to-end login flow has been implemented.

## 2. Configured issuer profile

The current lab realm is:

- Realm: `ludbA-bank`
- Client: `ludba-portal`
- Local issuer base: `http://localhost:8080/realms/ludbA-bank`
- Local OIDC discovery: `http://localhost:8080/realms/ludbA-bank/.well-known/openid-configuration`
- Local JWKS endpoint: `http://localhost:8080/realms/ludbA-bank/protocol/openid-connect/certs`

These URLs are valid only for the local isolated lab profile. The production-like deployment profile must use a fixed HTTPS issuer URL, trusted TLS, and exact configured origins. Never accept an issuer, discovery URL, or JWKS URL supplied by the incoming token or browser request.

Before implementation, retrieve the live discovery document from the running Keycloak realm and record its issuer, authorization endpoint, token endpoint, JWKS URI, and supported signing algorithms. Do not assume that a URL copied from a different realm or environment is correct.

## 3. Token types and intended use

The implementation must distinguish the OIDC ID token from the OAuth access token:

| Token | Intended consumer | Use in this lab |
|---|---|---|
| ID token | OIDC client | Establishes the authentication event and client session; not a substitute for API authorization |
| Access token | Intended resource server / API | Presented to the backend gateway for access-token validation and authorization context |
| Refresh token | OIDC client/token endpoint | Used only to obtain renewed tokens; never sent to OPA or accepted as an API bearer token |

The gateway must accept only the expected access-token profile for the protected API. It must reject an ID token or refresh token presented as an API access token.

The token profile must be agreed and documented from the actual Keycloak configuration. Do not infer token purpose solely from the presence of a familiar claim.

## 4. Validation pipeline — required order

The gateway must apply the following validation stages before extracting authorization claims:

1. **Input bounds:** enforce a reasonable Authorization header/token size limit; reject missing, duplicate, malformed, or ambiguous bearer credentials.
2. **JWT structure:** require the expected compact JWT format and parse header/payload safely. Parsing is not validation.
3. **Algorithm policy:** allow only explicitly configured asymmetric signing algorithms supported by the issuer profile. Reject `none`, unexpected algorithms, and algorithm/key-type mismatches.
4. **Key selection:** use `kid` only to select a key from the configured issuer's trusted JWKS set. Never follow token-provided `jku`, `x5u`, or arbitrary key URLs.
5. **Signature:** verify the cryptographic signature using the selected trusted public key. Unknown `kid` may trigger a controlled JWKS refresh; if still unresolved, reject.
6. **Issuer:** require exact equality with the configured realm issuer.
7. **Audience:** require the intended API audience. Configure a dedicated resource-server audience in Keycloak if needed; do not assume `ludba-portal` is automatically the correct API audience.
8. **Authorized party/client:** where the selected Keycloak token profile includes `azp` or another client-context claim, validate it against the expected client policy. Do not confuse `azp` with API audience.
9. **Time:** require a valid `exp`; validate `nbf` when present; apply a small documented clock-skew tolerance. Reject tokens outside their validity window.
10. **Token use/profile:** require the expected access-token profile and reject ID or refresh tokens.
11. **Claim schema:** validate required claim types and structures before mapping. Reject malformed values rather than coercing them.
12. **Identity lifecycle:** check trusted account state when the authorization model requires immediate disable/suspension enforcement.
13. **Claim normalization:** map only explicitly allowlisted identity attributes into the gateway-to-OPA contract.
14. **Policy evaluation:** call OPA over a protected internal channel using gateway-generated input.

Any validation error stops the pipeline. No invalid token reaches OPA.

## 5. JWKS retrieval and key rotation

- Configure the issuer and JWKS endpoint as deployment configuration controlled by operators.
- Retrieve signing keys only from the configured HTTPS issuer endpoint (HTTP is permitted solely for the localhost lab).
- Validate TLS certificates in non-local environments.
- Cache JWKS responses for a bounded interval and honor safe cache metadata where appropriate.
- On an unknown `kid`, perform at most a controlled refresh with rate limiting; do not create an unbounded network-fetch path.
- If the key remains unavailable or signature verification fails, reject the token.
- Support overlapping keys during legitimate issuer key rotation.
- Do not pin a single public key forever if the issuer rotates signing keys.
- Never log the complete JWT, Authorization header, private key, or token contents.

## 6. Claim mapping contract

The gateway converts validated claims into the following internal representation. This is a gateway-created object, not a browser API schema.

| Normalized field | Type | Mapping rule |
|---|---|---|
| `subject` | non-empty string | Verified `sub`; scope uniqueness by issuer |
| `issuer` | exact string | Verified `iss`; must match configured issuer |
| `client_id` | string | Validated client-context claim according to the actual Keycloak access-token profile |
| `roles` | array of strings | Allowlisted realm roles from verified access-token claims |
| `active` | boolean | Trusted account status; not a client-supplied claim |
| `auth_time` | integer | Verified `auth_time`, when emitted and required |
| `auth_strength` | object | Derived only from explicitly configured and verified authentication evidence |

### 6.1 Realm role extraction

The configured realm defines these role names:

- `system_admin`
- `security_analyst`
- `database_admin`
- `auditor`
- `external_vendor`

The gateway must inspect the actual signed access token from the running realm to identify where realm roles appear. Keycloak commonly represents realm roles under a realm-access structure, but implementation must verify the actual token rather than blindly assume a claim path.

Rules:

- Accept only exact allowlisted role strings.
- Do not derive permissions from group display names.
- Ignore or reject unknown roles according to the strict schema; never map an unknown role to a privileged role.
- Never accept a role list from query parameters, request JSON, headers other than the validated bearer token, or browser storage.
- Decide whether multiple roles are allowed. If so, OPA must evaluate each permission explicitly and must not rely on arbitrary role ordering.
- The IT Operations group currently maps to both `system_admin` and `database_admin`. This is a broad demonstration assignment and should be split into narrower groups before adding real identities.

### 6.2 Active/suspended account state

A signed token can remain cryptographically valid until expiry even after an account is disabled. If immediate revocation is required, the gateway must consult a trusted identity lifecycle source or use a documented short token lifetime/revocation strategy. Do not treat an `active` boolean supplied by the browser as authoritative.

For the lab, document which method is used and test disabled-user behavior. If the gateway cannot establish required account status, fail closed for protected operations.

### 6.3 MFA and authentication strength

The realm has TOTP configuration and a default `CONFIGURE_TOTP` required action. Neither fact alone proves that a specific login completed MFA.

Before enforcing an MFA-dependent policy:

1. Configure the intended Keycloak Browser flow with a required password-plus-OTP path.
2. Complete successful password-plus-OTP authentication in the running lab.
3. Capture a redacted example of the resulting ID token and access token claim names and types.
4. Run negative login cases (no OTP, wrong OTP, disabled user) and inspect resulting outcomes.
5. Identify a reliable, issuer-controlled signal that distinguishes MFA-authenticated sessions from password-only sessions.
6. If the standard token does not carry the needed assurance signal, deliberately configure an appropriate protocol mapper or authentication context mechanism and verify it.
7. Document exact semantics, including what the signal means and which flow produces it.

Do not invent `acr`, `amr`, or custom MFA claim values. Do not set `mfa_verified: true` simply because a user has enrolled TOTP. Missing, malformed, or insufficient assurance evidence must result in denial whenever policy requires MFA.

Proposed normalized shape (values illustrative, not actual observed Keycloak claims):

```json
{
  "auth_strength": {
    "mfa_verified": true,
    "method": ["password", "otp"],
    "assurance_source": "verified-keycloak-authentication-context"
  }
}
```

The gateway must set this object only after implementing and verifying the mapping described above.

## 7. Proposed gateway-to-OPA input

The architecture baseline proposes the following versioned contract:

```json
{
  "schema_version": "1.0",
  "identity": {
    "subject": "fictional-user-001",
    "issuer": "http://localhost:8080/realms/ludbA-bank",
    "client_id": "ludba-portal",
    "roles": ["security_analyst"],
    "active": true,
    "auth_time": 1790000000,
    "auth_strength": {
      "mfa_verified": true,
      "method": ["password", "otp"]
    }
  },
  "resource": {
    "id": "security-log-001",
    "type": "security_logs",
    "classification": "restricted"
  },
  "action": "read",
  "context": {
    "evaluated_at_epoch": 1790000000,
    "request_id": "simulated-request-001"
  },
  "vendor_access": {
    "approved": false,
    "resource_id": "",
    "expires_at_epoch": 0
  }
}
```

This is a proposed example, not an observed token or a currently accepted OPA input. The current Rego policy still reads `input.user.role`. A later implementation change must update the policy and all fixtures/tests atomically or introduce an explicit compatibility migration. Do not deploy a gateway that sends `identity` while OPA still expects `user`.

### Input provenance

| Input field | Trusted source |
|---|---|
| identity.subject / issuer / client_id / roles | Validated token claims and configured mapping |
| identity.active | Trusted identity lifecycle check |
| identity.auth_time | Validated token claim |
| identity.auth_strength | Verified authentication flow evidence |
| resource.id / type / classification | Backend resource lookup and server-side classification |
| action | Server-side route/operation mapping |
| context.evaluated_at_epoch | Gateway server clock |
| context.request_id | Gateway-generated correlation ID |
| vendor_access | Trusted approval/grant store |

The browser may request an operation and identify the target object, but the backend must resolve the authoritative resource attributes and authorization action. Client-supplied policy fields are not authoritative.

## 8. Error handling and response behavior

Use stable internal error categories. Avoid exposing cryptographic or policy internals to unauthenticated callers.

| Condition | Gateway behavior |
|---|---|
| Missing/invalid bearer credential | HTTP 401 |
| Invalid signature, issuer, audience, expiry, or token type | HTTP 401 |
| Valid identity but policy denies action | HTTP 403 |
| Required identity status cannot be established | Fail closed; deny protected operation |
| OPA timeout/unavailable/invalid response | Fail closed; service error may be returned, but protected action is never performed |
| Internal validation/configuration fault | Fail closed and emit sanitized operational alert |

Do not return a successful response if OPA is unavailable. Do not retry state-changing operations in a way that could execute them twice.

## 9. Security test matrix

The following cases are mandatory for the eventual gateway test suite.

| ID | Test input / condition | Expected result |
|---|---|---|
| TOK-001 | Correct signature, issuer, audience and time | Continue to claim mapping |
| TOK-002 | Missing bearer token | 401; no OPA call |
| TOK-003 | Malformed JWT | 401; no OPA call |
| TOK-004 | Tampered payload/signature | 401; no OPA call |
| TOK-005 | `alg=none` | 401; no OPA call |
| TOK-006 | Unsupported algorithm/key type | 401; no OPA call |
| TOK-007 | Unknown `kid` after controlled JWKS refresh | 401; no OPA call |
| TOK-008 | Wrong issuer / different realm | 401; no OPA call |
| TOK-009 | Missing or wrong API audience | 401; no OPA call |
| TOK-010 | Wrong authorized client context | 401; no OPA call |
| TOK-011 | Expired token | 401; no OPA call |
| TOK-012 | Future `nbf` beyond clock-skew tolerance | 401; no OPA call |
| TOK-013 | ID token presented to API | 401; no OPA call |
| TOK-014 | Refresh token presented to API | 401; no OPA call |
| TOK-015 | Valid token with no recognized role | No privilege; deny at policy layer |
| TOK-016 | Token contains unknown role | Unknown role never grants access |
| TOK-017 | Browser body includes forged `system_admin` | Forged role ignored; verified token roles only |
| TOK-018 | Browser body includes `active: true` for disabled account | Trusted status check wins; deny |
| TOK-019 | MFA-required operation with no verified MFA evidence | Deny |
| TOK-020 | TOTP enrolled but login did not complete OTP | Must not be marked MFA verified |
| TOK-021 | OPA unavailable | Protected operation denied; no bypass |
| TOK-022 | OPA returns malformed/unexpected response | Protected operation denied |
| TOK-023 | Vendor approval absent or expired | Deny |
| TOK-024 | Client attempts to set future evaluation timestamp | Gateway time is used; client value ignored |
| TOK-025 | JWKS endpoint unreachable and cached key unavailable | Deny; no signature bypass |

Tests must also verify that rejected tokens do not trigger an OPA request and that logs contain no raw credentials or bearer tokens.

## 10. Observability and audit

Log validation outcomes as structured events with:

- UTC server timestamp
- request/correlation ID
- issuer and client identifier (where safely available)
- pseudonymous or issuer-scoped subject identifier after validation
- validation result category
- policy decision result and policy version
- resource/action identifiers where appropriate

Never log the Authorization header, raw token, decoded full token payload, authorization code, refresh token, client secret, password, OTP, OTP seed, QR code, or recovery code. Sanitize exception messages and prevent token values from leaking through traces.

## 11. Implementation readiness checklist

Before gateway code is written, verify the following from the running lab:

- [ ] Keycloak container starts and realm import is successful.
- [ ] OIDC discovery document is reachable at the configured issuer.
- [ ] Actual issuer and JWKS URI are recorded.
- [ ] Signing algorithm and JWKS key metadata are observed.
- [ ] Authorization Code + PKCE S256 login succeeds.
- [ ] API audience is explicitly configured and observed in access token.
- [ ] Actual access-token claim paths and types are recorded.
- [ ] Realm role mapping is verified against test users.
- [ ] Mandatory password-plus-OTP flow is tested.
- [ ] MFA assurance signal is identified from real token evidence or deliberately configured.
- [ ] Disabled-user handling strategy is selected and tested.
- [ ] Gateway-to-OPA schema version is agreed.
- [ ] Existing OPA policy and fixtures have a migration plan.

## 12. References

- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0 Security Best Current Practice (RFC 9700): https://www.rfc-editor.org/rfc/rfc9700
- JSON Web Token Best Current Practices (RFC 8725): https://www.rfc-editor.org/rfc/rfc8725
- JSON Web Token (JWT) (RFC 7519): https://www.rfc-editor.org/rfc/rfc7519
- JSON Web Key (JWK) (RFC 7517): https://www.rfc-editor.org/rfc/rfc7517
- OpenID Connect Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
- Keycloak Server Administration Guide: https://www.keycloak.org/docs/latest/server_admin/
- Open Policy Agent documentation: https://www.openpolicyagent.org/docs/latest/

## 13. Explicit limitations

- No token verifier or gateway implementation exists yet.
- The API audience has not yet been configured or confirmed.
- The exact token claim layout must be observed from the running Keycloak realm.
- The MFA assurance claim has not yet been identified or verified.
- The current OPA policy input uses `input.user.role`, not the proposed `input.identity` schema.
- Documentation and CI checks cannot prove successful runtime authentication, token validation, MFA enforcement, or end-to-end authorization.
