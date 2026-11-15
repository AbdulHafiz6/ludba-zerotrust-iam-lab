# OIDC-to-OPA Trust Architecture

**Project:** LTL-001 — Multi-Cloud Zero-Trust Identities & Guardrails  
**Environment:** ludbA Bank (fictional, isolated simulation)  
**Status:** Architecture baseline — implementation and runtime verification pending

## 1. Purpose and scope

This document defines the trust boundary between Keycloak (identity provider), an application/policy gateway, and Open Policy Agent (OPA). It is the design baseline for connecting the existing Keycloak realm and OPA authorization policies.

This is an architecture specification, not evidence of a working end-to-end integration. The repository currently validates Keycloak realm configuration and OPA policy logic independently. It does not yet demonstrate application login, JWT verification, or live OPA enforcement.

## 2. Security objectives

1. Authenticate users through the configured OpenID Connect (OIDC) provider.
2. Validate every access token cryptographically and semantically before using its claims.
3. Derive authorization attributes only from validated identity-provider claims and trusted server-side data.
4. Enforce least privilege through OPA with default-deny behavior.
5. Keep client-controlled identity, role, resource ownership, MFA status, and evaluation time outside the trusted authorization context.
6. Produce auditable allow/deny decisions without logging bearer tokens, OTP secrets, or other credentials.

## 3. Target architecture

```text
[User / Browser]
      |
      | OIDC Authorization Code + PKCE (S256)
      v
[Keycloak: ludbA-bank]
      |
      | Authorization response / tokens
      v
[Application / Backend]
      |
      | Bearer access token + requested action/resource
      v
[Trusted Policy Gateway]
      |  1. Verify JWT signature using trusted issuer JWKS
      |  2. Validate issuer, audience, expiry, not-before, token type
      |  3. Normalize verified claims and resolve trusted account state
      |  4. Add server-derived time and request context
      |
      | Structured authorization input over protected service channel
      v
[OPA: default-deny policy]
      |
      | allow / deny + decision metadata
      v
[Policy Gateway] ---> [Application response]
      |
      +-------------> [Security audit event]
```

OPA is not an identity provider and must not be exposed as a public endpoint. The gateway is the policy enforcement point (PEP); OPA is the policy decision point (PDP). The application must fail closed if token validation or the policy decision service is unavailable.

## 4. Trust boundaries and responsibilities

| Component | Trusted responsibility | Must not be trusted for |
|---|---|---|
| Browser/client | Initiates OIDC flow and requests an operation | Supplying authoritative roles, MFA status, user active state, vendor approval, or evaluation time |
| Keycloak | Authenticates configured identities and issues signed tokens | Authorizing access to every application resource by itself |
| Application | Enforces the gateway decision before returning protected data or performing actions | Treating decoded-but-unverified JWT payloads as identity proof |
| Policy gateway | Validates tokens, normalizes claims, loads trusted context, calls OPA | Accepting identity or time overrides from the request body |
| OPA | Evaluates policy against the trusted input contract | Fetching keys from arbitrary URLs or independently trusting caller-supplied claims |
| Audit sink | Stores minimal decision evidence with controlled access | Storing passwords, OTP seeds, QR codes, recovery codes, or raw bearer tokens |

### Non-negotiable rules

- A JWT is not trusted merely because it can be base64-decoded.
- The gateway must verify the signature against keys obtained from the configured Keycloak issuer's trusted JWKS endpoint.
- Do not follow a token's untrusted `jku`, `x5u`, or arbitrary key URL.
- Pin accepted signing algorithms to the configured issuer's supported policy; reject `none` and unexpected algorithms.
- Match the exact expected issuer and intended audience. Do not accept a token issued for another realm, client, or API.
- Validate `exp` and `nbf`; apply only a small, documented clock-skew allowance.
- Validate token type/use and client context according to the selected Keycloak token profile.
- Never forward the original browser request body as authoritative OPA identity input.

## 5. OIDC login and token validation

The existing Keycloak client is `ludba-portal`, configured as a public OIDC browser client with Authorization Code flow, PKCE S256, direct access grants disabled, and implicit flow disabled. Its current callback and web-origin values are localhost-only lab settings.

The eventual application integration must:

1. Generate a cryptographically random `state` and bind it to the browser session.
2. Generate an OIDC `nonce` and validate it against the ID token where applicable.
3. Use Authorization Code flow with PKCE S256.
4. Exchange the authorization code through the configured token endpoint.
5. Validate the ID token as an OIDC authentication artifact; validate the access token separately for API authorization.
6. Validate access-token signature, issuer, audience, expiry, not-before, and expected token use before extracting claims.
7. Handle key rotation by refreshing trusted JWKS data safely; do not disable signature validation when a key is unknown.
8. Reject malformed, expired, unsigned, wrongly signed, wrong-issuer, wrong-audience, or otherwise invalid tokens.

The exact audience and access-token claim shape for the eventual API have not yet been established. Before implementation, define an explicit API audience (for example, a dedicated resource-server audience) and configure the Keycloak client/audience mapper accordingly. Do not assume that the browser client ID is automatically the correct API audience.

## 6. Identity and authorization claim contract

After successful validation, the gateway maps identity-provider claims into a small, normalized internal structure. This contract is an internal gateway-to-OPA format; it is not a request format that browsers may submit.

Proposed normalized identity fields:

| Field | Type | Source / rule |
|---|---|---|
| `subject` | string | Verified token `sub`; stable issuer-scoped subject identifier |
| `issuer` | string | Verified `iss`; must equal configured issuer |
| `client_id` | string | Verified client context from the token profile, after validating the appropriate claim for the configured Keycloak version |
| `roles` | array of strings | Allowlisted realm roles extracted from the verified access token |
| `active` | boolean | Trusted account-status lookup or validated identity lifecycle signal; never a browser field |
| `auth_time` | number | Verified authentication time, if present and required |
| `auth_strength` | object/string | Only set from a deliberately configured and verified authentication assurance signal |

Role mapping must use an explicit allowlist: `system_admin`, `security_analyst`, `database_admin`, `auditor`, and `external_vendor`. Unknown roles are ignored or cause rejection according to the gateway's strict mapping policy. Group display names are not authorization roles. The current realm's IT Operations group maps to both `system_admin` and `database_admin`; this broad demonstration mapping should be split before adding real users.

### MFA assurance caveat

The realm currently configures TOTP and a default `CONFIGURE_TOTP` required action. That proves an enrollment prompt is configured; it does not, by itself, prove that every login completed MFA.

Do not assume a particular `acr`, `amr`, or other MFA claim is emitted by Keycloak. The team must configure the intended Browser authentication flow, inspect actual tokens from successful password-plus-OTP and negative test logins, then document the exact claim/mapper behavior. Until that evidence exists, the gateway must not invent an MFA assurance value. If policy requires MFA and the verified assurance signal is absent or insufficient, deny access.

## 7. Gateway-to-OPA request contract

The gateway constructs the OPA input after token validation. The proposed shape is:

```json
{
  "identity": {
    "subject": "fictional-user-001",
    "issuer": "http://localhost:8080/realms/ludbA-bank",
    "client_id": "ludba-portal",
    "roles": ["security_analyst"],
    "active": true,
    "auth_strength": {
      "mfa_verified": false,
      "method": ["password"]
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
    "request_id": "simulated-request-001",
    "source": "ludba-portal"
  },
  "vendor_access": {
    "approved": false,
    "resource_id": "",
    "expires_at_epoch": 0
  }
}
```

All values above are fictional examples. In particular:

- `identity` is built only from verified token claims and trusted server-side identity state.
- `resource` is resolved by the backend from the requested object; never trust a client-provided classification or ownership label without checking it against authoritative data.
- `action` is selected from a server-side route/operation mapping, not accepted as an arbitrary policy instruction.
- `context.evaluated_at_epoch` is generated by the gateway using server time.
- Vendor approval, resource scope, and expiry come from a trusted approval record, not from a browser payload.
- Request IDs are correlation values, not credentials.

The example is a design contract, not yet compatible with the current `policies/access.rego`, which reads `input.user.role`. A later implementation change must migrate the policy to the normalized `input.identity` structure in a separate, tested change. Do not silently mix both formats.

## 8. Authorization decision behavior

- OPA policy package remains default deny.
- The gateway authorizes only after receiving an explicit `allow: true` decision.
- Missing, malformed, or unexpected decision responses are treated as deny.
- OPA timeout, connection failure, invalid response, or gateway validation error must fail closed.
- The application checks the decision before returning protected data or executing a state-changing operation.
- For sensitive operations, bind the decision to the specific subject, action, resource identifier, and request context to reduce confused-deputy and replay risks.
- Avoid caching allow decisions for privileged or time-bound vendor operations unless cache keys and expiry semantics are rigorously defined.

## 9. Vendor access controls

External vendor access remains read-only and narrowly scoped. The authorization service must obtain approval, resource identifier, and expiry from a trusted vendor-access record. The gateway injects server time for expiry comparison.

Deny if the vendor is inactive, approval is absent, the resource does not match exactly, expiry is missing/non-numeric, or current server time is at or beyond expiry. Consider a separate revocation/status check for vendor grants so revocation takes effect before the expiry timestamp.

## 10. Threat model and required negative tests

| Threat / failure | Required control | Test outcome |
|---|---|---|
| Forged JWT or invalid signature | Verify signature against trusted JWKS | Deny before OPA |
| Wrong issuer / another realm | Exact issuer allowlist | Deny |
| Wrong or missing API audience | Explicit audience validation | Deny |
| Expired token | Validate `exp` | Deny |
| Token not yet valid | Validate `nbf` | Deny |
| Unexpected signing algorithm | Algorithm allowlist | Deny |
| Browser submits `system_admin` role | Ignore client identity fields; derive roles from verified token | No privilege increase |
| Unknown or malformed role claim | Strict allowlist and schema validation | Deny or strip unknown role; never elevate |
| User disabled/suspended | Trusted active-state check | Deny |
| MFA required but not proven | Require verified configured assurance evidence | Deny |
| Missing/incorrect MFA evidence | Do not infer from TOTP enrollment setting | Deny when MFA is required |
| Vendor approval spoofed by browser | Trusted approval lookup | Deny |
| Vendor resource mismatch | Exact resource binding | Deny |
| Vendor grant expired/revoked | Trusted time and grant status | Deny |
| Client forges evaluation time | Gateway-generated time only | Ignore client value; use server time |
| OPA unavailable or malformed response | Fail-closed enforcement | Deny |
| Sensitive token appears in logs | Redaction and structured audit schema | No token/secret recorded |

## 11. Audit event requirements

Record only what is necessary to investigate and prove decisions:

- UTC event timestamp generated by the server
- request/correlation ID
- issuer-scoped subject identifier or approved pseudonymous identifier
- client/application identifier
- resource type and identifier
- requested action
- allow/deny result and stable policy rule/reason code
- token validation outcome category (never the token)
- policy bundle/version identifier
- gateway and OPA service version

Do not log passwords, authorization codes, access tokens, refresh tokens, ID tokens, OTP values, OTP seeds, QR codes, recovery codes, or complete authorization headers. Restrict audit-log access and define retention appropriate to this fictional lab.

## 12. Implementation sequence

1. **Architecture baseline (this document):** agree the trust boundaries and normalized contract.
2. **Keycloak runtime verification:** start the local container when power is available; verify realm import, client, and Browser MFA flow.
3. **Token evidence:** capture redacted claim examples for successful MFA, missing MFA, invalid credentials, and disabled identity. Determine actual MFA assurance claims rather than guessing.
4. **Gateway skeleton:** implement a small backend service that validates issuer/JWKS/signature/audience/time and maps claims to the normalized contract.
5. **OPA migration:** migrate policy input from `input.user.role` to `input.identity.roles` (or a deliberately selected single-role model) with regression tests for every existing allow/deny case.
6. **Integration tests:** exercise valid and invalid tokens, policy decisions, unavailable OPA, vendor expiry, and tampering.
7. **Evidence and documentation:** record reproducible test commands, redacted outputs, limitations, and CI results.

## 13. Completion criteria

This stage is complete only when:

- The trust boundaries and gateway responsibilities are documented.
- The OPA input contract is versioned and consistently implemented.
- Invalid tokens are rejected before OPA evaluation.
- Authorization roles and MFA assurance are derived from verified evidence.
- The gateway injects trusted evaluation time and trusted resource/vendor context.
- OPA and gateway fail closed.
- Positive and negative integration tests pass.
- Runtime evidence is captured without exposing credentials.

## 14. Current limitations

- No application callback handler or policy gateway exists in the repository yet.
- No JWT verification or JWKS integration is implemented.
- No explicit API audience has yet been configured or verified.
- The actual MFA assurance claim emitted by the configured Keycloak flow is unknown until runtime inspection.
- The current Rego policy uses the legacy `input.user.role` shape; the normalized contract above is a proposed future contract.
- The Keycloak realm's localhost callback is suitable only for the isolated local lab.
- CI validation does not prove live authentication, MFA enforcement, token verification, or end-to-end authorization.

## 15. References

- Keycloak Server Administration Guide — Authentication flows: https://www.keycloak.org/docs/26.8.0/server_admin/#_authentication-flows
- Keycloak Server Administration Guide — Server import/export: https://www.keycloak.org/server/importExport
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0 Security Best Current Practice (RFC 9700): https://www.rfc-editor.org/rfc/rfc9700
- JSON Web Token (JWT) Best Current Practices (RFC 8725): https://www.rfc-editor.org/rfc/rfc8725
- Open Policy Agent documentation: https://www.openpolicyagent.org/docs/latest/
