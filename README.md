# Ludba Zero-Trust IAM Lab

A fictional enterprise identity and access security simulation for the Ludba Tech Lab cyber-range. This repository models identity-aware authorization for the **ludbA Bank** environment; it is not connected to a production banking system.

## Current capabilities

- Open Policy Agent (OPA) authorization with default-deny behavior.
- Role-scoped access for system administrators, security analysts, database administrators, auditors and external vendors.
- Automated Rego tests for allowed and denied access paths.
- Keycloak realm configuration with TOTP enrollment, mapped identity groups and OIDC PKCE settings.
- GitHub Actions validation of realm JSON, selected Keycloak security settings, Rego syntax and policy tests.

## Authorization model

Every request is denied unless an explicit policy rule allows it. Roles are constrained by resource type and action:

| Role | Permitted scope |
|---|---|
| system_admin | Read, write and admin on managed server, identity configuration and policy configuration resources |
| security_analyst | Read security logs |
| database_admin | Read and write database resources |
| auditor | Read audit reports |
| external_vendor | Read only the specifically approved resource, before its access expiry |

Public resources are readable by active identities. This does not grant access to non-public resources.

## Keycloak identity configuration

The realm defines five authorization roles and maps them to four organizational groups. The IT Operations group currently contains both system_admin and database_admin; this is a demonstration mapping and should be split into narrower groups before introducing real identities.

TOTP is configured as the realm OTP method, with six-digit, 30-second codes. CONFIGURE_TOTP is included as a default required action so users are prompted to enrol an authenticator. This is an enrollment requirement, not by itself proof that every authentication flow enforces MFA for every login. A production-grade deployment must also configure and test an authentication flow that requires OTP at sign-in, including recovery and reset controls.

The ludba-portal client is a public OpenID Connect browser client. Direct access grants and implicit flow are disabled. The client is configured for PKCE S256 and an exact local callback URI:

- Redirect URI: http://localhost:8080/callback
- Web origin: http://localhost:8080
- PKCE challenge method: S256

These localhost values are for the isolated lab only. Replace them with the exact HTTPS origin and callback used by the deployed lab before deployment. Do not use broad wildcard redirect URIs for a real application.

## Time-bound vendor access

Vendor authorization requires an active vendor identity, explicit approval, a matching resource identifier, an expiry later than evaluation time, and a trusted context.evaluated_at_epoch value.

Trust boundary: context.evaluated_at_epoch must be injected by the trusted policy gateway or authorization service from server time. It must never be accepted from an end-user-controlled request. The sample vendor request is a test fixture only.

The policy compares Unix epoch seconds and denies access at the exact expiry instant.

## Repository layout

See .github/workflows/security-policy.yml, examples/, keycloak/realm-ludba.json and policies/ for the implementation.

## Run policy checks locally

Install the Open Policy Agent CLI and jq, then run:

```bash
jq -e . keycloak/realm-ludba.json > /dev/null
opa check --strict policies/
opa test policies/ -v
opa eval --data policies/access.rego --input examples/vendor-request.json "data.access.allow"
```

The GitHub Actions workflow validates realm JSON, checks selected TOTP and OIDC client settings, validates Rego syntax and runs the automated policy test suite on pushes and pull requests targeting main.

## Simulation boundaries and next steps

All identities, resources and access requests in this repository are fictional. No real customer, employee, banking or production data should be used.

The current policy suite demonstrates authorization decisions in OPA. It does not yet demonstrate a complete end-to-end Keycloak authentication, token validation and OPA enforcement integration. Next stages are to validate realm import against the chosen Keycloak release, configure and test an OTP-enforcing browser authentication flow, connect the identity provider to a trusted policy gateway, and capture reproducible security evidence.
