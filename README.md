# Ludba Zero-Trust IAM Lab

A fictional enterprise identity and access security simulation for the Ludba Tech Lab cyber-range. This repository models identity-aware authorization for the **ludbA Bank** environment; it is not connected to a production banking system.

## Current capabilities

- Open Policy Agent (OPA) authorization with default-deny behavior.
- Role-scoped access for system administrators, security analysts, database administrators, auditors and external vendors.
- Automated Rego tests for allowed and denied access paths.
- Keycloak realm configuration with TOTP enrollment, mapped identity groups and OIDC PKCE settings.
- A local Docker Compose Keycloak environment with startup realm import.
- GitHub Actions validation of realm JSON, selected Keycloak security settings, Docker Compose configuration, Rego syntax and policy tests.

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

TOTP is configured as the realm OTP method, with six-digit, 30-second codes. CONFIGURE_TOTP is included as a default required action so users are prompted to enrol an authenticator. This enrollment requirement alone does not prove mandatory MFA at every login. The local lab runbook explains how to duplicate the Browser flow and configure a required password-plus-OTP path.

The ludba-portal client is a public OpenID Connect browser client. Direct access grants and implicit flow are disabled. The client is configured for PKCE S256 and an exact local callback URI:

- Redirect URI: http://localhost:8080/callback
- Web origin: http://localhost:8080
- PKCE challenge method: S256

These localhost values are for the isolated lab only. Replace them with the exact HTTPS origin and callback used by the deployed lab before deployment. Do not use broad wildcard redirect URIs for a real application.

## Start the local Keycloak lab

Requirements: Docker Engine and the Docker Compose plugin.

```bash
cp .env.example .env
```

Edit `.env` and replace the placeholder bootstrap administrator password with a long, unique random password. Then run:

```bash
docker compose up -d
docker compose logs -f keycloak
```

Open http://localhost:8080/admin and sign in with the bootstrap credentials in your local `.env` file. The realm import file is `keycloak/ludbA-bank-realm.json`.

Detailed startup, Browser MFA flow setup, test cases, reset instructions and security boundaries are documented in [keycloak/README.md](keycloak/README.md).

Stop the lab with `docker compose down`. To delete the local Keycloak database volume as well, run `docker compose down -v`; this is destructive.

## Time-bound vendor access

Vendor authorization requires an active vendor identity, explicit approval, a matching resource identifier, an expiry later than evaluation time, and a trusted context.evaluated_at_epoch value.

Trust boundary: context.evaluated_at_epoch must be injected by the trusted policy gateway or authorization service from server time. It must never be accepted from an end-user-controlled request. The sample vendor request is a test fixture only.

The policy compares Unix epoch seconds and denies access at the exact expiry instant.

## Repository layout

```text
.
├── .github/workflows/security-policy.yml
├── examples/
├── keycloak/
│   ├── ludbA-bank-realm.json
│   └── README.md
├── policies/
├── compose.yaml
└── .env.example
```

## Run policy checks locally

Install the Open Policy Agent CLI and jq, then run:

```bash
jq -e . keycloak/ludbA-bank-realm.json > /dev/null
opa check --strict policies/
opa test policies/ -v
opa eval --data policies/access.rego --input examples/vendor-request.json "data.access.allow"
```

The GitHub Actions workflow validates realm JSON, checks selected TOTP and OIDC client settings, validates Docker Compose configuration, validates Rego syntax and runs the automated policy test suite on pushes and pull requests targeting main.

## Simulation boundaries and next steps

All identities, resources and access requests in this repository are fictional. No real customer, employee, banking or production data should be used.

The current repository provides OPA policy tests and a Docker-based Keycloak realm lab. It does not yet demonstrate a complete end-to-end application login, token validation and OPA enforcement integration. The next stages are to run and verify the Keycloak container, capture mandatory MFA test evidence, connect the identity provider to a trusted policy gateway, and capture reproducible security evidence.
