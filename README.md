# Ludba Zero-Trust IAM Lab

A fictional enterprise identity and access security simulation for the Ludba Tech Lab cyber-range. This repository models identity-aware authorization for the **ludbA Bank** environment; it is not connected to a production banking system.

## Current capabilities

- Open Policy Agent (OPA) authorization with default-deny behavior.
- Role-scoped access for system administrators, security analysts, database administrators, auditors and external vendors.
- Automated Rego tests for allowed and denied access paths.
- Keycloak realm configuration for the simulated ludbA Bank identity environment.
- GitHub Actions validation of the realm JSON, Rego syntax and policy tests.

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

## Time-bound vendor access

Vendor authorization requires all of the following:

1. An active vendor identity.
2. Explicit approval.
3. A resource identifier matching the requested resource.
4. A numeric `expires_at_epoch` later than the policy evaluation time.
5. A trusted `context.evaluated_at_epoch` value.

**Trust boundary:** `context.evaluated_at_epoch` must be injected by the trusted policy gateway or authorization service. It must be derived from server time and must never be accepted from an end-user-controlled request. The sample in `examples/vendor-request.json` is a test fixture only; its evaluation timestamp is illustrative and must be replaced by trusted runtime context in a live simulation.

The policy compares Unix epoch seconds and denies access at the exact expiry instant.

## Repository layout

```text
.
├── .github/workflows/security-policy.yml
├── examples/
│   ├── admin-request.json
│   ├── auditor-request.json
│   └── vendor-request.json
├── keycloak/
│   └── realm-ludba.json
└── policies/
    ├── access.rego
    └── access_test.rego
```

## Run policy checks locally

Install the Open Policy Agent CLI, then run:

```bash
opa check --strict policies/
opa test policies/ -v
opa eval --data policies/access.rego --input examples/vendor-request.json "data.access.allow"
```

The GitHub Actions workflow runs JSON validation, strict Rego validation and the automated policy test suite on pushes and pull requests targeting `main`.

## Simulation boundaries and next steps

All identities, resources and access requests in this repository are fictional. No real customer, employee, banking or production data should be used.

The current policy suite demonstrates authorization decisions in OPA. It does **not** yet demonstrate a complete end-to-end Keycloak authentication, token validation and OPA enforcement integration. The next engineering stages are to connect the identity provider to a trusted policy gateway, implement MFA and lifecycle controls, and capture reproducible security evidence.
