# Ludba Policy Gateway

A fictional, local-only policy enforcement point (PEP) for the ludbA Bank Zero-Trust IAM simulation. The gateway validates a Keycloak access token, normalizes trusted identity claims, resolves resources and vendor grants from server-side fixtures, and asks OPA for an authorization decision.

**Status:** Initial implementation scaffold. It has not been runtime-tested against the local Keycloak realm or OPA service. The MFA claim mapping is intentionally unset until actual Keycloak token evidence is inspected.

## Security behavior

- Accepts bearer access tokens only.
- Verifies JWT signature using the configured Keycloak JWKS endpoint.
- Validates exact issuer, configured API audience, allowed signing algorithm, expiry, issued-at, and authorized party.
- Extracts only allowlisted realm roles from verified token claims.
- Requires a server-side identity status record; unknown identities fail closed.
- Resolves resource type and classification from a server-side resource catalog. Client-supplied classification is ignored.
- Loads vendor approvals from a server-side grant fixture.
- Generates evaluation time and request IDs on the server.
- Calls OPA and fails closed on timeout, dependency failure, or malformed decisions.
- Logs authorization metadata only, never bearer tokens or credentials.

## Important integration prerequisites

1. The realm import now defines a bearer-only resource client named `ludba-api` and an access-token audience mapper on `ludba-portal`. Verify that a newly issued access token contains `aud: ludba-api` before relying on the gateway.
2. Inspect the actual Keycloak access-token claim layout and confirm the authorized-party claim behavior.
3. Verify realm role claim paths using a real, redacted token.
4. Configure and test the mandatory password-plus-OTP Browser flow.
5. Identify a reliable issuer-controlled MFA assurance claim. Until then, leave MFA_CLAIM_PATH empty; restricted role-based authorization will be denied by the OPA policy.
6. Add the real lab user's issuer-scoped sub to data/identities.json only after confirming the test account. The sample IDs are fictional fixtures.
7. Replace the local HTTP issuer/JWKS configuration only with the exact HTTPS issuer and JWKS URLs for a separate deployment profile.

Do not set MFA_ACCEPTED_VALUES based on guesswork. The current example deliberately leaves it empty.

### Applying realm-import changes

Keycloak's startup import does not overwrite a realm that already exists. If the local `ludbA-bank` realm was imported before this audience change, the updated JSON will not automatically modify that existing realm. For a disposable lab, export any evidence you need, then remove and recreate the realm or reset the local Keycloak development data before restarting with `--import-realm`. This is destructive to local realm users and configuration; do not do it if you need to preserve them. Alternatively, apply the API client and audience mapper manually in the Admin Console. After either method, obtain a fresh access token and inspect its `aud` claim.

## Local development

From this directory:

    Copy-Item .env.example .env
    npm install
    npm test
    npm start

Edit .env only after confirming the actual Keycloak issuer, API audience, client context and MFA evidence. Keep .env untracked.

The gateway binds to 127.0.0.1 only. Do not expose this development server to a network.

## Authorization request

Send a POST request to http://127.0.0.1:8090/v1/authorize with a valid Keycloak access token:

    {
      "resource_id": "logs-01",
      "action": "read"
    }

The request must include Authorization: Bearer <access-token> and Content-Type: application/json.

The caller supplies only the resource identifier and action. The gateway resolves the resource metadata and identity attributes from trusted sources. Any additional client-supplied role, MFA, classification, approval, expiry or evaluation-time fields are ignored.

## Response semantics

- 200: OPA explicitly allowed the action.
- 401: missing or invalid token.
- 403: identity is inactive/unknown or OPA denied the action.
- 400: malformed authorization request.
- 404: resource is not in the server-side catalog.
- 503: OPA unavailable or returned an invalid response.

## Unit tests

    npm test

The tests cover role allowlisting, identity lifecycle defaults, missing MFA evidence, safe claim lookup, and cryptographic JWT verification cases using a locally generated test key. JWT tests cover trusted signature, issuer, audience, authorized party, expiry, token profile and unsupported signing algorithm. They do not prove token issuance by the live Keycloak realm or end-to-end OPA enforcement.

## Limitations

- The identity status, resource catalog and vendor grant files are simulation fixtures, not production data stores.
- The API audience ludba-api must be configured in Keycloak before real tokens can pass validation.
- The exact Keycloak access-token claim paths and MFA assurance signal remain unverified until runtime inspection.
- The gateway has no browser login callback, session management, refresh-token handling, or production deployment configuration.
- No secrets belong in this repository.
