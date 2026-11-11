# Local Keycloak MFA Lab

This runbook starts the fictional ludbA Bank identity realm in an isolated local Docker environment. It is a development lab only, not a production deployment.

## Prerequisites

- Docker Engine with the Docker Compose plugin.
- A terminal in the repository root.
- A password manager to generate and retain a unique local Keycloak administrator password.

## Start Keycloak

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` and replace the placeholder administrator password with a long, unique random value.
3. Start the service:
   ```bash
   docker compose up -d
   ```
4. Follow startup logs:
   ```bash
   docker compose logs -f keycloak
   ```
5. Open the local administration console at http://localhost:8080/admin and sign in using the bootstrap credentials in your local `.env` file.
6. Confirm that the `ludbA-bank` realm and the `ludba-portal` client were imported.

The Compose file binds port 8080 to 127.0.0.1 only. Do not expose this development server to a public network. The development-mode server and its local HTTP endpoints are not production hardened.

## Enforce password + TOTP in the Browser flow

The realm import configures TOTP policy and enrollment, but the built-in Browser flow is not automatically changed by that setting. Keycloak built-in flows should be duplicated before customization.

1. In the Admin Console, select the `ludbA-bank` realm.
2. Open **Authentication → Flows**.
3. Find the built-in **Browser** flow. Use its action menu and select **Duplicate**.
4. Name the copy `Ludba Browser MFA`.
5. Open the duplicated flow and inspect its **Forms** sub-flow.
6. Ensure the **Username Password Form** execution is **Required**.
7. Configure the MFA branch so the **OTP Form** is **Required** and not merely Alternative or conditional on an already-configured credential. If the duplicated default flow contains a **Browser - Conditional 2FA** sub-flow with **Condition - User Configured**, do not leave that condition as the gate for mandatory OTP; configure a password-first path with a required OTP execution.
8. Use the **Actions → Bind flow** action on the duplicated flow and bind it as the **Browser Flow**.
9. Save the change.

Keycloak's documented flow behavior is that a required second-factor execution prompts a user who has not yet enrolled to set up that credential during authentication. A first-factor password execution must remain required before the OTP step. Review the official guide linked below before changing flow structure.

## Test cases

Create fictional test users in the realm and assign them to the appropriate groups. Do not reuse real passwords or personal information.

- **New user, no OTP:** after valid username/password, Keycloak must require authenticator enrollment before login completes.
- **Enrolled user, correct OTP:** login completes.
- **Enrolled user, incorrect OTP:** login is rejected.
- **Enrolled user, missing OTP:** login cannot complete.
- **Disabled user:** login is rejected.
- **Recovery:** test only after explicitly enabling and configuring the recovery-code required action; store recovery codes securely and verify single-use behavior.

Capture the flow configuration and test evidence without recording passwords, OTP seeds, QR codes, recovery codes, access tokens or refresh tokens.

## Stop and reset

Stop the service:
```bash
docker compose down
```

Remove the local database and all realm state:
```bash
docker compose down -v
```

The second command is destructive and deletes the local Keycloak database volume.

## Security notes

- `.env` is ignored by Git. Never commit real credentials.
- The example bootstrap password is intentionally a placeholder and must be replaced.
- Keep the service bound to localhost.
- The realm's callback and web-origin values are local examples only.
- Do not use `start-dev`, HTTP, or the sample credentials in production.
- TOTP setup is not the same as verified mandatory MFA; only the configured and tested browser flow provides that enforcement in this lab.
- The current repository does not yet contain an application callback server or an OPA enforcement gateway, so the OIDC client is configured but end-to-end SSO is not yet demonstrated.

## Official references

- [Keycloak 26.8 Server Administration Guide — Authentication flows](https://www.keycloak.org/docs/26.8.0/server_admin/#_authentication-flows)
- [Keycloak — Importing and exporting realms](https://www.keycloak.org/server/importExport)
