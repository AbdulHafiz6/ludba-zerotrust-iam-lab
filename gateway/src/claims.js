const ALLOWED_ROLES = new Set([
  "system_admin",
  "security_analyst",
  "database_admin",
  "auditor",
  "external_vendor"
]);

export function getPath(value, path) {
  if (!path) return undefined;
  return path.split(".").reduce((current, key) => {
    if (current === null || current === undefined || typeof current !== "object") return undefined;
    return current[key];
  }, value);
}

export function normalizeIdentity(payload, config) {
  const subject = typeof payload.sub === "string" ? payload.sub : "";
  const issuer = typeof payload.iss === "string" ? payload.iss : "";
  const clientId = typeof payload.azp === "string" ? payload.azp : "";

  const rawRoles = payload.realm_access?.roles;
  const roles = Array.isArray(rawRoles)
    ? [...new Set(rawRoles.filter((role) => typeof role === "string" && ALLOWED_ROLES.has(role)))]
    : [];

  const status = config.identityStatus[subject];
  const active = status?.active === true;

  // Deliberately fail closed until the actual Keycloak MFA assurance claim
  // is observed and explicitly configured in the local environment.
  const mfaValue = config.mfaClaimPath ? getPath(payload, config.mfaClaimPath) : undefined;
  const mfaVerified = config.mfaClaimPath !== "" &&
    config.mfaAcceptedValues.some((accepted) => accepted === mfaValue);

  return {
    subject,
    issuer,
    client_id: clientId,
    roles,
    active,
    auth_strength: {
      mfa_verified: mfaVerified,
      method: mfaVerified ? ["issuer-verified-assurance"] : []
    }
  };
}
