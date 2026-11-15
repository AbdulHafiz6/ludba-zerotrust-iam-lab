import { readFileSync } from "node:fs";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required configuration: ${name}`);
  return value;
}

function parseJsonEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON in environment variable: ${name}`);
  }
}

export function loadConfig() {
  const issuer = required("OIDC_ISSUER").replace(/\/$/, "");
  const jwksUri = required("OIDC_JWKS_URI");
  const audience = required("OIDC_AUDIENCE");
  const allowedClientId = required("OIDC_ALLOWED_CLIENT_ID");
  const algorithms = (process.env.OIDC_ALLOWED_ALGORITHMS || "RS256")
    .split(",").map((item) => item.trim()).filter(Boolean);
  const mfaClaimPath = process.env.MFA_CLAIM_PATH || "";
  const mfaAcceptedValues = parseJsonEnv("MFA_ACCEPTED_VALUES", []);

  if (!jwksUri.startsWith("https://") && !jwksUri.startsWith("http://127.0.0.1:") && !jwksUri.startsWith("http://localhost:")) {
    throw new Error("JWKS URI must use HTTPS outside the localhost lab");
  }
  if (!Array.isArray(mfaAcceptedValues)) {
    throw new Error("MFA_ACCEPTED_VALUES must be a JSON array");
  }

  return {
    port: Number(process.env.PORT || 8090),
    issuer,
    jwksUri,
    audience,
    allowedClientId,
    algorithms,
    mfaClaimPath,
    mfaAcceptedValues,
    opaUrl: required("OPA_URL").replace(/\/$/, ""),
    opaDecisionPath: process.env.OPA_DECISION_PATH || "/v1/data/access/allow",
    opaTimeoutMs: Number(process.env.OPA_TIMEOUT_MS || 1500),
    identityStatus: JSON.parse(readFileSync(process.env.IDENTITY_STATUS_FILE || "./data/identities.json", "utf8")),
    resourceCatalog: JSON.parse(readFileSync(process.env.RESOURCE_CATALOG_FILE || "./data/resources.json", "utf8")),
    vendorGrants: JSON.parse(readFileSync(process.env.VENDOR_GRANTS_FILE || "./data/vendor-grants.json", "utf8"))
  };
}
