import express from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { loadConfig } from "./config.js";
import { normalizeIdentity } from "./claims.js";
import { evaluatePolicy } from "./opa-client.js";

const config = loadConfig();
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "8kb", strict: true }));

const jwks = createRemoteJWKSet(new URL(config.jwksUri), {
  timeoutDuration: 2000,
  cooldownDuration: 30000,
  cacheMaxAge: 300000
});

const allowedActions = new Set(["read", "write", "admin"]);

function unauthorized(res) {
  return res.status(401).json({ error: "unauthorized", message: "A valid access token is required." });
}

app.get("/healthz", (_req, res) => {
  res.json({ status: "ok", service: "ludba-policy-gateway" });
});

app.post("/v1/authorize", async (req, res) => {
  const authHeader = req.get("authorization") || "";
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(authHeader);
  if (!match || match[1].length > 16384) return unauthorized(res);

  let payload;
  try {
    const verified = await jwtVerify(match[1], jwks, {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: config.algorithms,
      clockTolerance: 5,
      requiredClaims: ["sub", "iss", "exp", "iat"]
    });
    payload = verified.payload;
    if (payload.azp !== config.allowedClientId) return unauthorized(res);
    if (payload.typ && payload.typ !== "Bearer") return unauthorized(res);
  } catch {
    return unauthorized(res);
  }

  const identity = normalizeIdentity(payload, config);
  if (!identity.subject || !identity.active) {
    return res.status(403).json({ decision: "deny", reason: "identity_inactive_or_unknown" });
  }

  const resourceId = req.body?.resource_id;
  const action = req.body?.action;
  if (typeof resourceId !== "string" || typeof action !== "string" || !allowedActions.has(action)) {
    return res.status(400).json({ error: "invalid_authorization_request" });
  }

  // Resource classification and type are loaded from the server-side catalog.
  // Client-supplied resource metadata is deliberately ignored.
  const resource = config.resourceCatalog[resourceId];
  if (!resource) return res.status(404).json({ error: "resource_not_found" });

  const vendorAccess = identity.roles.includes("external_vendor")
    ? (config.vendorGrants[`${identity.subject}:${resourceId}`] || {
        approved: false, resource_id: resourceId, expires_at_epoch: 0
      })
    : { approved: false, resource_id: resourceId, expires_at_epoch: 0 };

  const input = {
    identity,
    resource,
    action,
    vendor_access: vendorAccess,
    context: {
      evaluated_at_epoch: Math.floor(Date.now() / 1000),
      request_id: crypto.randomUUID()
    }
  };

  try {
    const allowed = await evaluatePolicy({
      opaUrl: config.opaUrl,
      decisionPath: config.opaDecisionPath,
      timeoutMs: config.opaTimeoutMs,
      input
    });
    // Deliberately log metadata only. Never log bearer tokens or full claims.
    console.info(JSON.stringify({
      event: "authorization_decision",
      request_id: input.context.request_id,
      subject: identity.subject,
      resource_id: resource.id,
      action,
      decision: allowed ? "allow" : "deny"
    }));
    return res.status(allowed ? 200 : 403).json({
      decision: allowed ? "allow" : "deny",
      request_id: input.context.request_id
    });
  } catch {
    console.error(JSON.stringify({
      event: "authorization_dependency_failure",
      request_id: input.context.request_id,
      dependency: "opa"
    }));
    return res.status(503).json({ error: "authorization_unavailable" });
  }
});

app.use((error, _req, res, _next) => {
  if (error?.type === "entity.parse.failed" || error?.type === "entity.too.large") {
    return res.status(error.type === "entity.too.large" ? 413 : 400).json({ error: "invalid_request_body" });
  }
  return res.status(500).json({ error: "internal_error" });
});

app.listen(config.port, "127.0.0.1", () => {
  console.info(`Ludba policy gateway listening on 127.0.0.1:${config.port}`);
});
