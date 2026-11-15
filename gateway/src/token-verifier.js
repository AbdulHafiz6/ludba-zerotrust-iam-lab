import { createRemoteJWKSet, jwtVerify } from "jose";

/**
 * Verify a Keycloak access token against a statically configured issuer/JWKS.
 * The token itself can never select its own issuer or key URL.
 */
export function createAccessTokenVerifier(config, options = {}) {
  const jwks = options.jwks || createRemoteJWKSet(new URL(config.jwksUri), {
    timeoutDuration: 2000,
    cooldownDuration: 30000,
    cacheMaxAge: 300000
  });

  return async function verifyAccessToken(token) {
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: config.algorithms,
      clockTolerance: 5,
      requiredClaims: ["sub", "iss", "exp", "iat"]
    });

    // Keycloak access tokens use the Bearer token profile. Do not accept an
    // ID token or a JWT with a different/unspecified token-use marker.
    if (payload.typ !== "Bearer") throw new Error("Unexpected token profile");
    if (payload.azp !== config.allowedClientId) throw new Error("Unexpected authorized party");
    if (typeof payload.sub !== "string" || payload.sub.length === 0) throw new Error("Missing subject");
    if (typeof protectedHeader.kid !== "string" || protectedHeader.kid.length === 0) {
      throw new Error("Missing signing key identifier");
    }
    return payload;
  };
}
