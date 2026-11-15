import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT, createLocalJWKSet } from "jose";
import { createAccessTokenVerifier } from "../src/token-verifier.js";

const issuer = "https://id.example.test/realms/ludba-bank";
const audience = "ludba-api";
const clientId = "ludba-portal";
const now = Math.floor(Date.now() / 1000);
const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwk = await exportJWK(publicKey);
jwk.kid = "test-key-1";
jwk.alg = "RS256";
jwk.use = "sig";
const localJwks = createLocalJWKSet({ keys: [jwk] });

const config = {
  issuer,
  audience,
  allowedClientId: clientId,
  algorithms: ["RS256"],
  jwksUri: "https://unused.invalid/jwks"
};

async function token(overrides = {}, header = {}) {
  const claims = {
    iss: issuer,
    sub: "fictional-user-001",
    aud: audience,
    azp: clientId,
    typ: "Bearer",
    iat: now,
    exp: now + 300,
    ...overrides
  };
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "test-key-1", typ: "JWT", ...header })
    .sign(privateKey);
}

function verifier() {
  return createAccessTokenVerifier(config, { jwks: localJwks });
}

test("accepts correctly signed access token with expected issuer, audience and client", async () => {
  const payload = await verifier()(await token());
  assert.equal(payload.sub, "fictional-user-001");
  assert.equal(payload.typ, "Bearer");
});

test("rejects token signed with an untrusted key", async () => {
  const other = await generateKeyPair("RS256");
  const forged = await new SignJWT({
    iss: issuer, sub: "fictional-user-001", aud: audience, azp: clientId,
    typ: "Bearer", iat: now, exp: now + 300
  }).setProtectedHeader({ alg: "RS256", kid: "attacker-key" }).sign(other.privateKey);
  await assert.rejects(verifier()(forged));
});

test("rejects wrong issuer", async () => {
  await assert.rejects(verifier()(await token({ iss: "https://evil.example/realm" })));
});

test("rejects wrong audience", async () => {
  await assert.rejects(verifier()(await token({ aud: "another-api" })));
});

test("rejects wrong authorized party", async () => {
  await assert.rejects(verifier()(await token({ azp: "another-client" })));
});

test("rejects expired token", async () => {
  await assert.rejects(verifier()(await token({ exp: now - 60, iat: now - 600 })));
});

test("rejects token without the access-token Bearer profile", async () => {
  await assert.rejects(verifier()(await token({ typ: "ID" })));
});

test("rejects unsupported signing algorithm", async () => {
  const bad = await new SignJWT({
    iss: issuer, sub: "fictional-user-001", aud: audience, azp: clientId,
    typ: "Bearer", iat: now, exp: now + 300
  }).setProtectedHeader({ alg: "RS512", kid: "test-key-1" }).sign(privateKey);
  await assert.rejects(verifier()(bad));
});
