import test from "node:test";
import assert from "node:assert/strict";
import { normalizeIdentity, getPath } from "../src/claims.js";

const config = {
  identityStatus: { "user-1": { active: true }, "user-disabled": { active: false } },
  mfaClaimPath: "auth_context.assurance",
  mfaAcceptedValues: ["password+otp"]
};

test("normalizes only allowlisted realm roles", () => {
  const identity = normalizeIdentity({
    sub: "user-1",
    iss: "https://issuer.example/realm",
    azp: "ludba-portal",
    realm_access: { roles: ["system_admin", "made_up_admin", "auditor", "system_admin"] },
    auth_context: { assurance: "password+otp" }
  }, config);
  assert.deepEqual(identity.roles, ["system_admin", "auditor"]);
  assert.equal(identity.active, true);
  assert.equal(identity.auth_strength.mfa_verified, true);
});

test("unknown identity is inactive by default", () => {
  const identity = normalizeIdentity({ sub: "unlisted-user", realm_access: { roles: ["system_admin"] } }, config);
  assert.equal(identity.active, false);
});

test("disabled identity remains inactive even when token contains roles", () => {
  const identity = normalizeIdentity({ sub: "user-disabled", realm_access: { roles: ["auditor"] } }, config);
  assert.equal(identity.active, false);
});

test("missing MFA claim fails closed", () => {
  const identity = normalizeIdentity({ sub: "user-1", realm_access: { roles: ["auditor"] } }, config);
  assert.equal(identity.auth_strength.mfa_verified, false);
});

test("MFA cannot be inferred when no claim path is configured", () => {
  const identity = normalizeIdentity({
    sub: "user-1",
    realm_access: { roles: ["auditor"] },
    auth_context: { assurance: "password+otp" }
  }, { ...config, mfaClaimPath: "", mfaAcceptedValues: ["password+otp"] });
  assert.equal(identity.auth_strength.mfa_verified, false);
});

test("nested claim lookup safely handles missing paths", () => {
  assert.equal(getPath({ realm_access: { roles: ["auditor"] } }, "realm_access.roles.0"), "auditor");
  assert.equal(getPath({}, "realm_access.roles"), undefined);
});
