package access

import rego.v1

# Default deny: no request is authorized unless an explicit rule matches.
default allow := false

# Identity attributes are normalized by the trusted gateway after token
# verification. Never pass browser-supplied identity data directly to OPA.
active_identity if {
    input.identity.active == true
}

has_role(role) if {
    input.identity.roles[_] == role
}

mfa_verified if {
    input.identity.auth_strength.mfa_verified == true
}

# Public resources are readable by active identities. Public access does not
# grant write, update, delete, or administrative permissions.
allow if {
    active_identity
    input.resource.classification == "public"
    input.action == "read"
}

# All non-public role-based permissions require verified MFA evidence.
# The gateway must derive this value from the tested Keycloak authentication
# flow; TOTP enrollment alone is not sufficient.
allow if {
    active_identity
    has_role("system_admin")
    mfa_verified
    input.resource.type in {"server", "identity_config", "policy_config"}
    input.action in {"read", "write", "admin"}
}

allow if {
    active_identity
    has_role("security_analyst")
    mfa_verified
    input.resource.type == "security_logs"
    input.action == "read"
}

allow if {
    active_identity
    has_role("database_admin")
    mfa_verified
    input.resource.type == "database"
    input.action in {"read", "write"}
}

allow if {
    active_identity
    has_role("auditor")
    mfa_verified
    input.resource.type == "audit_report"
    input.action == "read"
}

# Vendor grants are read-only, MFA-protected, resource-bound and time-bound.
# Approval and evaluation time must be injected by trusted backend services.
allow if {
    active_identity
    has_role("external_vendor")
    mfa_verified
    input.action == "read"
    input.vendor_access.approved == true
    input.vendor_access.resource_id == input.resource.id
    is_number(input.vendor_access.expires_at_epoch)
    is_number(input.context.evaluated_at_epoch)
    input.context.evaluated_at_epoch < input.vendor_access.expires_at_epoch
}
