package access

import rego.v1

# Default deny: no request is authorized unless a rule below matches.
default allow := false

# Public resources are readable by active identities.
allow if {
    input.user.active == true
    input.resource.classification == "public"
    input.action == "read"
}

# System administrators are restricted to explicitly managed infrastructure
# and identity/policy control-plane resources.
allow if {
    input.user.active == true
    input.user.role == "system_admin"
    input.resource.type in {"server", "identity_config", "policy_config"}
    input.action in {"read", "write", "admin"}
}

# Security analysts may read security logs only.
allow if {
    input.user.active == true
    input.user.role == "security_analyst"
    input.resource.type == "security_logs"
    input.action == "read"
}

# Database administrators may read and write database resources only.
allow if {
    input.user.active == true
    input.user.role == "database_admin"
    input.resource.type == "database"
    input.action in {"read", "write"}
}

# Auditors are read-only and limited to audit reports.
allow if {
    input.user.active == true
    input.user.role == "auditor"
    input.resource.type == "audit_report"
    input.action == "read"
}

# Vendor access requires explicit approval, a matching resource, a numeric
# expiry, and a trusted evaluation timestamp injected by the policy gateway.
# input.context.evaluated_at_epoch MUST be server-side trusted context; never
# accept it directly from an end-user request.
allow if {
    input.user.active == true
    input.user.role == "external_vendor"
    input.action == "read"
    input.vendor_access.approved == true
    input.vendor_access.resource_id == input.resource.id
    is_number(input.vendor_access.expires_at_epoch)
    is_number(input.context.evaluated_at_epoch)
    input.context.evaluated_at_epoch < input.vendor_access.expires_at_epoch
}
