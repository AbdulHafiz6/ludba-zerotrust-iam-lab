
package access

import rego.v1

# Default deny
default allow := false

# Public resource read access
allow if {
    input.user.active == true
    input.resource.classification == "public"
    input.action == "read"
}

# System administrator permissions
allow if {
    input.user.active == true
    input.user.role == "system_admin"
    input.action in {"read", "write", "admin"}
}

# Security analyst permissions
allow if {
    input.user.active == true
    input.user.role == "security_analyst"
    input.resource.type == "security_logs"
    input.action == "read"
}

# Database administrator permissions
allow if {
    input.user.active == true
    input.user.role == "database_admin"
    input.resource.type == "database"
    input.action in {"read", "write"}
}

# Auditor permissions
allow if {
    input.user.active == true
    input.user.role == "auditor"
    input.resource.type == "audit_report"
    input.action == "read"
}

# Approved vendor permissions
allow if {
    input.user.active == true
    input.user.role == "external_vendor"
    input.action == "read"
    input.vendor_access.approved == true
    input.vendor_access.valid == true
    input.resource.id == input.vendor_access.resource_id
}
