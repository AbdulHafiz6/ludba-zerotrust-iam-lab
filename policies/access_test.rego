package access_test

import rego.v1
import data.access

test_public_resource_read_allowed_for_active_identity if {
    access.allow with input as {
        "identity": {"subject": "user-01", "active": true, "roles": []},
        "resource": {"id": "notice-01", "type": "notice", "classification": "public"},
        "action": "read"
    }
}

test_public_resource_write_denied if {
    not access.allow with input as {
        "identity": {"subject": "user-01", "active": true, "roles": []},
        "resource": {"id": "notice-01", "type": "notice", "classification": "public"},
        "action": "write"
    }
}

test_inactive_identity_denied_even_for_public_read if {
    not access.allow with input as {
        "identity": {"subject": "user-01", "active": false, "roles": []},
        "resource": {"id": "notice-01", "type": "notice", "classification": "public"},
        "action": "read"
    }
}

test_missing_identity_denied if {
    not access.allow with input as {
        "resource": {"id": "notice-01", "type": "notice", "classification": "public"},
        "action": "read"
    }
}

test_system_admin_can_administer_managed_server_with_mfa if {
    access.allow with input as {
        "identity": {"active": true, "roles": ["system_admin"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "admin"
    }
}

test_system_admin_denied_without_mfa if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["system_admin"], "auth_strength": {"mfa_verified": false}},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "admin"
    }
}

test_system_admin_denied_when_mfa_evidence_missing if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["system_admin"]},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "admin"
    }
}

test_system_admin_denied_unmanaged_resource_type if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["system_admin"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "payroll-01", "type": "payroll", "classification": "restricted"},
        "action": "read"
    }
}

test_system_admin_role_does_not_grant_arbitrary_action if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["system_admin"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "delete"
    }
}

test_security_analyst_can_read_security_logs_with_mfa if {
    access.allow with input as {
        "identity": {"active": true, "roles": ["security_analyst"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "logs-01", "type": "security_logs", "classification": "confidential"},
        "action": "read"
    }
}

test_security_analyst_denied_without_mfa if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["security_analyst"], "auth_strength": {"mfa_verified": false}},
        "resource": {"id": "logs-01", "type": "security_logs", "classification": "confidential"},
        "action": "read"
    }
}

test_security_analyst_cannot_write_logs if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["security_analyst"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "logs-01", "type": "security_logs", "classification": "confidential"},
        "action": "write"
    }
}

test_database_admin_can_write_database_with_mfa if {
    access.allow with input as {
        "identity": {"active": true, "roles": ["database_admin"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "db-01", "type": "database", "classification": "restricted"},
        "action": "write"
    }
}

test_database_admin_denied_without_mfa if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["database_admin"], "auth_strength": {"mfa_verified": false}},
        "resource": {"id": "db-01", "type": "database", "classification": "restricted"},
        "action": "write"
    }
}

test_database_admin_denied_server_admin if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["database_admin"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "admin"
    }
}

test_auditor_can_read_reports_with_mfa if {
    access.allow with input as {
        "identity": {"active": true, "roles": ["auditor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "audit-01", "type": "audit_report", "classification": "confidential"},
        "action": "read"
    }
}

test_auditor_denied_without_mfa if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["auditor"], "auth_strength": {"mfa_verified": false}},
        "resource": {"id": "audit-01", "type": "audit_report", "classification": "confidential"},
        "action": "read"
    }
}

test_auditor_cannot_write_reports if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["auditor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "audit-01", "type": "audit_report", "classification": "confidential"},
        "action": "write"
    }
}

test_multi_role_identity_receives_only_matching_permissions if {
    access.allow with input as {
        "identity": {"active": true, "roles": ["auditor", "security_analyst"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "logs-01", "type": "security_logs", "classification": "confidential"},
        "action": "read"
    }
}

test_unknown_role_grants_no_restricted_access if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["super_admin"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "admin"
    }
}

test_legacy_user_role_shape_does_not_authorize if {
    not access.allow with input as {
        "user": {"active": true, "role": "system_admin"},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "admin"
    }
}

test_vendor_approved_unexpired_matching_resource_allowed if {
    access.allow with input as {
        "identity": {"active": true, "roles": ["external_vendor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {"approved": true, "resource_id": "maintenance-01", "expires_at_epoch": 2000000000},
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_denied_without_mfa if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["external_vendor"], "auth_strength": {"mfa_verified": false}},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {"approved": true, "resource_id": "maintenance-01", "expires_at_epoch": 2000000000},
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_expired_access_denied_at_and_after_expiry if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["external_vendor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {"approved": true, "resource_id": "maintenance-01", "expires_at_epoch": 1900000000},
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_missing_expiry_denied if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["external_vendor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {"approved": true, "resource_id": "maintenance-01"},
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_string_expiry_denied if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["external_vendor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {"approved": true, "resource_id": "maintenance-01", "expires_at_epoch": "2000000000"},
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_missing_trusted_evaluation_time_denied if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["external_vendor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {"approved": true, "resource_id": "maintenance-01", "expires_at_epoch": 2000000000}
    }
}

test_vendor_cross_resource_denied if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["external_vendor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "server-99", "type": "server", "classification": "restricted"},
        "action": "read",
        "vendor_access": {"approved": true, "resource_id": "maintenance-01", "expires_at_epoch": 2000000000},
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_unapproved_denied if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["external_vendor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {"approved": false, "resource_id": "maintenance-01", "expires_at_epoch": 2000000000},
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_write_denied_even_when_approved if {
    not access.allow with input as {
        "identity": {"active": true, "roles": ["external_vendor"], "auth_strength": {"mfa_verified": true}},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "write",
        "vendor_access": {"approved": true, "resource_id": "maintenance-01", "expires_at_epoch": 2000000000},
        "context": {"evaluated_at_epoch": 1900000000}
    }
}
