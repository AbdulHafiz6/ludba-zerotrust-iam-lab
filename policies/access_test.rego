package access_test

import rego.v1
import data.access

test_admin_can_administer_managed_server if {
    access.allow with input as {
        "user": {"active": true, "role": "system_admin"},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "admin"
    }
}

test_admin_denied_unmanaged_resource_type if {
    not access.allow with input as {
        "user": {"active": true, "role": "system_admin"},
        "resource": {"id": "payroll-01", "type": "payroll", "classification": "restricted"},
        "action": "read"
    }
}

test_admin_denied_inactive_identity if {
    not access.allow with input as {
        "user": {"active": false, "role": "system_admin"},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "admin"
    }
}

test_security_analyst_can_read_security_logs if {
    access.allow with input as {
        "user": {"active": true, "role": "security_analyst"},
        "resource": {"id": "logs-01", "type": "security_logs", "classification": "confidential"},
        "action": "read"
    }
}

test_security_analyst_cannot_write_logs if {
    not access.allow with input as {
        "user": {"active": true, "role": "security_analyst"},
        "resource": {"id": "logs-01", "type": "security_logs", "classification": "confidential"},
        "action": "write"
    }
}

test_database_admin_can_write_database if {
    access.allow with input as {
        "user": {"active": true, "role": "database_admin"},
        "resource": {"id": "db-01", "type": "database", "classification": "restricted"},
        "action": "write"
    }
}

test_database_admin_denied_server_admin if {
    not access.allow with input as {
        "user": {"active": true, "role": "database_admin"},
        "resource": {"id": "server-01", "type": "server", "classification": "restricted"},
        "action": "admin"
    }
}

test_auditor_can_read_reports if {
    access.allow with input as {
        "user": {"active": true, "role": "auditor"},
        "resource": {"id": "audit-01", "type": "audit_report", "classification": "confidential"},
        "action": "read"
    }
}

test_auditor_cannot_write_reports if {
    not access.allow with input as {
        "user": {"active": true, "role": "auditor"},
        "resource": {"id": "audit-01", "type": "audit_report", "classification": "confidential"},
        "action": "write"
    }
}

test_vendor_approved_unexpired_matching_resource_allowed if {
    access.allow with input as {
        "user": {"active": true, "role": "external_vendor"},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {
            "approved": true,
            "resource_id": "maintenance-01",
            "expires_at_epoch": 2000000000
        },
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_expired_access_denied if {
    not access.allow with input as {
        "user": {"active": true, "role": "external_vendor"},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {
            "approved": true,
            "resource_id": "maintenance-01",
            "expires_at_epoch": 1800000000
        },
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_missing_expiry_denied if {
    not access.allow with input as {
        "user": {"active": true, "role": "external_vendor"},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {
            "approved": true,
            "resource_id": "maintenance-01"
        },
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_untrusted_missing_evaluation_time_denied if {
    not access.allow with input as {
        "user": {"active": true, "role": "external_vendor"},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {
            "approved": true,
            "resource_id": "maintenance-01",
            "expires_at_epoch": 2000000000
        }
    }
}

test_vendor_cross_resource_denied if {
    not access.allow with input as {
        "user": {"active": true, "role": "external_vendor"},
        "resource": {"id": "server-99", "type": "server", "classification": "restricted"},
        "action": "read",
        "vendor_access": {
            "approved": true,
            "resource_id": "maintenance-01",
            "expires_at_epoch": 2000000000
        },
        "context": {"evaluated_at_epoch": 1900000000}
    }
}

test_vendor_unapproved_denied if {
    not access.allow with input as {
        "user": {"active": true, "role": "external_vendor"},
        "resource": {"id": "maintenance-01", "type": "maintenance_record", "classification": "restricted"},
        "action": "read",
        "vendor_access": {
            "approved": false,
            "resource_id": "maintenance-01",
            "expires_at_epoch": 2000000000
        },
        "context": {"evaluated_at_epoch": 1900000000}
    }
}
