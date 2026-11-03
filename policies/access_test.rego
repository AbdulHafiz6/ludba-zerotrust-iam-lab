
package access_test

import rego.v1
import data.access

test_admin_can_administer if {
    access.allow with input as {
        "user": {
            "active": true,
            "role": "system_admin"
        },
        "resource": {
            "id": "server-01",
            "type": "server",
            "classification": "restricted"
        },
        "action": "admin"
    }
}

test_auditor_can_read_reports if {
    access.allow with input as {
        "user": {
            "active": true,
            "role": "auditor"
        },
        "resource": {
            "id": "audit-01",
            "type": "audit_report",
            "classification": "confidential"
        },
        "action": "read"
    }
}

test_vendor_approved_access if {
    access.allow with input as {
        "user": {
            "active": true,
            "role": "external_vendor"
        },
        "resource": {
            "id": "maintenance-01",
            "type": "maintenance_record",
            "classification": "restricted"
        },
        "action": "read",
        "vendor_access": {
            "approved": true,
            "valid": true,
            "resource_id": "maintenance-01"
        }
    }
}

test_vendor_cross_resource_denied if {
    not access.allow with input as {
        "user": {
            "active": true,
            "role": "external_vendor"
        },
        "resource": {
            "id": "server-99",
            "type": "server",
            "classification": "restricted"
        },
        "action": "read",
        "vendor_access": {
            "approved": true,
            "valid": true,
            "resource_id": "maintenance-01"
        }
    }
}

test_inactive_admin_denied if {
    not access.allow with input as {
        "user": {
            "active": false,
            "role": "system_admin"
        },
        "resource": {
            "id": "server-01",
            "type": "server",
            "classification": "restricted"
        },
        "action": "admin"
    }
}
