"""
Unit tests for RBAC Authorization, JWT, and Tamper-Evident Audit Logging.
"""

import os
import unittest
from backend.app.core.audit import AuditTrail
from backend.app.core.security import (
    ROLE_PERMISSIONS,
    UserRole,
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)


class TestRBACAndAudit(unittest.TestCase):

    def test_password_hashing(self):
        pw = "StrongSecurityPassword2026!"
        h = hash_password(pw)
        self.assertNotEqual(pw, h)
        self.assertTrue(verify_password(pw, h))
        self.assertFalse(verify_password("WrongPassword", h))

    def test_jwt_token_lifecycle(self):
        token = create_access_token({"sub": "secops_user", "role": UserRole.SECOPS_VIEWER.value})
        decoded = decode_token(token)
        self.assertEqual(decoded["sub"], "secops_user")
        self.assertEqual(decoded["role"], UserRole.SECOPS_VIEWER.value)

    def test_rbac_role_permissions_separation(self):
        viewer_perms = ROLE_PERMISSIONS[UserRole.SECOPS_VIEWER]
        responder_perms = ROLE_PERMISSIONS[UserRole.INCIDENT_RESPONDER]
        detector_perms = ROLE_PERMISSIONS[UserRole.DETECTION_ENGINEER]
        operator_perms = ROLE_PERMISSIONS[UserRole.RECOVERY_OPERATOR]
        admin_perms = ROLE_PERMISSIONS[UserRole.PLATFORM_ADMIN]

        # Viewer has read-only access, cannot write rules or cases
        self.assertIn("alerts:read", viewer_perms)
        self.assertNotIn("alerts:write", viewer_perms)
        self.assertNotIn("rules:write", viewer_perms)
        self.assertNotIn("backups:restore", viewer_perms)

        # Detection engineer can test and write rules, cannot restore backups
        self.assertIn("rules:write", detector_perms)
        self.assertIn("rules:test", detector_perms)
        self.assertNotIn("backups:restore", detector_perms)

        # Recovery operator can restore backups and rollback, cannot write detection rules
        self.assertIn("backups:restore", operator_perms)
        self.assertIn("rollback:execute", operator_perms)
        self.assertNotIn("rules:write", operator_perms)

        # Platform Admin has wildcard access
        self.assertIn("*", admin_perms)

    def test_tamper_evident_audit_trail_chain_integrity(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test_audit.jsonl")
            trail = AuditTrail(log_path=log_file)

            # Log 3 events
            e1 = trail.log("admin", "Platform Admin", "127.0.0.1", "AUTH_LOGIN", "session", "1")
            e2 = trail.log("admin", "Platform Admin", "127.0.0.1", "DEPLOY_INSTALL", "release", "v1.0.0-lab")
            e3 = trail.log("operator", "Recovery Operator", "127.0.0.1", "BACKUP_RESTORE", "backup", "bk-01")

            # Check that hash chaining is valid
            self.assertEqual(e2.prev_hash, e1.entry_hash)
            self.assertEqual(e3.prev_hash, e2.entry_hash)

            valid, broken_id = trail.verify_integrity()
            self.assertTrue(valid)
            self.assertIsNone(broken_id)

            # Simulate tampering with an entry in the log file
            with open(log_file, "r") as f:
                lines = f.readlines()
            lines[1] = lines[1].replace("DEPLOY_INSTALL", "UNAUTHORIZED_TAMPER")
            with open(log_file, "w") as f:
                f.writelines(lines)

            # Re-read and verify: must detect broken integrity
            tampered_trail = AuditTrail(log_path=log_file)
            valid_after, broken_id_after = tampered_trail.verify_integrity()
            self.assertFalse(valid_after)
            self.assertEqual(broken_id_after, 2)


if __name__ == "__main__":
    unittest.main()
