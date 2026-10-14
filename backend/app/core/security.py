"""
OpenSOC Forge - Authentication & Role-Based Access Control (RBAC).
Enforces fine-grained authorization policies at the API layer.
"""

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.core.config import settings


class UserRole(str, Enum):
    SECOPS_VIEWER = "SecOps Viewer"
    INCIDENT_RESPONDER = "Incident Responder"
    DETECTION_ENGINEER = "Detection Engineer"
    RECOVERY_OPERATOR = "Recovery Operator"
    PLATFORM_ADMIN = "Platform Admin"


# Permission Matrix defining explicit capabilities per role
ROLE_PERMISSIONS: Dict[UserRole, List[str]] = {
    UserRole.SECOPS_VIEWER: [
        "alerts:read",
        "hosts:read",
        "network:read",
        "rules:read",
        "reports:read",
        "health:read",
        "inventory:read",
    ],
    UserRole.INCIDENT_RESPONDER: [
        "alerts:read",
        "alerts:write",
        "cases:read",
        "cases:write",
        "hosts:read",
        "network:read",
        "rules:read",
        "reports:read",
        "health:read",
        "inventory:read",
    ],
    UserRole.DETECTION_ENGINEER: [
        "alerts:read",
        "hosts:read",
        "network:read",
        "rules:read",
        "rules:write",
        "rules:test",
        "reports:read",
        "health:read",
        "inventory:read",
    ],
    UserRole.RECOVERY_OPERATOR: [
        "health:read",
        "inventory:read",
        "backups:read",
        "backups:create",
        "backups:restore",
        "rollback:execute",
        "diagnostics:export",
    ],
    UserRole.PLATFORM_ADMIN: [
        "*",  # All permissions
    ],
}


def hash_password(password: str) -> str:
    """Deterministic salted hash using SHA256."""
    salt = "opensoc_fixed_salt_v1"
    return hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generate tamper-resistant HMAC-SHA256 JWT token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": int(expire.timestamp())})

    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps(to_encode).encode("utf-8")).rstrip(b"=")
    signature = hmac.new(settings.SECRET_KEY.encode("utf-8"), f"{header.decode()}.{payload.decode()}".encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")

    return f"{header.decode()}.{payload.decode()}.{sig_b64.decode()}"


def decode_token(token: str) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        header, payload, sig = parts
        expected_sig = hmac.new(
            settings.SECRET_KEY.encode("utf-8"),
            f"{header}.{payload}".encode(),
            hashlib.sha256,
        ).digest()
        actual_sig = base64.urlsafe_b64decode(sig + "=="[: (4 - len(sig) % 4) % 4])

        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("Token signature verification failed")

        payload_bytes = base64.urlsafe_b64decode(payload + "=="[: (4 - len(payload) % 4) % 4])
        data = json.loads(payload_bytes.decode("utf-8"))

        if data.get("exp") and time.time() > data["exp"]:
            raise ValueError("Token has expired")
        return data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


security_scheme = HTTPBearer(auto_error=False)


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)) -> Dict[str, Any]:
    if not credentials:
        # Default fallback to anonymous user in development or raise 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_token(credentials.credentials)


def require_permission(required_permission: str):
    """Dependency that verifies the authenticated caller has the needed permission."""

    def permission_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        user_role = current_user.get("role")
        role_enum = UserRole(user_role) if user_role in [r.value for r in UserRole] else None

        if not role_enum:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unknown or invalid role")

        perms = ROLE_PERMISSIONS.get(role_enum, [])
        if "*" in perms or required_permission in perms:
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: role '{user_role}' lacks required permission '{required_permission}'",
        )

    return permission_checker
