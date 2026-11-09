import base64
import binascii
import os
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.models import User


JWT_ALGORITHM = "HS256"
JWT_SECRET_ENV_VAR = "JWT_SECRET_KEY"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 15
MAX_ACCESS_TOKEN_EXPIRE_MINUTES = 60
MAX_ACCESS_TOKEN_LIFETIME_SECONDS = MAX_ACCESS_TOKEN_EXPIRE_MINUTES * 60
# Allow modest clock drift, while still limiting the usable token lifetime from now.
JWT_IAT_CLOCK_SKEW_SECONDS = 30
_bearer_scheme = HTTPBearer(auto_error=False)


class TokenConfigurationError(RuntimeError):
    """Raised when token signing cannot be performed securely."""


def _get_secret_key() -> bytes:
    secret_key = os.getenv(JWT_SECRET_ENV_VAR)
    if not secret_key:
        raise TokenConfigurationError(
            f"{JWT_SECRET_ENV_VAR} must be configured"
        )

    if not secret_key or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in secret_key
    ):
        raise TokenConfigurationError(
            f"{JWT_SECRET_ENV_VAR} must be unpadded base64url key material"
        )

    try:
        padding = "=" * (-len(secret_key) % 4)
        secret_bytes = base64.urlsafe_b64decode(secret_key + padding)
    except (binascii.Error, ValueError) as error:
        raise TokenConfigurationError(
            f"{JWT_SECRET_ENV_VAR} must be valid base64url key material"
        ) from error

    canonical = base64.urlsafe_b64encode(secret_bytes).decode("ascii").rstrip("=")
    if len(secret_bytes) < 32 or canonical != secret_key:
        raise TokenConfigurationError(
            f"{JWT_SECRET_ENV_VAR} must encode at least 32 bytes of key material"
        )

    return secret_bytes


def _get_expiration_minutes() -> int:
    raw_value = os.getenv(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        str(DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    try:
        expiration_minutes = int(raw_value)
    except (TypeError, ValueError) as error:
        raise TokenConfigurationError(
            "ACCESS_TOKEN_EXPIRE_MINUTES must be a positive integer"
        ) from error

    if not 1 <= expiration_minutes <= MAX_ACCESS_TOKEN_EXPIRE_MINUTES:
        raise TokenConfigurationError(
            "ACCESS_TOKEN_EXPIRE_MINUTES must be between 1 and 60"
        )

    return expiration_minutes


def create_access_token(
    user_id: int,
    *,
    authentication_method: Literal["password", "mfa"] = "password",
) -> tuple[str, int]:
    """Create a signed token for an authentication method verified by the server."""
    if authentication_method not in ("password", "mfa"):
        raise ValueError("Unsupported authentication method")

    secret_key = _get_secret_key()
    expiration_minutes = _get_expiration_minutes()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=expiration_minutes),
        "type": "access",
        "amr": ["pwd", "mfa"] if authentication_method == "mfa" else ["pwd"],
    }
    token = jwt.encode(payload, secret_key, algorithm=JWT_ALGORITHM)
    return token, expiration_minutes * 60


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validate a bearer token and return its active database user."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()

    try:
        secret_key = _get_secret_key()
        claims = jwt.decode(
            credentials.credentials,
            secret_key,
            algorithms=[JWT_ALGORITHM],
            options={"require_sub": True, "require_exp": True},
        )
    except TokenConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is not configured",
        )
    except (JWTError, TypeError, ValueError, OverflowError):
        raise _unauthorized()

    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    now_timestamp = datetime.now(timezone.utc).timestamp()
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, (int, float))
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_ACCESS_TOKEN_LIFETIME_SECONDS
        or issued_at > now_timestamp + JWT_IAT_CLOCK_SKEW_SECONDS
        or expires_at - now_timestamp > MAX_ACCESS_TOKEN_LIFETIME_SECONDS
    ):
        raise _unauthorized()

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.isdecimal():
        raise _unauthorized()

    try:
        user_id = int(subject)
    except ValueError:
        raise _unauthorized()
    if user_id <= 0 or str(user_id) != subject:
        raise _unauthorized()

    if claims.get("type") != "access":
        raise _unauthorized()

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None or user.account_status != "ACTIVE":
        raise _unauthorized()

    if user.mfa_enabled:
        authentication_methods = claims.get("amr")
        if (
            not isinstance(authentication_methods, list)
            or "mfa" not in authentication_methods
        ):
            raise _unauthorized()

    return user
