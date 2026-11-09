from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.auth import LoginRequest, TokenResponse
from app.security.authentication import authenticate_user
from app.security.login_rate_limit import (
    LoginRateLimitStoreUnavailable,
    SQLiteLoginRateLimiter,
)
from app.security.tokens import TokenConfigurationError, create_access_token


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


def get_login_rate_limiter() -> SQLiteLoginRateLimiter:
    return SQLiteLoginRateLimiter.from_environment()


@router.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    http_request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    client = http_request.client
    source_address = client.host if client is not None else "unknown"
    try:
        rate_limiter = get_login_rate_limiter()
        retry_after = rate_limiter.reserve_attempt(
            request.personnel_id,
            source_address,
        )
    except LoginRateLimitStoreUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is temporarily unavailable",
        )

    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    user = authenticate_user(db, request.personnel_id, request.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid personnel ID or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Multi-factor verification is required but unavailable",
        )

    try:
        access_token, expires_in = create_access_token(user.user_id)
    except TokenConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is not configured",
        )

    try:
        rate_limiter.clear_personnel_attempts(request.personnel_id)
    except LoginRateLimitStoreUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is temporarily unavailable",
        )

    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
    )
