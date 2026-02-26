# ids_project/main.py
"""Minimal Intrusion Detection System (IDS) backend using FastAPI."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4
import time

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, REQUEST_LIMIT, SECRET_KEY, WINDOW_SECONDS
from detectors.transport_layer import (
    check_command_injection,
    check_high_request_rate,
    check_sql_injection,
    check_xss,
)
from models import LoginRequest, TokenResponse
from scoring_engine import record_threat
from state import REQUEST_LOG, TOKEN_BLACKLIST

app = FastAPI(title="Minimal IDS Backend", version="1.0.0")
security = HTTPBearer(auto_error=False)

USERS: dict[str, dict[str, str]] = {
    "alice": {"id": "user-1", "password": "password123", "role": "user"},
    "bob": {"id": "user-2", "password": "password123", "role": "user"},
    "admin": {"id": "overseer-1", "password": "adminpass", "role": "overseer"},
}


def cleanup_blacklist() -> None:
    """Remove expired blacklist entries so memory use remains bounded."""

    now_ts = time.time()
    expired_jtis = [jti for jti, exp_ts in TOKEN_BLACKLIST.items() if exp_ts <= now_ts]
    for jti in expired_jtis:
        del TOKEN_BLACKLIST[jti]


def add_to_blacklist(jti: str, exp_ts: float, reason: str) -> None:
    """Add a token ID to blacklist with its expiration timestamp."""

    cleanup_blacklist()
    TOKEN_BLACKLIST[jti] = exp_ts
    print(f"[BLACKLIST] Added jti={jti} exp={exp_ts} reason={reason}")


def create_access_token(user_id: str, role: str = "user") -> str:
    """Create a signed JWT for the given user identity and role."""

    expire_dt = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "exp": expire_dt,
        "jti": str(uuid4()),
        "role": role,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_and_validate_token(token: str) -> dict[str, Any]:
    """Decode and validate JWT signature, expiry, and blacklist status."""

    cleanup_blacklist()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    sub = payload.get("sub")
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not sub or not jti or exp is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token claims")
    if jti in TOKEN_BLACKLIST:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
    return payload


def extract_token_from_auth_header(auth_header: Optional[str]) -> Optional[str]:
    """Extract Bearer token string from Authorization header."""

    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def _decode_user_from_header(auth_header: Optional[str]) -> Optional[dict[str, Any]]:
    """Best-effort decode of token payload from request authorization header."""

    token = extract_token_from_auth_header(auth_header)
    if not token:
        return None
    try:
        return decode_and_validate_token(token)
    except HTTPException:
        return None


@app.middleware("http")
async def intrusion_detection_middleware(request: Request, call_next):
    """Apply rate and payload-based intrusion checks before routing requests."""

    cleanup_blacklist()
    client_ip = request.client.host if request.client else "unknown"
    now_ts = time.time()

    ip_queue = REQUEST_LOG[client_ip]
    ip_queue.append(now_ts)
    while ip_queue and (now_ts - ip_queue[0]) > WINDOW_SECONDS:
        ip_queue.popleft()

    payload = _decode_user_from_header(request.headers.get("Authorization"))
    user_id = payload["sub"] if payload and "sub" in payload else client_ip

    high_rate_threat = check_high_request_rate(client_ip, user_id)
    if high_rate_threat:
        record_threat(user_id, client_ip, high_rate_threat)
        if payload is not None and len(ip_queue) > REQUEST_LIMIT:
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp is not None:
                add_to_blacklist(jti, float(exp), reason=f"suspicious-ip:{client_ip}")

    if request.method in {"POST", "PUT"}:
        raw_body = await request.body()
        request._body = raw_body
        body_text = raw_body.decode("utf-8", errors="ignore")

        for detector in (check_sql_injection, check_xss, check_command_injection):
            threat_type = detector(body_text, user_id, client_ip)
            if threat_type:
                record_threat(user_id, client_ip, threat_type)

    response = await call_next(request)
    return response


def require_auth(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    """Dependency that enforces JWT authentication on protected endpoints."""

    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    return decode_and_validate_token(credentials.credentials)


@app.post("/login", response_model=TokenResponse)
def login(data: LoginRequest) -> TokenResponse:
    """Authenticate a demo user and return a JWT token."""

    user = USERS.get(data.username)
    if not user or user["password"] != data.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    token = create_access_token(user_id=user["id"], role=user.get("role", "user"))
    return TokenResponse(access_token=token, token_type="bearer")


@app.get("/protected")
def protected_route(payload: dict[str, Any] = Depends(require_auth)) -> dict[str, str]:
    """Example protected endpoint requiring a valid non-blacklisted token."""

    return {
        "message": "You accessed a protected endpoint.",
        "user_id": payload["sub"],
        "token_jti": payload["jti"],
    }


@app.post("/logout")
def logout(payload: dict[str, Any] = Depends(require_auth)) -> JSONResponse:
    """Revoke current token by adding its jti to the in-memory blacklist."""

    jti = payload["jti"]
    exp = payload["exp"]
    add_to_blacklist(jti, float(exp), reason="manual-logout")
    return JSONResponse(content={"message": "Logged out. Token revoked."})


from routers import overseer

app.include_router(overseer.router)
