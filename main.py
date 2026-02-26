"""
Minimal Intrusion Detection System (IDS) backend using FastAPI.

Run with:
    uvicorn main:app --reload
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Optional
from uuid import uuid4
import time

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# ============================
# App setup
# ============================
app = FastAPI(title="Minimal IDS Backend", version="1.0.0")
security = HTTPBearer(auto_error=False)

# ============================
# Security/JWT settings
# ============================
SECRET_KEY = "change-this-in-real-projects"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ============================
# Demo in-memory user store
# In real systems, this would be in a database with hashed passwords.
# ============================
USERS = {
    "alice": {"id": "user-1", "password": "password123", "role": "user"},
    "bob": {"id": "user-2", "password": "password123", "role": "user"},
    "admin": {"id": "overseer-1", "password": "adminpass", "role": "overseer"},
}

# ============================
# In-memory IDS data structures
# ============================
# Tracks request timestamps for each IP. We keep only the last 10 seconds.
REQUEST_LOG: Dict[str, Deque[float]] = defaultdict(deque)
WINDOW_SECONDS = 10
REQUEST_LIMIT = 20

# Blacklist for revoked tokens.
# key: jti (token unique id)
# value: expiration timestamp (epoch seconds)
TOKEN_BLACKLIST: Dict[str, float] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


# ============================
# Helper functions
# ============================
def cleanup_blacklist() -> None:
    """
    Remove expired blacklist entries so memory doesn't grow forever.
    Called often because this app uses only in-memory storage.
    """
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
    """
    Create a JWT containing:
    - sub: subject/user id
    - exp: expiration datetime
    - jti: unique token id (UUID)
    """
    expire_dt = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "exp": expire_dt,
        "jti": str(uuid4()),
        "role": role,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)



def decode_and_validate_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate JWT signature + expiry + blacklist status.

    Raises HTTPException(401) if invalid.
    """
    cleanup_blacklist()

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        print("[TOKEN] Validation failed: token expired")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        print("[TOKEN] Validation failed: invalid signature/token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    sub = payload.get("sub")
    jti = payload.get("jti")
    exp = payload.get("exp")

    if not sub or not jti or exp is None:
        print("[TOKEN] Validation failed: missing required claims")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token claims")

    if jti in TOKEN_BLACKLIST:
        print(f"[TOKEN] Validation failed: blacklisted token jti={jti}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    print(f"[TOKEN] Validation success: sub={sub}, jti={jti}")
    return payload



def extract_token_from_auth_header(auth_header: Optional[str]) -> Optional[str]:
    """Extract Bearer token string from Authorization header."""
    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


# ============================
# IDS middleware
# ============================
@app.middleware("http")
async def intrusion_detection_middleware(request: Request, call_next):
    """
    Simple intrusion detection middleware.

    Steps:
    1. Identify client IP
    2. Count requests in a sliding 10-second window
    3. If >20 requests, mark IP suspicious
    4. If request is authenticated, blacklist that token jti
    """
    cleanup_blacklist()

    client_ip = request.client.host if request.client else "unknown"
    now_ts = time.time()

    # Keep only timestamps inside the last WINDOW_SECONDS.
    ip_queue = REQUEST_LOG[client_ip]
    ip_queue.append(now_ts)
    while ip_queue and (now_ts - ip_queue[0]) > WINDOW_SECONDS:
        ip_queue.popleft()

    if len(ip_queue) > REQUEST_LIMIT:
        print(f"[IDS] Suspicious IP detected: {client_ip} ({len(ip_queue)} req/{WINDOW_SECONDS}s)")

        # If authenticated, revoke this specific token.
        auth_header = request.headers.get("Authorization")
        token = extract_token_from_auth_header(auth_header)
        if token:
            try:
                # Decode only to read jti/exp. Signature+exp are still verified here.
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                jti = payload.get("jti")
                exp = payload.get("exp")
                if jti and exp is not None:
                    add_to_blacklist(jti, float(exp), reason=f"suspicious-ip:{client_ip}")
            except jwt.InvalidTokenError:
                # Ignore malformed tokens in middleware; endpoint auth will handle response.
                print("[IDS] Could not parse token during suspicious-IP handling")

    response = await call_next(request)
    return response


# ============================
# Authentication dependency
# ============================
def require_auth(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Dependency that enforces JWT authentication on protected endpoints."""
    if credentials is None:
        print("[TOKEN] Validation failed: missing Authorization header")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    return decode_and_validate_token(credentials.credentials)


# ============================
# API endpoints
# ============================
@app.post("/login")
def login(data: LoginRequest):
    """Authenticate a demo user and return a JWT token."""
    user = USERS.get(data.username)
    if not user or user["password"] != data.password:
        print(f"[AUTH] Failed login for username={data.username}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    token = create_access_token(user_id=user["id"], role=user.get("role", "user"))
    print(f"[AUTH] Successful login for username={data.username}")
    return {"access_token": token, "token_type": "bearer"}


@app.get("/protected")
def protected_route(payload: Dict[str, Any] = Depends(require_auth)):
    """Example protected endpoint. Requires a valid non-blacklisted token."""
    return {
        "message": "You accessed a protected endpoint.",
        "user_id": payload["sub"],
        "token_jti": payload["jti"],
    }


@app.post("/logout")
def logout(payload: Dict[str, Any] = Depends(require_auth)):
    """Revoke current token by adding its jti to the in-memory blacklist."""
    jti = payload["jti"]
    exp = payload["exp"]
    add_to_blacklist(jti, float(exp), reason="manual-logout")
    return JSONResponse(content={"message": "Logged out. Token revoked."})


from routers import overseer

app.include_router(overseer.router)
