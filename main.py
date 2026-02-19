"""
Minimal Intrusion Detection System (IDS) backend using FastAPI.

Run with:
    uvicorn main:app --reload
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Optional
from uuid import uuid4

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
app = FastAPI(title="Minimal IDS Backend")

# Optional CORS setup so browser clients can call this API during demos.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Security / JWT settings
# -----------------------------------------------------------------------------
SECRET_KEY = "change-this-in-real-projects"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# -----------------------------------------------------------------------------
# In-memory "data stores"
# -----------------------------------------------------------------------------
# Demo users (no DB). Key = username, value = plain password for simplicity.
# In real projects, passwords should be hashed.
USERS = {
    "admin": {"id": "1", "password": "admin123"},
    "analyst": {"id": "2", "password": "analyst123"},
}

# Token blacklist:
# key   -> JWT jti (unique token id)
# value -> expiration timestamp (unix seconds)
blacklist: Dict[str, float] = {}

# Request tracker per IP for a sliding 10-second window.
# key   -> IP address
# value -> deque of request timestamps (unix seconds)
request_log: Dict[str, Deque[float]] = defaultdict(deque)

# Track which IPs have already been flagged as suspicious.
suspicious_ips = set()

WINDOW_SECONDS = 10
MAX_REQUESTS_IN_WINDOW = 20


# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


# -----------------------------------------------------------------------------
# Utility helpers
# -----------------------------------------------------------------------------
def now_utc() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(timezone.utc)


def prune_blacklist() -> None:
    """Remove expired blacklist entries so in-memory storage stays clean."""
    current_ts = now_utc().timestamp()
    expired_jtis = [jti for jti, exp_ts in blacklist.items() if exp_ts <= current_ts]
    for jti in expired_jtis:
        del blacklist[jti]


def add_jti_to_blacklist(jti: str, exp_timestamp: float, reason: str) -> None:
    """Blacklist a token jti until its natural expiration."""
    prune_blacklist()
    blacklist[jti] = exp_timestamp
    print(f"[BLACKLIST] Added jti={jti} until exp={exp_timestamp} | reason={reason}")


def create_access_token(user_id: str) -> str:
    """
    Create a signed JWT containing:
      - sub: user id
      - exp: expiration time
      - jti: unique token id
    """
    expire_dt = now_utc() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "exp": expire_dt,
        "jti": str(uuid4()),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    """
    Decode and validate JWT signature + expiration.
    Raises HTTPException(401) on any validation failure.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Ensure required claims are present.
        if "sub" not in payload or "jti" not in payload or "exp" not in payload:
            print("[TOKEN] Validation failed: missing required claims")
            raise HTTPException(status_code=401, detail="Token missing required claims")

        prune_blacklist()
        if payload["jti"] in blacklist:
            print(f"[TOKEN] Validation failed: blacklisted jti={payload['jti']}")
            raise HTTPException(status_code=401, detail="Token is blacklisted")

        print(f"[TOKEN] Validation success: sub={payload['sub']} jti={payload['jti']}")
        return payload

    except jwt.ExpiredSignatureError:
        print("[TOKEN] Validation failed: token expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as exc:
        print(f"[TOKEN] Validation failed: invalid token ({exc})")
        raise HTTPException(status_code=401, detail="Invalid token")


def extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    """Extract JWT from Authorization: Bearer <token> header."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def get_client_ip(request: Request) -> str:
    """Get best-effort client IP (supports x-forwarded-for)."""
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


# -----------------------------------------------------------------------------
# IDS middleware
# -----------------------------------------------------------------------------
@app.middleware("http")
async def ids_middleware(request: Request, call_next):
    """
    Intrusion detection middleware:
      1) Track request rate per IP in 10-second sliding window.
      2) Mark IP suspicious if it makes >20 requests in that window.
      3) If suspicious request has valid authenticated token, blacklist its jti.
    """
    current_ts = now_utc().timestamp()
    client_ip = get_client_ip(request)

    # Update per-IP sliding window.
    ip_window = request_log[client_ip]
    ip_window.append(current_ts)

    # Remove timestamps older than WINDOW_SECONDS.
    while ip_window and current_ts - ip_window[0] > WINDOW_SECONDS:
        ip_window.popleft()

    # Suspicious behavior detection.
    if len(ip_window) > MAX_REQUESTS_IN_WINDOW:
        if client_ip not in suspicious_ips:
            suspicious_ips.add(client_ip)
            print(
                f"[IDS] Suspicious IP detected: ip={client_ip}, "
                f"requests_in_{WINDOW_SECONDS}s={len(ip_window)}"
            )

        # If request is authenticated, blacklist this token.
        token = extract_bearer_token(request.headers.get("authorization"))
        if token:
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                jti = payload.get("jti")
                exp = payload.get("exp")

                if jti and exp:
                    add_jti_to_blacklist(jti, float(exp), "suspicious IP activity")
            except jwt.InvalidTokenError:
                # Ignore invalid tokens here; protected endpoints will handle auth errors.
                pass

    response = await call_next(request)
    return response


# -----------------------------------------------------------------------------
# Auth dependency for protected routes
# -----------------------------------------------------------------------------
def get_current_token_payload(authorization: Optional[str] = Header(default=None)) -> dict:
    """Dependency that enforces Bearer JWT auth for protected endpoints."""
    token = extract_bearer_token(authorization)
    if not token:
        print("[TOKEN] Validation failed: missing bearer token")
        raise HTTPException(status_code=401, detail="Missing bearer token")

    return decode_token(token)


# -----------------------------------------------------------------------------
# API endpoints
# -----------------------------------------------------------------------------
@app.post("/login")
def login(data: LoginRequest):
    """Authenticate user and return a JWT access token."""
    user_record = USERS.get(data.username)

    if not user_record or user_record["password"] != data.password:
        print(f"[AUTH] Login failed for username={data.username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token(user_record["id"])
    print(f"[AUTH] Login success for username={data.username} user_id={user_record['id']}")
    return {"access_token": token, "token_type": "bearer"}


@app.get("/protected")
def protected_route(payload: dict = Depends(get_current_token_payload)):
    """Protected endpoint accessible only with a valid non-blacklisted JWT."""
    return {
        "message": "Access granted to protected data.",
        "user_id": payload["sub"],
        "token_jti": payload["jti"],
    }


@app.post("/logout")
def logout(payload: dict = Depends(get_current_token_payload)):
    """
    Logout by blacklisting the current token's jti.
    Token will remain blacklisted until its expiration time.
    """
    jti = payload["jti"]
    exp = float(payload["exp"])
    add_jti_to_blacklist(jti, exp, "manual logout")
    return {"message": "Logged out successfully. Token blacklisted."}
