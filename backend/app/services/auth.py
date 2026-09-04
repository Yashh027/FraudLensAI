"""Authentication service for FraudLens AI.

Handles password hashing (bcrypt) and JWT token creation/validation.
"""

import os
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from jose import jwt, JWTError
from passlib.context import CryptContext

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24  # 24 hours

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET must be set in environment variables")


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=JWT_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token. Returns payload or None if invalid."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


def get_user_id_from_token(token: str) -> Optional[int]:
    """Extract user_id from a JWT token."""
    payload = decode_token(token)
    if payload is None:
        return None
    user_id = payload.get("sub")
    if user_id is None:
        return None
    try:
        return int(user_id)
    except (ValueError, TypeError):
        return None