"""
DevPulse - Shared Authentication Module
Centralized JWT verification to eliminate duplication across main.py,
billing_endpoints.py, and admin_endpoints.py.
"""

import os
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from .models import User
from .database import get_db
from .auth_service_db import SECRET_KEY, ALGORITHM

security = HTTPBearer()

JWT_SECRET = os.getenv("SECRET_KEY", SECRET_KEY)
JWT_ALGORITHM = ALGORITHM


async def verify_token(credentials=Depends(security), db: Session = Depends(get_db)) -> str:
    """Verify JWT token and return user_id.

    Legacy token_<user_id> fallback is ONLY available when ENVIRONMENT=development.
    In production (the default), only valid JWT tokens are accepted.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        pass
    # Legacy token support — ONLY in development mode to prevent auth bypass in production
    if os.getenv("ENVIRONMENT", "production") == "development":
        if token and token.startswith("token_"):
            user_id = token.replace("token_", "")
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                return user_id
    raise HTTPException(status_code=401, detail="Invalid or expired token")


async def verify_admin(credentials=Depends(security), db: Session = Depends(get_db)) -> User:
    """Verify user is admin (enterprise plan required).

    Uses the same JWT verification logic as verify_token, then checks plan.
    """
    token = credentials.credentials
    user_id = None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        pass
    # Legacy token support — ONLY in development mode
    if not user_id and os.getenv("ENVIRONMENT", "production") == "development":
        if token and token.startswith("token_"):
            user_id = token.replace("token_", "")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    current_user = db.query(User).filter(User.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=401, detail="User not found")
    if current_user.plan not in ("enterprise", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user
