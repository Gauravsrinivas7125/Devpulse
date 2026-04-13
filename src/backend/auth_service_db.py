"""
DevPulse - Authentication Service with Database Persistence
Rewritten to use SQLAlchemy CRUD instead of in-memory storage
"""

import os
import logging
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .models import User
from . import crud

logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


class AuthServiceDB:
    """Authentication service using database persistence"""
    
    def __init__(self, db: Session):
        self.db = db
        self.secret_key = SECRET_KEY
        self.algorithm = ALGORITHM

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)

    def register(
        self,
        email: str,
        name: str,
        password: str,
        plan: str = "free"
    ) -> Tuple[bool, str, Optional[Dict]]:
        """
        Register a new user
        Returns: (success, message, user_data)
        """
        try:
            # Check if user already exists
            existing_user = self.db.query(User).filter(User.email == email).first()
            if existing_user:
                return False, "User already exists", None
            
            # Validate password strength
            if len(password) < 8:
                return False, "Password must be at least 8 characters", None
            
            # Hash password
            password_hash = self.hash_password(password)
            
            # Generate email verification token
            verification_token = secrets.token_urlsafe(32)
            
            # Create user
            user = User(
                email=email,
                name=name,
                password_hash=password_hash,
                plan=plan,
                email_verified=False,
                verification_token=verification_token,
                verification_token_expires=datetime.utcnow() + timedelta(hours=24),
                created_at=datetime.utcnow()
            )
            
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            
            logger.info(f"User registered: {email}")
            
            return True, "Registration successful", {
                "user_id": user.id,
                "email": user.email,
                "name": user.name,
                "plan": user.plan,
                "verification_token": verification_token
            }
        
        except Exception as e:
            self.db.rollback()
            logger.error(f"Registration error: {str(e)}")
            return False, f"Registration failed: {str(e)}", None

    def login(self, email: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Authenticate user and return JWT tokens
        Returns: (success, message, token_data)
        """
        try:
            # Find user by email
            user = self.db.query(User).filter(User.email == email).first()
            if not user:
                logger.warning(f"Login attempt for non-existent user: {email}")
                return False, "Invalid email or password", None
            
            # Verify password
            if not self.verify_password(password, user.password_hash):
                logger.warning(f"Failed login attempt for user: {email}")
                return False, "Invalid email or password", None
            
            # Check if email is verified
            if not user.email_verified:
                logger.warning(f"Login attempt with unverified email: {email}")
                return False, "Please verify your email first", None
            
            # Generate tokens
            access_token = self._create_access_token(user.id, user.email)
            refresh_token = self._create_refresh_token(user.id)
            
            # Update last login
            user.last_login = datetime.utcnow()
            self.db.commit()
            
            logger.info(f"User logged in: {email}")
            
            return True, "Login successful", {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "user_id": user.id,
                "email": user.email,
                "name": user.name,
                "plan": user.plan
            }
        
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return False, f"Login failed: {str(e)}", None

    def verify_email(self, token: str) -> Tuple[bool, str]:
        """
        Verify email with token
        Returns: (success, message)
        """
        try:
            user = self.db.query(User).filter(
                User.verification_token == token
            ).first()
            
            if not user:
                return False, "Invalid verification token"
            
            if user.verification_token_expires < datetime.utcnow():
                return False, "Verification token has expired"
            
            user.email_verified = True
            user.verification_token = None
            user.verification_token_expires = None
            self.db.commit()
            
            logger.info(f"Email verified for user: {user.email}")
            return True, "Email verified successfully"
        
        except Exception as e:
            self.db.rollback()
            logger.error(f"Email verification error: {str(e)}")
            return False, f"Verification failed: {str(e)}"

    def request_password_reset(self, email: str) -> Tuple[bool, str, Optional[str]]:
        """
        Request password reset
        Returns: (success, message, reset_token)
        """
        try:
            user = self.db.query(User).filter(User.email == email).first()
            if not user:
                # Don't reveal if user exists
                return True, "If email exists, reset link has been sent", None
            
            reset_token = secrets.token_urlsafe(32)
            user.password_reset_token = reset_token
            user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
            self.db.commit()
            
            logger.info(f"Password reset requested for user: {email}")
            return True, "Password reset link sent to email", reset_token
        
        except Exception as e:
            self.db.rollback()
            logger.error(f"Password reset request error: {str(e)}")
            return False, f"Request failed: {str(e)}", None

    def reset_password(self, token: str, new_password: str) -> Tuple[bool, str]:
        """
        Reset password with token
        Returns: (success, message)
        """
        try:
            user = self.db.query(User).filter(
                User.password_reset_token == token
            ).first()
            
            if not user:
                return False, "Invalid reset token"
            
            if user.password_reset_expires < datetime.utcnow():
                return False, "Reset token has expired"
            
            if len(new_password) < 8:
                return False, "Password must be at least 8 characters"
            
            user.password_hash = self.hash_password(new_password)
            user.password_reset_token = None
            user.password_reset_expires = None
            self.db.commit()
            
            logger.info(f"Password reset for user: {user.email}")
            return True, "Password reset successfully"
        
        except Exception as e:
            self.db.rollback()
            logger.error(f"Password reset error: {str(e)}")
            return False, f"Reset failed: {str(e)}"

    def refresh_access_token(self, refresh_token: str) -> Tuple[bool, str, Optional[str]]:
        """
        Refresh access token using refresh token
        Returns: (success, message, new_access_token)
        """
        try:
            payload = jwt.decode(refresh_token, self.secret_key, algorithms=[self.algorithm])
            user_id = payload.get("sub")
            token_type = payload.get("type")
            
            if token_type != "refresh":
                return False, "Invalid token type", None
            
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                return False, "User not found", None
            
            new_access_token = self._create_access_token(user.id, user.email)
            return True, "Token refreshed", new_access_token
        
        except jwt.ExpiredSignatureError:
            return False, "Refresh token expired", None
        except jwt.InvalidTokenError:
            return False, "Invalid refresh token", None
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return False, f"Refresh failed: {str(e)}", None

    def verify_token(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """
        Verify JWT token and return payload
        Returns: (valid, payload)
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return True, payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return False, None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return False, None

    def _create_access_token(self, user_id: str, email: str) -> str:
        """Create JWT access token"""
        payload = {
            "sub": user_id,
            "email": email,
            "type": "access",
            "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def _create_refresh_token(self, user_id: str) -> str:
        """Create JWT refresh token"""
        payload = {
            "sub": user_id,
            "type": "refresh",
            "exp": datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def get_user(self, user_id: str) -> Optional[Dict]:
        """Get user by ID"""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                return None
            
            return {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "plan": user.plan,
                "email_verified": user.email_verified,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_login": user.last_login.isoformat() if user.last_login else None
            }
        except Exception as e:
            logger.error(f"Error getting user: {str(e)}")
            return None

    def update_user(self, user_id: str, **kwargs) -> Tuple[bool, str]:
        """Update user fields"""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                return False, "User not found"
            
            # Only allow specific fields to be updated
            allowed_fields = ["name", "plan"]
            for key, value in kwargs.items():
                if key in allowed_fields:
                    setattr(user, key, value)
            
            self.db.commit()
            logger.info(f"User updated: {user_id}")
            return True, "User updated successfully"
        
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error updating user: {str(e)}")
            return False, f"Update failed: {str(e)}"

    def delete_user(self, user_id: str) -> Tuple[bool, str]:
        """Delete user account"""
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                return False, "User not found"
            
            self.db.delete(user)
            self.db.commit()
            logger.info(f"User deleted: {user_id}")
            return True, "User deleted successfully"
        
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error deleting user: {str(e)}")
            return False, f"Deletion failed: {str(e)}"
