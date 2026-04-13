"""
DevPulse - CSRF Protection
Prevent Cross-Site Request Forgery attacks
"""

from typing import Any, Dict, Optional, Set
from datetime import datetime, timedelta
import secrets
import hashlib
import logging

logger = logging.getLogger(__name__)


class CSRFTokenManager:
    """Manage CSRF tokens"""
    
    def __init__(self, token_lifetime_hours: int = 24):
        self.token_lifetime = timedelta(hours=token_lifetime_hours)
        self.tokens: Dict[str, Dict] = {}  # token -> {user_id, created_at, valid}
        self.user_sessions: Dict[str, Set[str]] = {}  # user_id -> set of tokens
    
    def generate_token(self, user_id: str) -> str:
        """Generate CSRF token"""
        # Generate random token
        token = secrets.token_urlsafe(32)
        
        # Hash token for storage
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Store token
        self.tokens[token_hash] = {
            "user_id": user_id,
            "created_at": datetime.utcnow(),
            "valid": True
        }
        
        # Track user session
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = set()
        self.user_sessions[user_id].add(token_hash)
        
        logger.info(f"Generated CSRF token for user {user_id}")
        return token
    
    def validate_token(self, user_id: str, token: str) -> bool:
        """Validate CSRF token"""
        # Hash provided token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Check if token exists
        if token_hash not in self.tokens:
            logger.warning(f"Invalid token provided for user {user_id}")
            return False
        
        token_data = self.tokens[token_hash]
        
        # Check if token belongs to user
        if token_data["user_id"] != user_id:
            logger.warning(f"Token mismatch for user {user_id}")
            return False
        
        # Check if token is still valid
        if not token_data["valid"]:
            logger.warning(f"Token already used for user {user_id}")
            return False
        
        # Check if token is expired
        if datetime.utcnow() - token_data["created_at"] > self.token_lifetime:
            logger.warning(f"Token expired for user {user_id}")
            return False
        
        # Mark token as used
        token_data["valid"] = False
        
        logger.info(f"Validated CSRF token for user {user_id}")
        return True
    
    def invalidate_user_tokens(self, user_id: str):
        """Invalidate all tokens for user (e.g., on logout)"""
        if user_id in self.user_sessions:
            for token_hash in self.user_sessions[user_id]:
                if token_hash in self.tokens:
                    self.tokens[token_hash]["valid"] = False
            del self.user_sessions[user_id]
            logger.info(f"Invalidated all tokens for user {user_id}")
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens"""
        now = datetime.utcnow()
        expired_tokens = []
        
        for token_hash, token_data in self.tokens.items():
            if now - token_data["created_at"] > self.token_lifetime:
                expired_tokens.append(token_hash)
        
        for token_hash in expired_tokens:
            del self.tokens[token_hash]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")
    
    def get_stats(self) -> Dict:
        """Get token statistics"""
        total_tokens = len(self.tokens)
        valid_tokens = sum(1 for t in self.tokens.values() if t["valid"])
        total_users = len(self.user_sessions)
        
        return {
            "total_tokens": total_tokens,
            "valid_tokens": valid_tokens,
            "used_tokens": total_tokens - valid_tokens,
            "total_users": total_users,
            "avg_tokens_per_user": total_tokens / total_users if total_users > 0 else 0
        }


class CSRFMiddleware:
    """CSRF protection middleware"""
    
    # Methods that require CSRF protection
    PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
    
    # Endpoints that don't require CSRF protection
    EXCLUDED_ENDPOINTS = {
        "/api/health",
        "/api/status",
        "/api/auth/login",
        "/api/auth/register",
        "/api/csrf-token",
    }
    
    def __init__(self, token_manager: CSRFTokenManager):
        self.token_manager = token_manager
    
    def should_protect(self, method: str, path: str) -> bool:
        """Check if request should be protected"""
        # Only protect certain methods
        if method not in self.PROTECTED_METHODS:
            return False
        
        # Exclude certain endpoints
        if path in self.EXCLUDED_ENDPOINTS:
            return False
        
        return True
    
    def validate_request(
        self,
        method: str,
        path: str,
        user_id: str,
        csrf_token: Optional[str]
    ) -> bool:
        """Validate request for CSRF"""
        # Check if protection needed
        if not self.should_protect(method, path):
            return True
        
        # Check if token provided
        if not csrf_token:
            logger.warning(f"No CSRF token provided for {method} {path}")
            return False
        
        # Validate token
        return self.token_manager.validate_token(user_id, csrf_token)


class CSRFProtectionHeaders:
    """CSRF protection headers"""
    
    @staticmethod
    def get_headers(csrf_token: str) -> Dict[str, str]:
        """Get headers for CSRF protection"""
        return {
            "X-CSRF-Token": csrf_token,
            "X-Requested-With": "XMLHttpRequest",
        }
    
    @staticmethod
    def get_cookie_settings() -> Dict[str, Any]:
        """Get CSRF cookie settings"""
        return {
            "key": "csrf_token",
            "httponly": True,
            "secure": True,  # HTTPS only
            "samesite": "Strict",
            "max_age": 86400,  # 24 hours
        }


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Create token manager
    manager = CSRFTokenManager()
    
    # Generate token for user
    print("Generating CSRF token...")
    token = manager.generate_token("user_123")
    print(f"  Token: {token[:20]}...")
    
    # Validate token
    print("\nValidating token...")
    valid = manager.validate_token("user_123", token)
    print(f"  Valid: {valid}")
    
    # Try to use same token again (should fail)
    print("\nTrying to reuse token...")
    valid = manager.validate_token("user_123", token)
    print(f"  Valid: {valid}")
    
    # Generate multiple tokens
    print("\nGenerating multiple tokens...")
    tokens = [manager.generate_token("user_456") for _ in range(5)]
    print(f"  Generated {len(tokens)} tokens")
    
    # Get stats
    print("\nToken statistics:")
    stats = manager.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Test middleware
    print("\nTesting CSRF middleware...")
    middleware = CSRFMiddleware(manager)
    
    # Generate new token for testing
    test_token = manager.generate_token("user_789")
    
    # Test protected request
    print("  POST /api/collections/import:")
    valid = middleware.validate_request(
        method="POST",
        path="/api/collections/import",
        user_id="user_789",
        csrf_token=test_token
    )
    print(f"    Valid: {valid}")
    
    # Test unprotected request
    print("  GET /api/health:")
    valid = middleware.validate_request(
        method="GET",
        path="/api/health",
        user_id="user_789",
        csrf_token=None
    )
    print(f"    Valid: {valid}")
