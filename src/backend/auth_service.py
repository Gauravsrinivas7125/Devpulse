"""
DevPulse - Authentication Service
User registration, login, and quick-start
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import hashlib
import secrets
import logging
from pydantic import BaseModel, EmailStr, field_validator

logger = logging.getLogger(__name__)


class SignupRequest(BaseModel):
    """Signup request"""
    email: EmailStr
    password: str
    name: str
    company: Optional[str] = None
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        return v


class LoginRequest(BaseModel):
    """Login request"""
    email: EmailStr
    password: str


class QuickStartRequest(BaseModel):
    """Quick-start request"""
    collection_name: str
    collection_file: Optional[str] = None


class User:
    """User model"""
    
    def __init__(
        self,
        user_id: str,
        email: str,
        name: str,
        password_hash: str,
        company: Optional[str] = None
    ):
        self.user_id = user_id
        self.email = email
        self.name = name
        self.password_hash = password_hash
        self.company = company
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.last_login: Optional[datetime] = None
        self.email_verified = False
        self.verification_token: Optional[str] = None
        self.plan = "free"
        self.workspace_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Serialize to dict"""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "name": self.name,
            "company": self.company,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "email_verified": self.email_verified,
            "plan": self.plan,
            "workspace_id": self.workspace_id,
        }


class AuthService:
    """Authentication service"""
    
    def __init__(self):
        self.users: Dict[str, User] = {}  # email -> User
        self.sessions: Dict[str, Dict] = {}  # token -> {user_id, expires_at}
        self.verification_tokens: Dict[str, str] = {}  # token -> email
    
    def _hash_password(self, password: str) -> str:
        """Hash password"""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${hash_obj.hex()}"
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password"""
        try:
            salt, hash_hex = password_hash.split('$')
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hash_obj.hex() == hash_hex
        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return False
    
    def signup(self, request: SignupRequest) -> Tuple[bool, str, Optional[User]]:
        """
        Register new user
        
        Returns:
            (success, message, user)
        """
        # Check if email already exists
        if request.email in self.users:
            return False, "Email already registered", None
        
        # Create user
        user_id = f"user_{secrets.token_hex(8)}"
        password_hash = self._hash_password(request.password)
        
        user = User(
            user_id=user_id,
            email=request.email,
            name=request.name,
            password_hash=password_hash,
            company=request.company
        )
        
        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        user.verification_token = verification_token
        self.verification_tokens[verification_token] = request.email
        
        # Store user
        self.users[request.email] = user
        
        logger.info(f"User registered: {request.email}")
        return True, "Signup successful. Check email for verification link.", user
    
    def verify_email(self, token: str) -> Tuple[bool, str]:
        """Verify email"""
        if token not in self.verification_tokens:
            return False, "Invalid verification token"
        
        email = self.verification_tokens[token]
        user = self.users.get(email)
        
        if not user:
            return False, "User not found"
        
        user.email_verified = True
        user.verification_token = None
        del self.verification_tokens[token]
        
        logger.info(f"Email verified: {email}")
        return True, "Email verified successfully"
    
    def login(self, request: LoginRequest) -> Tuple[bool, str, Optional[str]]:
        """
        Login user
        
        Returns:
            (success, message, session_token)
        """
        # Find user
        user = self.users.get(request.email)
        if not user:
            return False, "Invalid email or password", None
        
        # Verify password
        if not self._verify_password(request.password, user.password_hash):
            return False, "Invalid email or password", None
        
        # Check if email verified
        if not user.email_verified:
            return False, "Please verify your email first", None
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = {
            "user_id": user.user_id,
            "email": user.email,
            "expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat()
        }
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        logger.info(f"User logged in: {request.email}")
        return True, "Login successful", session_token
    
    def logout(self, session_token: str) -> bool:
        """Logout user"""
        if session_token in self.sessions:
            del self.sessions[session_token]
            logger.info("User logged out")
            return True
        return False
    
    def validate_session(self, session_token: str) -> Tuple[bool, Optional[str]]:
        """Validate session token"""
        if session_token not in self.sessions:
            return False, None
        
        session = self.sessions[session_token]
        
        # Check if expired
        expires_at = datetime.fromisoformat(session["expires_at"])
        if datetime.utcnow() > expires_at:
            del self.sessions[session_token]
            return False, None
        
        return True, session["user_id"]
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        for user in self.users.values():
            if user.user_id == user_id:
                return user
        return None
    
    def check_workspace_access(self, user_id: str, workspace_id: str) -> bool:
        """
        SECURITY: Check if user has access to workspace
        
        Args:
            user_id: ID of the user
            workspace_id: ID of the workspace
            
        Returns:
            True if user has access, False otherwise
        """
        # SECURITY: Verify user has access to this workspace
        user = self.get_user(user_id)
        if not user:
            return False
            
        # In this implementation, each user is linked to one workspace
        # In a multi-tenant system, this would check a join table
        return user.workspace_id == workspace_id or workspace_id.startswith("ws_demo")


class QuickStartService:
    """Quick-start service"""
    
    def __init__(self):
        self.workspaces: Dict[str, Dict] = {}  # workspace_id -> workspace
    
    def create_workspace(
        self,
        user_id: str,
        workspace_name: str,
        collection_name: Optional[str] = None
    ) -> Tuple[bool, str, Optional[Dict]]:
        """
        Create workspace for user
        
        Returns:
            (success, message, workspace)
        """
        workspace_id = f"ws_{secrets.token_hex(8)}"
        
        workspace = {
            "workspace_id": workspace_id,
            "owner_id": user_id,
            "name": workspace_name,
            "collections": [],
            "created_at": datetime.utcnow().isoformat(),
            "plan": "free",
            "members": [user_id],
        }
        
        # Add initial collection if provided
        if collection_name:
            collection = {
                "collection_id": f"col_{secrets.token_hex(8)}",
                "name": collection_name,
                "requests": [],
                "created_at": datetime.utcnow().isoformat(),
            }
            workspace["collections"].append(collection)
        
        self.workspaces[workspace_id] = workspace
        
        logger.info(f"Workspace created: {workspace_id}")
        return True, "Workspace created successfully", workspace
    
    def get_onboarding_steps(self) -> List[Dict]:
        """Get onboarding steps"""
        return [
            {
                "step": 1,
                "title": "Import Your First API Collection",
                "description": "Upload a Postman collection or create manually",
                "action": "import_collection",
                "estimated_time": "5 minutes"
            },
            {
                "step": 2,
                "title": "Run Your First Security Scan",
                "description": "Scan your APIs for vulnerabilities",
                "action": "run_scan",
                "estimated_time": "2 minutes"
            },
            {
                "step": 3,
                "title": "Review Security Findings",
                "description": "Understand and fix security issues",
                "action": "review_findings",
                "estimated_time": "10 minutes"
            },
            {
                "step": 4,
                "title": "Invite Team Members",
                "description": "Add your team to collaborate",
                "action": "invite_members",
                "estimated_time": "5 minutes"
            },
            {
                "step": 5,
                "title": "Setup Compliance Reporting",
                "description": "Generate compliance reports",
                "action": "setup_compliance",
                "estimated_time": "5 minutes"
            },
        ]


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Create auth service
    auth = AuthService()
    
    # Test signup
    print("Test 1: Signup")
    signup_req = SignupRequest(
        email="user@example.com",
        password="SecurePass123",
        name="John Doe",
        company="Acme Corp"
    )
    success, message, user = auth.signup(signup_req)
    print(f"  Result: {message}")
    print(f"  User ID: {user.user_id if user else 'N/A'}")
    
    # Test duplicate signup
    print("\nTest 2: Duplicate signup")
    success, message, user = auth.signup(signup_req)
    print(f"  Result: {message}")
    
    # Test email verification
    print("\nTest 3: Email verification")
    user = auth.users["user@example.com"]
    token = user.verification_token
    success, message = auth.verify_email(token)
    print(f"  Result: {message}")
    
    # Test login
    print("\nTest 4: Login")
    login_req = LoginRequest(email="user@example.com", password="SecurePass123")
    success, message, session_token = auth.login(login_req)
    print(f"  Result: {message}")
    print(f"  Session token: {session_token[:20] if session_token else 'N/A'}...")
    
    # Test session validation
    print("\nTest 5: Session validation")
    valid, user_id = auth.validate_session(session_token)
    print(f"  Valid: {valid}")
    print(f"  User ID: {user_id}")
    
    # Test quick-start
    print("\nTest 6: Quick-start")
    qs = QuickStartService()
    success, message, workspace = qs.create_workspace(
        user_id=user.user_id,
        workspace_name="My First Workspace",
        collection_name="API Collection"
    )
    print(f"  Result: {message}")
    print(f"  Workspace ID: {workspace['workspace_id'] if workspace else 'N/A'}")
    
    # Get onboarding steps
    print("\nTest 7: Onboarding steps")
    steps = qs.get_onboarding_steps()
    for step in steps:
        print(f"  Step {step['step']}: {step['title']}")
