"""
DevPulse - Type Definitions
Complete type safety for all API responses
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict
from enum import Enum
from datetime import datetime, timezone


# ============================================================================
# ENUMS
# ============================================================================

class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """Vulnerability types"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    XXE = "xxe"
    BROKEN_AUTHENTICATION = "broken_authentication"


class PlanType(str, Enum):
    """Subscription plan types"""
    FREE = "free"
    PRO = "pro"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class ScanStatus(str, Enum):
    """Scan status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class BaseResponse(BaseModel):
    """Base response model"""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})

    success: bool
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ErrorResponse(BaseResponse):
    """Error response"""
    success: bool = False
    error_code: str
    details: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    """Security finding"""
    id: str
    title: str
    description: str
    severity: SeverityLevel
    vulnerability_type: VulnerabilityType
    affected_endpoint: str
    affected_parameter: Optional[str] = None
    evidence: Optional[str] = None
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Collection(BaseModel):
    """API Collection"""
    id: str
    name: str
    description: Optional[str] = None
    total_requests: int
    total_endpoints: int
    with_auth: int
    with_body: int
    created_at: datetime
    updated_at: datetime
    owner_id: str


class Request(BaseModel):
    """API Request"""
    id: str
    collection_id: str
    name: str
    method: str  # GET, POST, PUT, DELETE, PATCH
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    auth_type: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    
    @field_validator('method')
    @classmethod
    def validate_method(cls, v: str) -> str:
        allowed = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        if v.upper() not in allowed:
            raise ValueError(f'Method must be one of {allowed}')
        return v.upper()


class RiskScore(BaseModel):
    """Unified risk score"""
    score: float = Field(ge=0, le=100)
    level: str  # LOW, MEDIUM, HIGH, CRITICAL
    total_findings: int
    by_severity: Dict[SeverityLevel, int]
    trend: str  # increasing, decreasing, stable
    trend_change: float
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanResult(BaseModel):
    """Scan result"""
    scan_id: str
    collection_id: str
    status: ScanStatus
    findings: List[Finding]
    risk_score: RiskScore
    scan_duration_seconds: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    errors: List[str] = Field(default_factory=list)


class UsageData(BaseModel):
    """Usage data"""
    metric: str
    current: int
    limit: int
    remaining: int
    percentage_used: float
    reset_date: Optional[datetime] = None


class UserPlan(BaseModel):
    """User subscription plan"""
    plan_type: PlanType
    billing_cycle: str  # monthly, yearly
    price: float
    renewal_date: datetime
    auto_renew: bool
    features: List[str]


class User(BaseModel):
    """User"""
    id: str
    email: str
    name: str
    plan: UserPlan
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None


class Team(BaseModel):
    """Team/Organization"""
    id: str
    name: str
    owner_id: str
    members: List[str]
    plan: UserPlan
    created_at: datetime
    updated_at: datetime


# ============================================================================
# API REQUEST MODELS
# ============================================================================

class ImportCollectionRequest(BaseModel):
    """Import collection request"""
    name: str
    collection_data: Dict[str, Any]


class ScanRequest(BaseModel):
    """Scan request"""
    collection_id: str
    scan_type: str = "full"  # full, quick, custom
    include_shadow_apis: bool = True
    include_compliance: bool = True


class CreateTeamRequest(BaseModel):
    """Create team request"""
    name: str
    description: Optional[str] = None


class AddTeamMemberRequest(BaseModel):
    """Add team member request"""
    team_id: str
    user_email: str
    role: str = "member"  # member, admin


# ============================================================================
# API RESPONSE MODELS
# ============================================================================

class ImportCollectionResponse(BaseResponse):
    """Import collection response"""
    success: bool = True
    collection_id: str
    total_requests: int
    total_endpoints: int
    statistics: Dict[str, Any]


class ScanResponse(BaseResponse):
    """Scan response"""
    success: bool = True
    scan_result: ScanResult


class GetCollectionsResponse(BaseResponse):
    """Get collections response"""
    success: bool = True
    collections: List[Collection]
    total: int
    page: int
    page_size: int


class GetFindingsResponse(BaseResponse):
    """Get findings response"""
    success: bool = True
    findings: List[Finding]
    total: int
    by_severity: Dict[SeverityLevel, int]


class GetRiskScoreResponse(BaseResponse):
    """Get risk score response"""
    success: bool = True
    risk_score: RiskScore


class GetUsageResponse(BaseResponse):
    """Get usage response"""
    success: bool = True
    usage: Dict[str, UsageData]
    plan: UserPlan
    warnings: List[str]


class HealthCheckResponse(BaseResponse):
    """Health check response"""
    success: bool = True
    version: str
    status: str  # healthy, degraded, unhealthy
    uptime_seconds: float
    database: str  # connected, disconnected
    cache: str  # connected, disconnected


# ============================================================================
# VALIDATION HELPERS
# ============================================================================

def validate_email(email: str) -> bool:
    """Validate email format"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_url(url: str) -> bool:
    """Validate URL format"""
    import re
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return re.match(pattern, url) is not None


def validate_risk_score(score: float) -> bool:
    """Validate risk score"""
    return 0 <= score <= 100


# ============================================================================
# TYPE ALIASES
# ============================================================================

JSONData = Dict[str, Any]
ResponseData = Union[BaseResponse, ErrorResponse]
