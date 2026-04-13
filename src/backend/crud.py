"""
DevPulse - CRUD Operations
Database operations for all models
"""

from sqlalchemy.orm import Session
from sqlalchemy import and_
from .models import User, Collection, Scan, Finding, TeamMember, TokenUsage, ComplianceReport, AuditLog
from typing import List, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# USER OPERATIONS
# ============================================================================

def create_user(db: Session, email: str, name: str, password_hash: str) -> User:
    """Create a new user"""
    user = User(email=email, name=name, password_hash=password_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info(f"Created user: {email}")
    return user


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Get user by email"""
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    """Get user by ID"""
    return db.query(User).filter(User.id == user_id).first()


def update_user(db: Session, user_id: str, **kwargs) -> Optional[User]:
    """Update user fields"""
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    
    for key, value in kwargs.items():
        if hasattr(user, key):
            setattr(user, key, value)
    
    db.commit()
    db.refresh(user)
    logger.info(f"Updated user: {user_id}")
    return user


# ============================================================================
# COLLECTION OPERATIONS
# ============================================================================

def create_collection(db: Session, user_id: str, name: str, format: str, total_requests: int, data: Dict[str, Any]) -> Collection:
    """Create a new collection"""
    collection = Collection(
        user_id=user_id,
        name=name,
        format=format,
        total_requests=total_requests,
        data=data
    )
    db.add(collection)
    db.commit()
    db.refresh(collection)
    logger.info(f"Created collection: {name} for user {user_id}")
    return collection


def get_collection_by_id(db: Session, collection_id: str) -> Optional[Collection]:
    """Get collection by ID"""
    return db.query(Collection).filter(Collection.id == collection_id).first()


def get_user_collections(db: Session, user_id: str) -> List[Collection]:
    """Get all collections for a user"""
    return db.query(Collection).filter(Collection.user_id == user_id).all()


def check_collection_ownership(db: Session, collection_id: str, user_id: str) -> bool:
    """Check if user owns the collection"""
    collection = get_collection_by_id(db, collection_id)
    return collection is not None and collection.user_id == user_id


def delete_collection(db: Session, collection_id: str) -> bool:
    """Delete a collection"""
    collection = get_collection_by_id(db, collection_id)
    if not collection:
        return False
    
    db.delete(collection)
    db.commit()
    logger.info(f"Deleted collection: {collection_id}")
    return True


# ============================================================================
# SCAN OPERATIONS
# ============================================================================

# create_scan (legacy removed — see new create_scan below with scan_type/status support)


def get_scan_by_id(db: Session, scan_id: str) -> Optional[Scan]:
    """Get scan by ID"""
    return db.query(Scan).filter(Scan.id == scan_id).first()


def get_collection_scans(db: Session, collection_id: str) -> List[Scan]:
    """Get all scans for a collection"""
    return db.query(Scan).filter(Scan.collection_id == collection_id).order_by(Scan.created_at.desc()).all()


def get_user_scans(db: Session, user_id: str, limit: int = 50) -> List[Scan]:
    """Get recent scans for a user"""
    return db.query(Scan).filter(Scan.user_id == user_id).order_by(Scan.created_at.desc()).limit(limit).all()


def check_scan_ownership(db: Session, scan_id: str, user_id: str) -> bool:
    """Check if user owns the scan"""
    scan = get_scan_by_id(db, scan_id)
    return scan is not None and scan.user_id == user_id


# ============================================================================
# TEAM MEMBER OPERATIONS
# ============================================================================

def add_team_member(db: Session, user_id: str, email: str, role: str = "viewer") -> TeamMember:
    """Add a team member"""
    member = TeamMember(user_id=user_id, email=email, role=role)
    db.add(member)
    db.commit()
    db.refresh(member)
    logger.info(f"Added team member: {email} to user {user_id}")
    return member


def get_user_team_members(db: Session, user_id: str) -> List[TeamMember]:
    """Get team members for a user"""
    return db.query(TeamMember).filter(TeamMember.user_id == user_id).all()


def remove_team_member(db: Session, member_id: str) -> bool:
    """Remove a team member"""
    member = db.query(TeamMember).filter(TeamMember.id == member_id).first()
    if not member:
        return False
    
    db.delete(member)
    db.commit()
    logger.info(f"Removed team member: {member_id}")
    return True


# ============================================================================
# TOKEN USAGE OPERATIONS
# ============================================================================

def record_token_usage(db: Session, user_id: str, request_id: str, model: str, prompt_tokens: int, completion_tokens: int, thinking_tokens: int, cost_usd: float) -> TokenUsage:
    """Record token usage"""
    usage = TokenUsage(
        user_id=user_id,
        request_id=request_id,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        thinking_tokens=thinking_tokens,
        cost_usd=cost_usd
    )
    db.add(usage)
    db.commit()
    db.refresh(usage)
    return usage


def get_user_token_usage(db: Session, user_id: str, limit: int = 100) -> List[TokenUsage]:
    """Get token usage for a user"""
    return db.query(TokenUsage).filter(TokenUsage.user_id == user_id).order_by(TokenUsage.created_at.desc()).limit(limit).all()


# ============================================================================
# COMPLIANCE REPORT OPERATIONS
# ============================================================================

# create_compliance_report (legacy removed — see updated version below with explicit id/created_at)


def get_collection_compliance_reports(db: Session, collection_id: str) -> List[ComplianceReport]:
    """Get compliance reports for a collection"""
    return db.query(ComplianceReport).filter(ComplianceReport.collection_id == collection_id).all()


# ============================================================================
# AUDIT LOG OPERATIONS
# ============================================================================

def log_audit_event(db: Session, action: str, resource_type: str, user_id: Optional[str] = None, resource_id: Optional[str] = None, details: Optional[Dict] = None, ip_address: Optional[str] = None) -> AuditLog:
    """Log an audit event"""
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def get_audit_logs(db: Session, user_id: Optional[str] = None, limit: int = 100) -> List[AuditLog]:
    """Get audit logs"""
    query = db.query(AuditLog)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    return query.order_by(AuditLog.created_at.desc()).limit(limit).all()


# ============================================================================
# FINDING OPERATIONS
# ============================================================================

def create_finding(
    db: Session,
    scan_id: str,
    title: str,
    description: str,
    severity: str,
    category: str = None,
    remediation: str = None,
    cwe_id: str = None
) -> Finding:
    """Create a security finding record"""
    from datetime import datetime
    import uuid
    
    finding = Finding(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        remediation=remediation,
        cwe_id=cwe_id,
        created_at=datetime.utcnow()
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


# ============================================================================
# TOKEN USAGE OPERATIONS
# ============================================================================

def create_token_usage(
    db: Session,
    user_id: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    thinking_tokens: int,
    cost: float
) -> TokenUsage:
    """Create a token usage record"""
    from datetime import datetime
    import uuid
    
    usage = TokenUsage(
        id=str(uuid.uuid4()),
        user_id=user_id,
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        thinking_tokens=thinking_tokens,
        cost_usd=cost,
        created_at=datetime.utcnow()
    )
    db.add(usage)
    db.commit()
    db.refresh(usage)
    return usage


# ============================================================================
# SCAN OPERATIONS (UPDATED)
# ============================================================================

def create_scan(
    db: Session,
    user_id: str,
    collection_id: str,
    scan_type: str = "full",
    status: str = "pending",
    risk_score: float = 0.0,
    risk_level: str = "LOW",
    findings_data: List[Dict] = None
) -> Scan:
    """Create a scan record"""
    from datetime import datetime
    import uuid
    
    scan = Scan(
        id=str(uuid.uuid4()),
        user_id=user_id,
        collection_id=collection_id,
        scan_type=scan_type,
        status=status,
        risk_score=risk_score,
        risk_level=risk_level,
        findings_data=findings_data or [],
        started_at=datetime.utcnow(),
        created_at=datetime.utcnow()
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def create_compliance_report(
    db: Session,
    user_id: str,
    collection_id: str,
    report_type: str,
    compliance_percentage: float,
    requirements_data: Dict[str, Any]
) -> ComplianceReport:
    """Create a compliance report"""
    from datetime import datetime
    import uuid
    
    report = ComplianceReport(
        id=str(uuid.uuid4()),
        user_id=user_id,
        collection_id=collection_id,
        report_type=report_type,
        compliance_percentage=compliance_percentage,
        requirements_data=requirements_data,
        created_at=datetime.utcnow()
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report
