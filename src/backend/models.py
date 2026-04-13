"""
DevPulse - SQLAlchemy Models
Database schema for persistent storage
"""

from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, ForeignKey, Text, JSON, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

Base = declarative_base()


class User(Base):
    """User account model"""
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    plan = Column(String(50), default="free", nullable=False)  # free, pro, enterprise
    stripe_customer_id = Column(String(255), unique=True, nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    subscription_status = Column(String(50), nullable=True)  # active, trialing, past_due, canceled
    onboarding_completed = Column(Boolean, default=False)
    email_verified = Column(Boolean, default=False)
    verification_token = Column(String(255), nullable=True)
    verification_token_expires = Column(DateTime, nullable=True)
    password_reset_token = Column(String(255), nullable=True)
    password_reset_expires = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    collections = relationship("Collection", back_populates="owner", cascade="all, delete-orphan")
    team_members = relationship("TeamMember", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.email}>"


class Collection(Base):
    """API Collection model"""
    __tablename__ = "collections"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    format = Column(String(50), nullable=False)  # postman, openapi, bruno
    total_requests = Column(Integer, default=0)
    data = Column(JSON, nullable=True)  # Store raw collection data
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    owner = relationship("User", back_populates="collections")
    scans = relationship("Scan", back_populates="collection", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Collection {self.name}>"


class Scan(Base):
    """Security scan result model"""
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    collection_id = Column(String(36), ForeignKey("collections.id"), nullable=False, index=True)
    scan_type = Column(String(50), default="full", nullable=False)
    status = Column(String(50), default="pending", nullable=False)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(50), nullable=False, default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    findings_data = Column(JSON, nullable=True)  # Store findings as JSON
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="scans")
    collection = relationship("Collection", back_populates="scans")
    
    def __repr__(self):
        return f"<Scan {self.id}>"


class Finding(Base):
    """Security finding model"""
    __tablename__ = "findings"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    cwe_id = Column(String(50), nullable=True)
    affected_endpoints = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<Finding {self.title}>"


class TeamMember(Base):
    """Team member model"""
    __tablename__ = "team_members"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    email = Column(String(255), nullable=False)
    role = Column(String(50), default="viewer", nullable=False)  # admin, editor, viewer
    invited_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    joined_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="team_members")
    
    def __repr__(self):
        return f"<TeamMember {self.email}>"


class TokenUsage(Base):
    """LLM token usage tracking"""
    __tablename__ = "token_usage"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    request_id = Column(String(255), nullable=False)
    model = Column(String(100), nullable=False)
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    prompt_tokens = Column(Integer, default=0)  # Alias for input_tokens
    completion_tokens = Column(Integer, default=0)  # Alias for output_tokens
    thinking_tokens = Column(Integer, default=0)
    cost = Column(Float, default=0.0)
    cost_usd = Column(Float, default=0.0)  # Alias for cost
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<TokenUsage {self.model}>"


class ComplianceReport(Base):
    """Compliance report model"""
    __tablename__ = "compliance_reports"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    collection_id = Column(String(36), ForeignKey("collections.id"), nullable=False, index=True)
    report_type = Column(String(50), nullable=False)  # pci-dss, hipaa, gdpr, sox
    compliance_percentage = Column(Float, default=0.0)
    requirements_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<ComplianceReport {self.report_type}>"


class AuditLog(Base):
    """Audit log for security and compliance"""
    __tablename__ = "audit_logs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(255), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<AuditLog {self.action}>"
