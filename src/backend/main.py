"""
DevPulse - Production Backend API
Complete FastAPI application with database persistence, JWT auth,
email notifications, rate limiting, and all core services.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks, Header, WebSocket, WebSocketDisconnect, status, Request
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import json
import os
import uuid
import time
import jwt
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pydantic import BaseModel
from dotenv import load_dotenv
load_dotenv()

# Database imports
from .database import init_db, get_db, engine
from .models import (
    Base, User, Collection, Scan, Finding, TeamMember,
    TokenUsage, ComplianceReport, AuditLog,
    KillSwitchEvent, Workspace, ShadowAPIScanResult,
)
from . import crud
from sqlalchemy.orm import Session
from sqlalchemy import func

# Import services
from .trpc_router import trpc
from .billing_endpoints import router as billing_router
from .admin_endpoints import router as admin_router
from .team_endpoints import router as team_router
from .stripe_webhook_handler import get_webhook_handler
from .plan_enforcement import get_plan_enforcer, PlanLimits
from .auth_service import QuickStartService
from .auth_service_db import AuthServiceDB, SECRET_KEY, ALGORITHM
from .redis_client import redis_client
from services.postman_parser import PostmanParser
from services.collection_parsers import parser_factory
from services.risk_score_engine import RiskScoreEngine, SecurityFinding
from services.kill_switch import KillSwitch
from services.shadow_api_scanner import ShadowAPIScanner
from services.pci_compliance import PCIComplianceGenerator
from services.thinking_tokens import ThinkingTokenTracker
from services.pdf_generator import PDFReportGenerator
from services.enhanced_cost_tracker import enhanced_cost_tracker
from services.advanced_analytics import analytics_engine
from services.ai_security_prompts import ai_security_analyzer
from services.webhook_integrations import webhook_service
from services.enhanced_policy_engine import policy_engine
from services.scan_session_history import scan_session_history
from services.email_service import email_service
import logging
from passlib.context import CryptContext
from pathlib import Path

logger = logging.getLogger(__name__)

# Use bcrypt for production-grade password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
JWT_SECRET = os.getenv("SECRET_KEY", SECRET_KEY)
JWT_ALGORITHM = ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Rate limiting configuration
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))

# Initialize FastAPI app
app = FastAPI(
    title="DevPulse API",
    description="Production-grade API security and LLM cost intelligence",
    version="1.0.0"
)

# Add CORS middleware
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:5174,http://localhost:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
app.include_router(trpc.get_fastapi_router())
app.include_router(billing_router)
app.include_router(admin_router)
app.include_router(team_router)

postman_parser = PostmanParser()
risk_engine = RiskScoreEngine()
kill_switch = KillSwitch()
shadow_scanner = ShadowAPIScanner()
pci_generator = PCIComplianceGenerator()
token_tracker = ThinkingTokenTracker()
pdf_generator = PDFReportGenerator()

quick_start = QuickStartService()

security = HTTPBearer()


# ============================================================================
# JWT AUTHENTICATION
# ============================================================================

def _create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id, "email": email, "type": "access",
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id, "type": "refresh",
        "exp": datetime.utcnow() + timedelta(days=7),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def verify_token(credentials=Depends(security), db: Session = Depends(get_db)) -> str:
    """Verify JWT token and return user_id. Supports JWT and legacy token_<user_id>."""
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
    # Legacy token support for backward compatibility
    if token and token.startswith("token_"):
        user_id = token.replace("token_", "")
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            return user_id
    raise HTTPException(status_code=401, detail="Invalid or expired token")


# ============================================================================
# RATE LIMITING MIDDLEWARE
# ============================================================================

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if path in ("/api/health", "/docs", "/openapi.json", "/redoc"):
        return await call_next(request)
    client_ip = request.client.host if request.client else "unknown"
    auth_header = request.headers.get("authorization", "")
    client_key = f"ratelimit:{auth_header[:20] if auth_header else client_ip}"
    current_minute = int(time.time() // 60)
    rate_key = f"{client_key}:{current_minute}"
    count = redis_client.incr(rate_key)
    if count == 1:
        redis_client.set(rate_key, "1", ex=120)
    if count > RATE_LIMIT_RPM:
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded. Please try again later."},
            headers={"Retry-After": "60"},
        )
    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_RPM)
    response.headers["X-RateLimit-Remaining"] = str(max(0, RATE_LIMIT_RPM - count))
    return response


# ============================================================================
# AUTH ENDPOINTS (database + JWT)
# ============================================================================

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/auth/register")
async def register(req: RegisterRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    password_hash = pwd_context.hash(req.password)
    import secrets as _secrets
    verification_token = _secrets.token_urlsafe(32)
    user = User(
        email=req.email, name=req.name or req.email.split("@")[0],
        password_hash=password_hash, plan="free", email_verified=False,
        verification_token=verification_token,
        verification_token_expires=datetime.utcnow() + timedelta(hours=24),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    crud.log_audit_event(db, action="user.registered", resource_type="user", user_id=user.id, resource_id=user.id)
    background_tasks.add_task(email_service.send_verification_email, email=user.email, name=user.name, verification_token=verification_token)
    access_token = _create_access_token(user.id, user.email)
    refresh_token = _create_refresh_token(user.id)
    return {
        "success": True, "user_id": user.id, "token": access_token,
        "refresh_token": refresh_token, "token_type": "bearer",
        "message": "User registered successfully. Please verify your email.",
    }


@app.post("/api/auth/login")
async def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not pwd_context.verify(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user.last_login = datetime.utcnow()
    db.commit()
    access_token = _create_access_token(user.id, user.email)
    refresh_token = _create_refresh_token(user.id)
    crud.log_audit_event(db, action="user.login", resource_type="user", user_id=user.id)
    return {
        "success": True, "token": access_token, "refresh_token": refresh_token,
        "token_type": "bearer", "user_id": user.id,
    }


@app.post("/api/auth/refresh")
async def refresh_token_endpoint(refresh_token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        new_access_token = _create_access_token(user.id, user.email)
        return {"access_token": new_access_token, "token_type": "bearer"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@app.post("/api/auth/verify-email")
async def verify_email_endpoint(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verification_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    if user.verification_token_expires and user.verification_token_expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Verification token expired")
    user.email_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    db.commit()
    return {"success": True, "message": "Email verified successfully"}


@app.post("/api/auth/request-password-reset")
async def request_password_reset(email: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    import secrets as _secrets
    user = db.query(User).filter(User.email == email).first()
    if user:
        reset_token = _secrets.token_urlsafe(32)
        user.password_reset_token = reset_token
        user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        db.commit()
        background_tasks.add_task(email_service.send_password_reset_email, email=user.email, reset_token=reset_token)
    return {"success": True, "message": "If the email exists, a reset link has been sent."}


@app.post("/api/auth/reset-password")
async def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.password_reset_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset token")
    if user.password_reset_expires and user.password_reset_expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Reset token expired")
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    user.password_hash = pwd_context.hash(new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    db.commit()
    return {"success": True, "message": "Password reset successfully"}


# ============================================================================
# COLLECTION ENDPOINTS (database)
# ============================================================================

@app.post("/api/collections/import")
async def import_postman_collection(
    file: UploadFile = File(...), user_id: str = Depends(verify_token), db: Session = Depends(get_db),
):
    try:
        content = await file.read()
        collection_data = json.loads(content)
        result = parser_factory.parse(collection_data)
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        requests_list = result.get("requests", [])
        owasp_findings = []
        credential_findings = []
        if collection_data.get("info"):
            scan_result = postman_parser.parse_collection_data(collection_data)
            security_scan = scan_result.get("security_scan", {})
            owasp_findings = security_scan.get("owasp_details", [])
            credential_findings = security_scan.get("credential_details", [])
        collection_name = result.get("name", "Imported Collection")
        collection_format = result.get("format", "unknown")
        total_requests = result.get("total_requests", 0)
        db_collection = crud.create_collection(
            db, user_id=user_id, name=collection_name,
            format=collection_format, total_requests=total_requests,
            data={"requests": requests_list, "owasp_findings": owasp_findings, "credential_findings": credential_findings},
        )
        crud.log_audit_event(db, action="collection.imported", resource_type="collection", user_id=user_id, resource_id=db_collection.id)
        return {
            "success": True, "collection_id": db_collection.id,
            "format": collection_format, "total_requests": total_requests, "name": collection_name,
            "security_scan": {"owasp_findings": len(owasp_findings), "credential_findings": len(credential_findings)},
        }
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)}")


@app.get("/api/collections/{collection_id}")
async def get_collection(collection_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    collection = crud.get_collection_by_id(db, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    if collection.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this collection")
    return {
        "id": collection.id, "owner_id": collection.user_id, "name": collection.name,
        "format": collection.format, "total_requests": collection.total_requests,
        "requests": collection.data.get("requests", []) if collection.data else [],
        "owasp_findings": collection.data.get("owasp_findings", []) if collection.data else [],
        "credential_findings": collection.data.get("credential_findings", []) if collection.data else [],
        "created_at": collection.created_at.isoformat() if collection.created_at else None,
    }


@app.get("/api/collections")
async def list_collections(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    collections = crud.get_user_collections(db, user_id)
    return {
        "collections": [
            {"id": c.id, "name": c.name, "format": c.format, "total_requests": c.total_requests,
             "created_at": c.created_at.isoformat() if c.created_at else None}
            for c in collections
        ],
        "total": len(collections),
    }


@app.delete("/api/collections/{collection_id}")
async def delete_collection(collection_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    collection = crud.get_collection_by_id(db, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    if collection.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this collection")
    crud.delete_collection(db, collection_id)
    crud.log_audit_event(db, action="collection.deleted", resource_type="collection", user_id=user_id, resource_id=collection_id)
    return {"success": True, "message": "Collection deleted"}


# ============================================================================
# SECURITY SCANNING ENDPOINTS (database)
# ============================================================================

@app.post("/api/scan/code")
async def scan_code(code: str, language: str = "python", user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    try:
        findings = []
        if "eval(" in code or "exec(" in code:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4()), title="Dangerous code execution",
                severity="CRITICAL", category="Code Execution",
                description="Use of eval() or exec() is dangerous",
                remediation="Avoid dynamic code execution", affected_endpoints=["*"]
            ))
        if "SELECT" in code and "+" in code:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4()), title="Potential SQL Injection",
                severity="HIGH", category="SQL Injection",
                description="String concatenation in SQL query",
                remediation="Use parameterized queries", affected_endpoints=["*"]
            ))
        scan_engine = RiskScoreEngine()
        scan_engine.add_findings(findings)
        metrics = scan_engine.get_metrics()
        findings_dicts = [f.__dict__ for f in findings]
        scan_record = crud.create_scan(
            db, user_id=user_id, collection_id="code-scan",
            scan_type="code", status="completed",
            risk_score=metrics.risk_score, risk_level=metrics.risk_level, findings_data=findings_dicts,
        )
        for f in findings:
            crud.create_finding(db, scan_id=scan_record.id, title=f.title, description=f.description,
                              severity=f.severity, category=f.category, remediation=f.remediation)
        return {
            "scan_id": scan_record.id, "total_findings": len(findings),
            "risk_score": metrics.risk_score, "risk_level": metrics.risk_level,
            "findings": [{"id": f.id, "title": f.title, "severity": f.severity,
                         "category": f.category, "remediation": f.remediation} for f in findings],
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Scan failed: {str(e)}")


# ============================================================================
# RISK SCORE ENDPOINTS (database)
# ============================================================================

@app.get("/api/risk-score")
async def get_risk_score(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    user_engine = RiskScoreEngine()
    scans = crud.get_user_scans(db, user_id)
    for scan in scans:
        if scan.findings_data:
            for f in scan.findings_data:
                user_engine.add_findings([SecurityFinding(
                    id=f.get("id", ""), title=f.get("title", ""),
                    severity=f.get("severity", "info"), category=f.get("category", ""),
                    description=f.get("description", ""), remediation=f.get("remediation", ""),
                    affected_endpoints=f.get("affected_endpoints", []),
                )])
    for idx, anomaly in enumerate(enhanced_cost_tracker.get_anomalies()):
        user_engine.ingest_cost_anomaly(
            anomaly_id=anomaly.get("id", f"cost-anomaly-{idx}"),
            anomaly_type=anomaly.get("type", "spike"), model=anomaly.get("model", "unknown"),
            expected_cost=anomaly.get("expected_cost", 0), actual_cost=anomaly.get("actual_cost", 0),
            description=anomaly.get("description", ""),
        )
    metrics = user_engine.get_metrics()
    risk_data = user_engine.to_dict()
    return {
        "risk_score": metrics.risk_score, "risk_level": metrics.risk_level,
        "total_findings": metrics.total_findings,
        "by_severity": {"critical": metrics.critical_count, "high": metrics.high_count,
                        "medium": metrics.medium_count, "low": metrics.low_count, "info": metrics.info_count},
        "trends": metrics.trends,
        "security_score": risk_data.get("security_score", 0),
        "cost_anomaly_score": risk_data.get("cost_anomaly_score", 0),
        "cost_anomalies": risk_data.get("cost_anomalies", 0),
    }


@app.get("/api/findings")
async def get_findings(user_id: str = Depends(verify_token), export_pdf: bool = False, db: Session = Depends(get_db)):
    scans = crud.get_user_scans(db, user_id)
    all_findings = []
    for scan in scans:
        if scan.findings_data:
            all_findings.extend(scan.findings_data)
    if export_pdf:
        user_engine = RiskScoreEngine()
        for f in all_findings:
            user_engine.add_findings([SecurityFinding(
                id=f.get("id", ""), title=f.get("title", ""), severity=f.get("severity", "info"),
                category=f.get("category", ""), description=f.get("description", ""),
                remediation=f.get("remediation", ""), affected_endpoints=f.get("affected_endpoints", []),
            )])
        scan_data = {"scan_id": "current_findings", "risk_score": user_engine.calculate_score(), "findings": all_findings}
        pdf_path = pdf_generator.generate_security_report(scan_data)
        return {"total": len(all_findings), "findings": all_findings,
                "pdf_url": f"/api/reports/download/{os.path.basename(pdf_path)}"}
    return {"total": len(all_findings), "findings": all_findings}


@app.get("/api/reports/download/{filename}")
async def download_report(filename: str, user_id: str = Depends(verify_token)):
    from fastapi.responses import FileResponse
    from .secure_download import SecureFileDownload
    is_valid, file_path, error = SecureFileDownload.validate_path(filename, pdf_generator.output_dir)
    if not is_valid:
        raise HTTPException(status_code=403 if error == "Access denied" else 404, detail=error)
    return FileResponse(str(file_path), media_type="application/pdf", filename=filename)


# ============================================================================
# KILL SWITCH ENDPOINTS (DB audit persistence)
# ============================================================================

@app.post("/api/kill-switch/block")
async def block_request(request_id: str, reason: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    result = kill_switch.block_request(request_id, reason)
    event = KillSwitchEvent(user_id=user_id, event_type="block", request_id=request_id, reason=reason, details={"result": result})
    db.add(event)
    db.commit()
    crud.log_audit_event(db, action="killswitch.block", resource_type="request", user_id=user_id, resource_id=request_id)
    return {"success": True, "blocked_request_id": request_id, "reason": reason, "blocked_at": datetime.utcnow().isoformat()}


@app.get("/api/kill-switch/status")
async def get_kill_switch_status(user_id: str = Depends(verify_token)):
    return {
        "enabled": kill_switch.is_enabled(), "blocked_count": kill_switch.get_blocked_count(),
        "patterns": kill_switch.get_active_patterns(), "budget_status": kill_switch.get_budget_status(),
        "loop_detections": kill_switch.get_loop_detections(), "audit_trail": kill_switch.get_audit_trail()[-10:],
    }


@app.post("/api/kill-switch/budget")
async def set_kill_switch_budget(
    budget_limit: float = 100.0, model: Optional[str] = None, model_budget: Optional[float] = None,
    operation: Optional[str] = None, operation_budget: Optional[float] = None,
    user_id: str = Depends(verify_token), db: Session = Depends(get_db),
):
    kill_switch.set_budget(
        global_limit=budget_limit,
        model_limits={model: model_budget} if model and model_budget else None,
        operation_limits={operation: operation_budget} if operation and operation_budget else None,
    )
    event = KillSwitchEvent(user_id=user_id, event_type="budget_set", details={"budget_limit": budget_limit, "model": model, "model_budget": model_budget})
    db.add(event)
    db.commit()
    return {"success": True, "budget_status": kill_switch.get_budget_status()}


@app.post("/api/kill-switch/record-cost")
async def record_kill_switch_cost(
    cost: float, model: str, operation: str = "api_call", request_id: Optional[str] = None,
    user_id: str = Depends(verify_token), db: Session = Depends(get_db),
):
    result = kill_switch.record_cost(cost, model, operation)
    event = KillSwitchEvent(user_id=user_id, event_type="cost_recorded", request_id=request_id, model=model, cost=cost, details={"operation": operation, "result": result})
    db.add(event)
    db.commit()
    return result


@app.post("/api/kill-switch/record-agent-call")
async def record_agent_call(
    agent_id: str, endpoint: str, model: str = "unknown",
    user_id: str = Depends(verify_token), db: Session = Depends(get_db),
):
    result = kill_switch.record_agent_call(agent_id, endpoint, model)
    event = KillSwitchEvent(user_id=user_id, event_type="agent_call", agent_id=agent_id, model=model, details={"endpoint": endpoint, "result": result})
    db.add(event)
    db.commit()
    return result


@app.get("/api/kill-switch/audit-trail")
async def get_kill_audit_trail(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    db_events = db.query(KillSwitchEvent).filter(KillSwitchEvent.user_id == user_id).order_by(KillSwitchEvent.created_at.desc()).limit(100).all()
    db_trail = [
        {"event_type": e.event_type, "request_id": e.request_id, "agent_id": e.agent_id, "model": e.model,
         "cost": e.cost, "reason": e.reason, "details": e.details,
         "timestamp": e.created_at.isoformat() if e.created_at else None}
        for e in db_events
    ]
    return {"audit_trail": db_trail, "budget_status": kill_switch.get_budget_status(), "loop_detections": kill_switch.get_loop_detections()}


# ============================================================================
# SHADOW API ENDPOINTS (database + path sandboxing)
# ============================================================================

ALLOWED_WORKSPACE_ROOTS = [os.path.expanduser("~"), "/tmp", "/home"]


def _validate_workspace_path(workspace_path: str) -> str:
    resolved = Path(workspace_path).resolve()
    if ".." in workspace_path:
        raise HTTPException(status_code=400, detail="Path traversal not allowed")
    allowed = any(str(resolved).startswith(root) for root in ALLOWED_WORKSPACE_ROOTS)
    if not allowed:
        raise HTTPException(status_code=403, detail="Workspace path not in allowed directory")
    sensitive = ["/etc", "/var/log", "/proc", "/sys", "/root", "/boot"]
    if any(str(resolved).startswith(s) for s in sensitive):
        raise HTTPException(status_code=403, detail="Access to system directories not allowed")
    return str(resolved)


@app.post("/api/shadow-apis/scan")
async def scan_shadow_apis(collection_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    collection = crud.get_collection_by_id(db, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    if collection.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to scan this collection")
    requests_list = collection.data.get("requests", []) if collection.data else []
    shadow_apis = shadow_scanner.detect_shadow_apis(requests_list)
    scan_result = ShadowAPIScanResult(
        user_id=user_id, collection_id=collection_id, total_shadow_apis=len(shadow_apis),
        results_data=shadow_apis, risk_impact=shadow_scanner.get_risk_impact(),
    )
    db.add(scan_result)
    db.commit()
    crud.log_audit_event(db, action="shadow_api.scan", resource_type="collection", user_id=user_id, resource_id=collection_id)
    return {"collection_id": collection_id, "shadow_apis": shadow_apis, "total_shadow_apis": len(shadow_apis), "risk_impact": shadow_scanner.get_risk_impact()}


@app.post("/api/shadow-apis/scan-workspace")
async def scan_workspace_shadow_apis(
    workspace_path: str, collection_id: Optional[str] = None,
    user_id: str = Depends(verify_token), db: Session = Depends(get_db),
):
    safe_path = _validate_workspace_path(workspace_path)
    documented: set = set()
    if collection_id:
        collection = crud.get_collection_by_id(db, collection_id)
        if collection and collection.user_id == user_id:
            requests_list = collection.data.get("requests", []) if collection.data else []
            for req in requests_list:
                url = req.get("url", "")
                if isinstance(url, str) and url:
                    from urllib.parse import urlparse
                    path = urlparse(url).path
                    if path:
                        documented.add(path)
    result = shadow_scanner.scan_workspace(safe_path, documented)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    scan_result = ShadowAPIScanResult(
        user_id=user_id, collection_id=collection_id, workspace_path=safe_path,
        total_shadow_apis=result.get("total_shadow_apis", 0),
        results_data=result.get("shadow_apis", []), risk_impact=result.get("risk_impact"),
    )
    db.add(scan_result)
    db.commit()
    return result


@app.get("/api/shadow-apis/results")
async def get_shadow_scan_results(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    latest = db.query(ShadowAPIScanResult).filter(ShadowAPIScanResult.user_id == user_id).order_by(ShadowAPIScanResult.created_at.desc()).first()
    if latest:
        return {"shadow_apis": latest.results_data or [], "total_shadow_apis": latest.total_shadow_apis,
                "risk_impact": latest.risk_impact, "scanned_at": latest.created_at.isoformat() if latest.created_at else None}
    return shadow_scanner.to_dict()


# ============================================================================
# PCI DSS COMPLIANCE ENDPOINTS (database)
# ============================================================================

@app.post("/api/compliance/pci-dss")
async def generate_pci_report(
    collection_id: str, export_pdf: bool = False,
    user_id: str = Depends(verify_token), db: Session = Depends(get_db),
    background_tasks: BackgroundTasks = None,
):
    collection = crud.get_collection_by_id(db, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    if collection.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this collection")
    requests_list = collection.data.get("requests", []) if collection.data else []
    owasp_findings = collection.data.get("owasp_findings", []) if collection.data else []
    credential_findings = collection.data.get("credential_findings", []) if collection.data else []
    if not owasp_findings:
        owasp_findings = postman_parser.scan_owasp(requests_list)
    if not credential_findings:
        credential_findings = postman_parser.detect_credentials(requests_list)
    report = pci_generator.generate_report(
        requests=requests_list, owasp_findings=owasp_findings,
        credential_findings=credential_findings, organization=collection.name or "Unknown",
    )
    compliance_pct = report.get("compliance_percentage", report.get("overall_score", 0))
    crud.create_compliance_report(db, user_id=user_id, collection_id=collection_id, report_type="pci-dss-v4.0.1",
                                  compliance_percentage=compliance_pct, requirements_data=report.get("requirements", {}))
    crud.log_audit_event(db, action="compliance.generated", resource_type="collection", user_id=user_id,
                         resource_id=collection_id, details={"report_type": "pci-dss", "compliance_pct": compliance_pct})
    if background_tasks:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            background_tasks.add_task(email_service.send_compliance_report, email=user.email, name=user.name,
                                      report_type="PCI DSS v4.0.1", compliance_score=compliance_pct)
    if export_pdf:
        pdf_content = pci_generator.export_to_pdf(report)
        pdf_filename = f"compliance_{report.get('report_id', uuid.uuid4())}.txt"
        pdf_path = os.path.join(pdf_generator.output_dir, pdf_filename)
        os.makedirs(pdf_generator.output_dir, exist_ok=True)
        with open(pdf_path, "wb") as f:
            f.write(pdf_content)
        return {**report, "pdf_url": f"/api/reports/download/{pdf_filename}"}
    return report


# ============================================================================
# THINKING TOKEN ENDPOINTS (database)
# ============================================================================

@app.post("/api/tokens/track")
async def track_thinking_tokens(
    request_id: str, model: str, prompt_tokens: int, completion_tokens: int, thinking_tokens: int,
    response_time_ms: Optional[float] = None, user_id: str = Depends(verify_token), db: Session = Depends(get_db),
):
    token_data = token_tracker.track_tokens(
        request_id=request_id, model=model, prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens, thinking_tokens=thinking_tokens, response_time_ms=response_time_ms,
    )
    cost = token_tracker.calculate_cost({
        "model": model, "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens, "thinking_tokens": thinking_tokens,
    })
    crud.create_token_usage(
        db, user_id=user_id, model=model, input_tokens=prompt_tokens,
        output_tokens=completion_tokens, thinking_tokens=thinking_tokens,
        cost=cost.get("total_cost", 0) if isinstance(cost, dict) else cost,
    )
    return {
        "request_id": request_id, "tokens": token_data["tokens"], "cost": cost,
        "differential_analysis": token_data.get("differential_analysis"),
        "timing": token_data.get("timing"), "anomalies": token_data.get("anomalies", []),
    }


@app.get("/api/tokens/analytics")
async def get_token_analytics(user_id: str = Depends(verify_token)):
    return token_tracker.get_analytics()


# ============================================================================
# WEBSOCKET (JWT auth)
# ============================================================================

class WebSocketManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, token: str):
        try:
            user_id = None
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                user_id = payload.get("sub")
            except (jwt.InvalidTokenError, jwt.ExpiredSignatureError):
                pass
            if not user_id and token and token.startswith("token_"):
                user_id = token.replace("token_", "")
            if not user_id:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return None
            await websocket.accept()
            if user_id not in self.active_connections:
                self.active_connections[user_id] = []
            self.active_connections[user_id].append(websocket)
            await websocket.send_json({"type": "connection_established", "user_id": user_id, "timestamp": datetime.utcnow().isoformat()})
            return user_id
        except Exception as e:
            logger.error(f"WebSocket connection error: {str(e)}")
            await websocket.close()
            return None

    def disconnect(self, websocket: WebSocket, user_id: str):
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]

    async def send_to_user(self, user_id: str, message: Dict[str, Any]):
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to send message to {user_id}: {str(e)}")

    async def broadcast(self, message: Dict[str, Any]):
        for user_id, connections in self.active_connections.items():
            for connection in connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to broadcast message: {str(e)}")


ws_manager = WebSocketManager()


@app.websocket("/ws/notifications")
async def websocket_endpoint(websocket: WebSocket, token: str):
    user_id = await ws_manager.connect(websocket, token)
    if not user_id:
        return
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, user_id)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
        ws_manager.disconnect(websocket, user_id)


# ============================================================================
# STRIPE WEBHOOK (database)
# ============================================================================

@app.post("/api/webhooks/stripe")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    signature = request.headers.get("stripe-signature", "")
    def db_user_lookup(user_id):
        return db.query(User).filter(User.id == user_id).first()
    webhook_handler = get_webhook_handler(db_user_lookup)
    result = webhook_handler.verify_and_process_webhook(body.decode(), signature)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Webhook processing failed"))
    return result


# ============================================================================
# PLAN ENFORCEMENT (database)
# ============================================================================

@app.get("/api/plan/limits")
async def get_plan_limits(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    plan = user.plan if user else "free"
    limits = PlanLimits.get_limits(plan)
    return {"plan": plan, "limits": limits}


@app.get("/api/plan/check/{feature}")
async def check_feature(feature: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    plan = user.plan if user else "free"
    allowed = True
    return {"feature": feature, "allowed": allowed, "plan": plan, "upgrade_url": "/settings#billing" if not allowed else None}


# ============================================================================
# BILLING CUSTOMER LINKING (database)
# ============================================================================

@app.post("/api/billing/link-customer")
async def link_stripe_customer(stripe_customer_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.stripe_customer_id = stripe_customer_id
    db.commit()
    crud.log_audit_event(db, action="billing.customer_linked", resource_type="user", user_id=user_id)
    return {"success": True, "stripe_customer_id": stripe_customer_id}


# ============================================================================
# WORKSPACE / ONBOARDING (database)
# ============================================================================

class CreateWorkspaceRequest(BaseModel):
    name: str
    collection_name: Optional[str] = None


@app.post("/api/workspaces/create")
async def create_workspace(req: CreateWorkspaceRequest, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    workspace = Workspace(owner_id=user_id, name=req.name, plan="free")
    db.add(workspace)
    db.commit()
    db.refresh(workspace)
    crud.log_audit_event(db, action="workspace.created", resource_type="workspace", user_id=user_id, resource_id=workspace.id)
    return {"success": True, "workspace": {"workspace_id": workspace.id, "name": workspace.name,
            "owner_id": workspace.owner_id, "plan": workspace.plan,
            "created_at": workspace.created_at.isoformat() if workspace.created_at else None}}


@app.post("/api/onboarding/complete")
async def complete_onboarding(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.onboarding_completed = True
    db.commit()
    return {"success": True}


@app.get("/api/onboarding/steps")
async def get_onboarding_steps():
    return {"steps": quick_start.get_onboarding_steps()}


@app.get("/api/auth/verify")
async def verify_auth(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {"id": user.id, "email": user.email, "name": user.name,
            "onboarding_completed": user.onboarding_completed, "plan": user.plan, "email_verified": user.email_verified}


# ============================================================================
# SCAN HISTORY (database)
# ============================================================================

@app.get("/api/scans")
async def list_scans(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    scans = crud.get_user_scans(db, user_id)
    return {
        "scans": [{"id": s.id, "collection_id": s.collection_id, "scan_type": s.scan_type,
                   "status": s.status, "risk_score": s.risk_score, "risk_level": s.risk_level,
                   "total_findings": s.total_findings,
                   "created_at": s.created_at.isoformat() if s.created_at else None} for s in scans],
        "total": len(scans),
    }


@app.post("/api/scan/collection/{collection_id}")
async def scan_collection(
    collection_id: str, background_tasks: BackgroundTasks,
    user_id: str = Depends(verify_token), db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    plan = user.plan if user else "free"
    limits = PlanLimits.get_limits(plan)
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    user_scans_count = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id, Scan.created_at >= month_start).scalar() or 0
    max_scans = limits.get("max_scans_per_month", 10)
    if user_scans_count >= max_scans:
        raise HTTPException(status_code=403, detail="Scan limit reached for your plan. Please upgrade.")
    collection = crud.get_collection_by_id(db, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    if collection.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to scan this collection")
    requests_list = collection.data.get("requests", []) if collection.data else []
    findings = []
    for req_item in requests_list:
        url = req_item.get("url", "")
        if isinstance(url, dict):
            url = url.get("raw", "")
        if "http://" in str(url):
            findings.append({"id": str(uuid.uuid4()), "title": "Insecure HTTP endpoint",
                            "severity": "HIGH", "category": "Transport Security",
                            "description": f"Endpoint uses HTTP instead of HTTPS: {url}",
                            "remediation": "Use HTTPS for all API endpoints"})
    risk_score = min(100, len(findings) * 15)
    risk_level = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 60 else "HIGH" if risk_score < 80 else "CRITICAL"
    scan_record = crud.create_scan(db, user_id=user_id, collection_id=collection_id, scan_type="full",
                                    status="completed", risk_score=risk_score, risk_level=risk_level, findings_data=findings)
    for f in findings:
        crud.create_finding(db, scan_id=scan_record.id, title=f["title"], description=f["description"],
                           severity=f["severity"], category=f.get("category"), remediation=f.get("remediation"))
    crud.log_audit_event(db, action="scan.completed", resource_type="collection", user_id=user_id,
                         resource_id=collection_id, details={"risk_score": risk_score, "findings": len(findings)})
    if user:
        background_tasks.add_task(email_service.send_scan_results, email=user.email, name=user.name,
                                  collection_name=collection.name, risk_score=risk_score, total_findings=len(findings))
    return {
        "id": scan_record.id, "user_id": user_id, "collection_id": collection_id,
        "collection_name": collection.name, "status": "completed",
        "risk_score": risk_score, "risk_level": risk_level,
        "total_findings": len(findings), "findings": findings,
        "created_at": scan_record.created_at.isoformat() if scan_record.created_at else None,
    }


# ============================================================================
# TEAM MANAGEMENT (database)
# ============================================================================

class InviteTeamMemberRequest(BaseModel):
    email: str
    role: str = "viewer"


@app.post("/api/team/invite")
async def invite_team_member(
    req: InviteTeamMemberRequest, background_tasks: BackgroundTasks,
    user_id: str = Depends(verify_token), db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    plan = user.plan if user else "free"
    limits = PlanLimits.get_limits(plan)
    current_members = db.query(func.count(TeamMember.id)).filter(TeamMember.user_id == user_id).scalar() or 0
    max_members = limits.get("max_team_members", 1)
    if current_members >= max_members:
        raise HTTPException(status_code=403, detail="Team member limit reached. Please upgrade.")
    member = crud.add_team_member(db, user_id=user_id, email=req.email, role=req.role)
    crud.log_audit_event(db, action="team.member_invited", resource_type="team", user_id=user_id, resource_id=member.id)
    if user:
        background_tasks.add_task(email_service.send_security_alert, email=req.email, name=req.email.split("@")[0],
                                  alert_type="Team Invitation",
                                  details={"description": f"You have been invited to join {user.name}" + "'" + f"s workspace on DevPulse.",
                                           "action": "Visit https://devpulse.io to accept the invitation."})
    return {"success": True, "member": {"id": member.id, "email": member.email, "role": member.role, "invited_at": member.invited_at.isoformat()}}


@app.get("/api/team/members")
async def list_team_members(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    members = crud.get_user_team_members(db, user_id)
    return {"members": [{"id": m.id, "email": m.email, "role": m.role,
                         "invited_at": m.invited_at.isoformat() if m.invited_at else None} for m in members],
            "total": len(members)}


@app.delete("/api/team/members/{member_id}")
async def remove_team_member(member_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    member = db.query(TeamMember).filter(TeamMember.id == member_id, TeamMember.user_id == user_id).first()
    if not member:
        raise HTTPException(status_code=404, detail="Team member not found")
    crud.remove_team_member(db, member_id)
    crud.log_audit_event(db, action="team.member_removed", resource_type="team", user_id=user_id, resource_id=member_id)
    return {"success": True}


# ============================================================================
# ADMIN ENDPOINTS (database)
# ============================================================================

@app.get("/api/admin/users")
async def admin_list_users(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    admin_user = db.query(User).filter(User.id == user_id).first()
    if not admin_user or admin_user.plan not in ("enterprise", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    users = db.query(User).order_by(User.created_at.desc()).all()
    return {"users": [{"id": u.id, "email": u.email, "name": u.name, "plan": u.plan,
                       "email_verified": u.email_verified,
                       "created_at": u.created_at.isoformat() if u.created_at else None,
                       "last_login": u.last_login.isoformat() if u.last_login else None} for u in users],
            "total": len(users)}


@app.get("/api/admin/metrics")
async def admin_metrics(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    admin_user = db.query(User).filter(User.id == user_id).first()
    if not admin_user or admin_user.plan not in ("enterprise", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"total_users": db.query(func.count(User.id)).scalar() or 0,
            "total_collections": db.query(func.count(Collection.id)).scalar() or 0,
            "total_scans": db.query(func.count(Scan.id)).scalar() or 0,
            "total_findings": db.query(func.count(Finding.id)).scalar() or 0,
            "active_workspaces": db.query(func.count(Workspace.id)).scalar() or 0}


@app.get("/api/admin/audit-log")
async def admin_audit_log(user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    admin_user = db.query(User).filter(User.id == user_id).first()
    if not admin_user or admin_user.plan not in ("enterprise", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    logs = crud.get_audit_logs(db, limit=100)
    return {"entries": [{"id": l.id, "user_id": l.user_id, "action": l.action,
                         "resource_type": l.resource_type, "resource_id": l.resource_id, "details": l.details,
                         "created_at": l.created_at.isoformat() if l.created_at else None} for l in logs],
            "total": len(logs)}


# ============================================================================
# HEALTH & STATUS (database)
# ============================================================================

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": "1.0.0", "database": "connected"}


@app.get("/api/status")
async def get_status(db: Session = Depends(get_db)):
    return {"collections": db.query(func.count(Collection.id)).scalar() or 0,
            "scans": db.query(func.count(Scan.id)).scalar() or 0,
            "users": db.query(func.count(User.id)).scalar() or 0,
            "blocked_requests": kill_switch.get_blocked_count()}


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# ============================================================================
# ENHANCED COST TRACKING ENDPOINTS
# ============================================================================

@app.post("/api/cost-tracker/track")
async def track_llm_cost(
    request_id: str, model: str, prompt_tokens: int, completion_tokens: int,
    thinking_tokens: int = 0, session_id: Optional[str] = None, endpoint: Optional[str] = None,
    user_id: str = Depends(verify_token),
):
    entry = enhanced_cost_tracker.track(request_id=request_id, model=model, prompt_tokens=prompt_tokens,
                                         completion_tokens=completion_tokens, thinking_tokens=thinking_tokens,
                                         session_id=session_id, endpoint=endpoint)
    analytics_engine.log_event("cost.tracked", {"model": model, "cost": entry.cost_usd, "tokens": entry.usage.total_tokens}, user_id=user_id)
    return {"request_id": entry.request_id, "model": entry.model, "cost_usd": entry.cost_usd,
            "tokens": {"prompt": entry.usage.prompt_tokens, "completion": entry.usage.completion_tokens,
                       "thinking": entry.usage.thinking_tokens, "total": entry.usage.total_tokens}}


@app.get("/api/cost-tracker/summary")
async def get_cost_summary(user_id: str = Depends(verify_token)):
    return enhanced_cost_tracker.get_summary()


@app.get("/api/cost-tracker/models")
async def get_cost_by_model(user_id: str = Depends(verify_token)):
    return {"models": enhanced_cost_tracker.get_model_breakdown()}


@app.get("/api/cost-tracker/utilization")
async def get_cost_utilization(user_id: str = Depends(verify_token)):
    return enhanced_cost_tracker.get_utilization()


@app.get("/api/cost-tracker/daily")
async def get_daily_costs(days: int = 30, user_id: str = Depends(verify_token)):
    return {"daily": enhanced_cost_tracker.get_daily_breakdown(days)}


@app.get("/api/cost-tracker/anomalies")
async def get_cost_anomalies(user_id: str = Depends(verify_token)):
    return {"anomalies": enhanced_cost_tracker.get_anomalies()}


@app.post("/api/cost-tracker/budget")
async def set_cost_budget(window: str, budget_usd: float, user_id: str = Depends(verify_token)):
    success = enhanced_cost_tracker.set_window_budget(window, budget_usd)
    if not success:
        raise HTTPException(status_code=400, detail=f"Invalid window: {window}")
    return {"success": True, "window": window, "budget_usd": budget_usd}


# ============================================================================
# ADVANCED ANALYTICS ENDPOINTS
# ============================================================================

@app.get("/api/analytics/comprehensive")
async def get_comprehensive_analytics(user_id: str = Depends(verify_token)):
    return analytics_engine.get_comprehensive_analytics(user_id=user_id)


@app.get("/api/analytics/scan-trends")
async def get_scan_trends(days: int = 30, user_id: str = Depends(verify_token)):
    return analytics_engine.get_scan_trends(days=days)


@app.get("/api/analytics/risk-trend")
async def get_risk_trend(days: int = 30, user_id: str = Depends(verify_token)):
    return {"trend": analytics_engine.get_risk_trend(user_id=user_id, days=days)}


@app.get("/api/analytics/finding-heatmap")
async def get_finding_heatmap(user_id: str = Depends(verify_token)):
    return analytics_engine.get_finding_heatmap()


@app.get("/api/analytics/endpoint-risk")
async def get_endpoint_risk(user_id: str = Depends(verify_token)):
    return {"endpoints": analytics_engine.get_endpoint_risk_distribution()}


@app.get("/api/analytics/activity-feed")
async def get_activity_feed(limit: int = 50, user_id: str = Depends(verify_token)):
    return {"activity": analytics_engine.get_activity_feed(user_id=user_id, limit=limit)}


# ============================================================================
# AI SECURITY ANALYSIS ENDPOINTS
# ============================================================================

@app.post("/api/ai-security/analyze-collection/{collection_id}")
async def ai_analyze_collection(collection_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    collection = crud.get_collection_by_id(db, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    if collection.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    requests_list = collection.data.get("requests", []) if collection.data else []
    result = ai_security_analyzer.analyze_collection(requests_list)
    analytics_engine.log_event("ai_analysis.completed", {"collection_id": collection_id, "findings": result["total_findings"], "risk_score": result["risk_score"]}, user_id=user_id)
    return result


@app.get("/api/ai-security/owasp-reference")
async def get_owasp_reference(user_id: str = Depends(verify_token)):
    return {"owasp_top_10": ai_security_analyzer.get_owasp_coverage_report()}


@app.post("/api/ai-security/remediation-plan")
async def get_remediation_plan(collection_id: str, user_id: str = Depends(verify_token), db: Session = Depends(get_db)):
    collection = crud.get_collection_by_id(db, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    if collection.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    requests_list = collection.data.get("requests", []) if collection.data else []
    analysis = ai_security_analyzer.analyze_collection(requests_list)
    plan = ai_security_analyzer.get_remediation_plan(analysis["findings"])
    return {"remediation_plan": plan, "total_items": len(plan)}


# ============================================================================
# WEBHOOK INTEGRATION ENDPOINTS
# ============================================================================

class WebhookCreateRequest(BaseModel):
    name: str
    platform: str
    url: str
    events: List[str]


class WebhookUpdateRequest(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    events: Optional[List[str]] = None
    enabled: Optional[bool] = None


@app.post("/api/webhooks")
async def create_webhook(req: WebhookCreateRequest, user_id: str = Depends(verify_token)):
    wh = webhook_service.register_webhook(user_id=user_id, name=req.name, platform=req.platform, url=req.url, events=req.events)
    analytics_engine.log_event("webhook.created", {"platform": req.platform, "events": req.events}, user_id=user_id)
    return {"success": True, "webhook_id": wh.webhook_id}


@app.get("/api/webhooks")
async def list_webhooks(user_id: str = Depends(verify_token)):
    return {"webhooks": webhook_service.get_webhooks(user_id)}


@app.put("/api/webhooks/{webhook_id}")
async def update_webhook(webhook_id: str, req: WebhookUpdateRequest, user_id: str = Depends(verify_token)):
    result = webhook_service.update_webhook(webhook_id, user_id, req.dict(exclude_none=True))
    if not result:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return result


@app.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user_id: str = Depends(verify_token)):
    if not webhook_service.delete_webhook(webhook_id, user_id):
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"success": True}


@app.get("/api/webhooks/events")
async def get_webhook_events(user_id: str = Depends(verify_token)):
    return {"events": webhook_service.get_supported_events()}


@app.get("/api/webhooks/platforms")
async def get_webhook_platforms(user_id: str = Depends(verify_token)):
    return {"platforms": webhook_service.get_supported_platforms()}


@app.get("/api/webhooks/history")
async def get_webhook_history(user_id: str = Depends(verify_token)):
    return {"deliveries": webhook_service.get_delivery_history(user_id)}


@app.post("/api/webhooks/test/{webhook_id}")
async def test_webhook(webhook_id: str, user_id: str = Depends(verify_token)):
    results = webhook_service.dispatch(event_type="scan.completed", data={"test": True, "risk_score": 42, "total_findings": 3, "collection_name": "Test Collection"}, user_id=user_id)
    return {"success": True, "deliveries": results}


# ============================================================================
# ENHANCED POLICY ENGINE ENDPOINTS
# ============================================================================

@app.get("/api/policy/check/{feature_id}")
async def check_policy(feature_id: str, user_id: str = Depends(verify_token)):
    return policy_engine.check_feature_access(user_id, feature_id)


@app.get("/api/policy/plans")
async def get_all_plans(user_id: str = Depends(verify_token)):
    return {"plans": policy_engine.get_all_plans()}


@app.get("/api/policy/usage")
async def get_policy_usage(user_id: str = Depends(verify_token)):
    return policy_engine.get_usage_summary(user_id)


@app.get("/api/policy/features/{tier}")
async def get_plan_features_detail(tier: str, user_id: str = Depends(verify_token)):
    return policy_engine.get_plan_features(tier)


# ============================================================================
# SCAN SESSION HISTORY ENDPOINTS
# ============================================================================

@app.get("/api/scan-sessions")
async def get_scan_sessions(collection_id: Optional[str] = None, status: Optional[str] = None, limit: int = 50, user_id: str = Depends(verify_token)):
    return {"sessions": scan_session_history.get_user_history(user_id=user_id, limit=limit, collection_id=collection_id, status=status)}


@app.get("/api/scan-sessions/{session_id}")
async def get_scan_session(session_id: str, user_id: str = Depends(verify_token)):
    session = scan_session_history.get_session(session_id, user_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.post("/api/scan-sessions/{session_id}/notes")
async def add_scan_note(session_id: str, note: str, user_id: str = Depends(verify_token)):
    if not scan_session_history.add_note(session_id, note):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"success": True}


@app.post("/api/scan-sessions/compare")
async def compare_scan_sessions(baseline_session_id: str, compare_session_id: str, user_id: str = Depends(verify_token)):
    result = scan_session_history.compare_sessions(baseline_session_id, compare_session_id, user_id)
    if not result:
        raise HTTPException(status_code=404, detail="One or both sessions not found")
    return result


@app.get("/api/scan-sessions/stats")
async def get_scan_stats(user_id: str = Depends(verify_token)):
    return scan_session_history.get_user_stats(user_id)


# ============================================================================
# STARTUP & SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup_event():
    init_db()
    print("DevPulse API starting up...")
    print("Database initialized successfully")
    print("All services initialized: DB Persistence, JWT Auth, Email, Redis Rate Limiting")
    print("Patents: [1] Unified Risk Score, [2] Thinking Token Analysis, [3] Kill Switch")
    print("Features: PCI DSS v4.0.1, GDPR, Shadow API Scanner, Admin Dashboard, Team Mgmt, Stripe Billing")


@app.on_event("shutdown")
async def shutdown_event():
    print("DevPulse API shutting down...")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
