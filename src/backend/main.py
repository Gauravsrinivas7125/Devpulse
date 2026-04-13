"""
DevPulse - Production Backend API
Complete FastAPI application with all core services
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks, Header, WebSocket, WebSocketDisconnect, status
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pydantic import BaseModel
from dotenv import load_dotenv
load_dotenv()

# Import services
from .trpc_router import trpc
from .billing_endpoints import router as billing_router
from .stripe_webhook_handler import get_webhook_handler
from .plan_enforcement import get_plan_enforcer, PlanLimits
from .auth_service import QuickStartService
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
import logging
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

# Use bcrypt for production-grade password hashing (salted, slow, timing-safe)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _hash_password(password: str) -> str:
    """Hash password using bcrypt (salted, timing-safe)"""
    return pwd_context.hash(password)


def _verify_password(password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash (timing-safe)"""
    return pwd_context.verify(password, hashed)

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
postman_parser = PostmanParser()
risk_engine = RiskScoreEngine()
kill_switch = KillSwitch()
shadow_scanner = ShadowAPIScanner()
pci_generator = PCIComplianceGenerator()
token_tracker = ThinkingTokenTracker()
pdf_generator = PDFReportGenerator()

# In-memory storage (replace with database in production)
collections_db = {}
findings_db = {}
users_db = {}
workspaces_db = {}
scans_db = {}
audit_log = []

# Initialize plan enforcement and webhook handler
quick_start = QuickStartService()

# SECURITY: Add authentication dependency
security = HTTPBearer()

async def verify_token(credentials = Depends(security)) -> str:
    """Verify JWT token and return user_id"""
    token = credentials.credentials
    # In production, verify JWT signature and expiration
    # For now, just check if token exists
    if not token or not token.startswith("token_"):
        raise HTTPException(status_code=401, detail="Invalid token")
    return token.replace("token_", "")


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.post("/api/auth/register")
async def register(email: str, password: str):
    """Register new user"""
    if email in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    user_id = str(uuid.uuid4())
    users_db[email] = {
        "id": user_id,
        "email": email,
        "password": _hash_password(password),
        "created_at": datetime.utcnow().isoformat(),
        "stripe_customer_id": None,  # Set when billing is initialized
    }
    
    return {
        "success": True,
        "user_id": user_id,
        "token": f"token_{user_id}",
        "message": "User registered successfully"
    }


@app.post("/api/auth/login")
async def login(email: str, password: str):
    """Login user"""
    if email not in users_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = users_db[email]
    if not _verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate JWT token (simplified - use proper JWT in production)
    token = f"token_{user['id']}"
    
    return {
        "success": True,
        "token": token,
        "user_id": user["id"]
    }


# ============================================================================
# POSTMAN COLLECTION ENDPOINTS
# ============================================================================

@app.post("/api/collections/import")
async def import_postman_collection(file: UploadFile = File(...), user_id: str = Depends(verify_token)):
    """Import collection (Postman, Bruno, or OpenAPI format)"""
    try:
        # Read file content
        content = await file.read()
        collection_data = json.loads(content)
        
        # Auto-detect format and parse (Postman, Bruno, or OpenAPI)
        result = parser_factory.parse(collection_data)
        
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        
        # Store in database with owner_id for ownership checks
        collection_id = str(uuid.uuid4())
        collections_db[collection_id] = {
            "id": collection_id,
            "owner_id": user_id,
            "name": result.get("name", "Imported Collection"),
            "format": result.get("format", "unknown"),
            "requests": result.get("requests", []),
            "total_requests": result.get("total_requests", 0),
            "created_at": datetime.utcnow().isoformat()
        }
        
        return {
            "success": True,
            "collection_id": collection_id,
            "format": result.get("format"),
            "total_requests": result.get("total_requests", 0),
            "name": result.get("name")
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)}")


@app.get("/api/collections/{collection_id}")
async def get_collection(collection_id: str, user_id: str = Depends(verify_token)):
    """Get collection details (requires auth + ownership)"""
    if collection_id not in collections_db:
        raise HTTPException(status_code=404, detail="Collection not found")
    collection = collections_db[collection_id]
    if collection.get("owner_id") and collection["owner_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this collection")
    return collection


@app.get("/api/collections")
async def list_collections(user_id: str = Depends(verify_token)):
    """List all collections owned by the authenticated user"""
    user_collections = [c for c in collections_db.values() if c.get("owner_id") == user_id]
    return {
        "collections": user_collections,
        "total": len(user_collections)
    }


# ============================================================================
# SECURITY SCANNING ENDPOINTS
# ============================================================================

@app.post("/api/scan/code")
async def scan_code(code: str, language: str = "python", user_id: str = Depends(verify_token)):
    """Scan code for vulnerabilities (requires authentication)"""
    try:
        # Simulate vulnerability detection
        findings = []
        
        # Check for common vulnerabilities
        if "eval(" in code or "exec(" in code:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4()),
                title="Dangerous code execution",
                severity="CRITICAL",
                category="Code Execution",
                description="Use of eval() or exec() is dangerous",
                remediation="Avoid dynamic code execution",
                affected_endpoints=["*"]
            ))
        
        if "SELECT" in code and "+" in code:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4()),
                title="Potential SQL Injection",
                severity="HIGH",
                category="SQL Injection",
                description="String concatenation in SQL query",
                remediation="Use parameterized queries",
                affected_endpoints=["*"]
            ))
        
        # Calculate risk score per-scan (avoid global accumulation)
        scan_engine = RiskScoreEngine()
        scan_engine.add_findings(findings)
        metrics = scan_engine.get_metrics()
        
        # Store findings
        scan_id = str(uuid.uuid4())
        findings_db[scan_id] = {
            "id": scan_id,
            "user_id": user_id,
            "findings": [f.__dict__ for f in findings],
            "risk_score": metrics.risk_score,
            "risk_level": metrics.risk_level,
            "created_at": datetime.utcnow().isoformat()
        }
        
        return {
            "scan_id": scan_id,
            "total_findings": len(findings),
            "risk_score": metrics.risk_score,
            "risk_level": metrics.risk_level,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "remediation": f.remediation
                }
                for f in findings
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Scan failed: {str(e)}")


# ============================================================================
# RISK SCORE ENDPOINTS
# ============================================================================

@app.get("/api/risk-score")
async def get_risk_score(user_id: str = Depends(verify_token)):
    """Get current unified risk score scoped to the authenticated user"""
    # Build risk score from this user's findings only
    user_engine = RiskScoreEngine()
    for scan in findings_db.values():
        if scan.get("user_id") == user_id:
            for f in scan.get("findings", []):
                user_engine.add_findings([
                    SecurityFinding(
                        id=f.get("id", ""),
                        title=f.get("title", ""),
                        severity=f.get("severity", "info"),
                        category=f.get("category", ""),
                        description=f.get("description", ""),
                        remediation=f.get("remediation", ""),
                        affected_endpoints=f.get("affected_endpoints", []),
                    )
                ])
    metrics = user_engine.get_metrics()
    
    return {
        "risk_score": metrics.risk_score,
        "risk_level": metrics.risk_level,
        "total_findings": metrics.total_findings,
        "by_severity": {
            "critical": metrics.critical_count,
            "high": metrics.high_count,
            "medium": metrics.medium_count,
            "low": metrics.low_count,
            "info": metrics.info_count
        },
        "trends": metrics.trends
    }


@app.get("/api/findings")
async def get_findings(user_id: str = Depends(verify_token), export_pdf: bool = False):
    """Get all findings (requires auth)"""
    all_findings = []
    for scan in findings_db.values():
        if scan.get("user_id") == user_id:
            all_findings.extend(scan["findings"])
    
    if export_pdf:
        # Build per-user risk score for PDF (avoid global engine which is never populated)
        user_engine = RiskScoreEngine()
        for f in all_findings:
            user_engine.add_findings([SecurityFinding(
                id=f.get("id", ""), title=f.get("title", ""),
                severity=f.get("severity", "info"), category=f.get("category", ""),
                description=f.get("description", ""), remediation=f.get("remediation", ""),
                affected_endpoints=f.get("affected_endpoints", []),
            )])
        scan_data = {
            "scan_id": "current_findings",
            "risk_score": user_engine.calculate_score(),
            "findings": all_findings
        }
        pdf_path = pdf_generator.generate_security_report(scan_data)
        return {
            "total": len(all_findings),
            "findings": all_findings,
            "pdf_url": f"/api/reports/download/{os.path.basename(pdf_path)}"
        }
    
    return {
        "total": len(all_findings),
        "findings": all_findings
    }

@app.get("/api/reports/download/{filename}")
async def download_report(filename: str, user_id: str = Depends(verify_token)):
    """Download a generated PDF report"""
    from fastapi.responses import FileResponse
    from .secure_download import SecureFileDownload
    is_valid, file_path, error = SecureFileDownload.validate_path(filename, pdf_generator.output_dir)
    if not is_valid:
        raise HTTPException(status_code=403 if error == "Access denied" else 404, detail=error)
    return FileResponse(str(file_path), media_type="application/pdf", filename=filename)


# ============================================================================
# KILL SWITCH ENDPOINTS
# ============================================================================

@app.post("/api/kill-switch/block")
async def block_request(request_id: str, reason: str, user_id: str = Depends(verify_token)):
    """Block a request (requires authentication)"""
    result = kill_switch.block_request(request_id, reason)
    
    return {
        "success": True,
        "blocked_request_id": request_id,
        "reason": reason,
        "blocked_at": datetime.utcnow().isoformat()
    }


@app.get("/api/kill-switch/status")
async def get_kill_switch_status(user_id: str = Depends(verify_token)):
    """Get kill switch status (requires authentication)"""
    return {
        "enabled": kill_switch.is_enabled(),
        "blocked_count": kill_switch.get_blocked_count(),
        "patterns": kill_switch.get_active_patterns()
    }


# ============================================================================
# SHADOW API ENDPOINTS
# ============================================================================

@app.post("/api/shadow-apis/scan")
async def scan_shadow_apis(collection_id: str, user_id: str = Depends(verify_token)):
    """Scan for shadow APIs (requires authentication + ownership)"""
    if collection_id not in collections_db:
        raise HTTPException(status_code=404, detail="Collection not found")
    
    collection = collections_db[collection_id]
    if collection.get("owner_id") and collection["owner_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to scan this collection")
    shadow_apis = shadow_scanner.detect_shadow_apis(collection["requests"])
    
    return {
        "collection_id": collection_id,
        "shadow_apis": shadow_apis,
        "total_shadow_apis": len(shadow_apis),
        "risk_impact": len(shadow_apis) * 5  # Each shadow API adds 5 points
    }


# ============================================================================
# PCI DSS COMPLIANCE ENDPOINTS
# ============================================================================

@app.post("/api/compliance/pci-dss")
async def generate_pci_report(collection_id: str, export_pdf: bool = False, user_id: str = Depends(verify_token)):
    """Generate PCI DSS compliance report (requires authentication + ownership)"""
    if collection_id not in collections_db:
        raise HTTPException(status_code=404, detail="Collection not found")
    
    collection = collections_db[collection_id]
    if collection.get("owner_id") and collection["owner_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this collection")
    report = pci_generator.generate_report(collection["requests"], collection["name"])
    
    if export_pdf:
        pdf_path = pdf_generator.generate_compliance_report(report)
        return {**report, "pdf_url": f"/api/reports/download/{os.path.basename(pdf_path)}"}
    
    return {
        "report_id": str(uuid.uuid4()),
        "collection_id": collection_id,
        "compliance_status": report["summary"]["status"],
        "compliance_percentage": report["summary"]["compliance_percentage"],
        "requirements": report["requirements"],
        "generated_at": datetime.utcnow().isoformat()
    }


# ============================================================================
# THINKING TOKEN ENDPOINTS
# ============================================================================

@app.post("/api/tokens/track")
async def track_thinking_tokens(
    request_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    thinking_tokens: int,
    user_id: str = Depends(verify_token)
):
    """Track thinking tokens for LLM calls (requires authentication)"""
    token_data = token_tracker.track_tokens(
        request_id=request_id,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        thinking_tokens=thinking_tokens
    )

    # calculate_cost expects flat token keys; pass the original parameters directly
    cost = token_tracker.calculate_cost({
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "thinking_tokens": thinking_tokens,
    })

    return {
        "request_id": request_id,
        "tokens": token_data["tokens"],
        "cost": cost
    }


@app.get("/api/tokens/analytics")
async def get_token_analytics(user_id: str = Depends(verify_token)):
    """Get token usage analytics (requires authentication)"""
    return token_tracker.get_analytics()


# ============================================================================
# WEBSOCKET REAL-TIME PUSH
# ============================================================================

class WebSocketManager:
    """Manage WebSocket connections with AUTH and RECONNECT logic"""
    
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}  # user_id -> List[WebSocket]
    
    async def connect(self, websocket: WebSocket, token: str):
        """Accept connection with AUTHENTICATION"""
        try:
            # SECURITY: Use same token_<user_id> scheme as HTTP auth
            if not token or not token.startswith("token_"):
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                logger.warning(f"WebSocket auth failed for token: {token[:10]}...")
                return None
            user_id = token.replace("token_", "")
            
            if not user_id:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                logger.warning(f"WebSocket auth failed: empty user_id")
                return None
            
            await websocket.accept()
            if user_id not in self.active_connections:
                self.active_connections[user_id] = []
            self.active_connections[user_id].append(websocket)
            
            logger.info(f"WebSocket connected for user {user_id}: {len(self.active_connections[user_id])} active")
            
            # Send welcome message (confirms connection to client)
            await websocket.send_json({
                "type": "connection_established",
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat()
            })
            return user_id
            
        except Exception as e:
            logger.error(f"WebSocket connection error: {str(e)}")
            await websocket.close()
            return None
    
    def disconnect(self, websocket: WebSocket, user_id: str):
        """Remove connection from active list"""
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
            logger.info(f"WebSocket disconnected for user {user_id}")
    
    async def send_to_user(self, user_id: str, message: Dict[str, Any]):
        """Send message to a specific user (all their active sessions)"""
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to send message to {user_id}: {str(e)}")
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all active connections"""
        for user_id, connections in self.active_connections.items():
            for connection in connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to broadcast message: {str(e)}")

ws_manager = WebSocketManager()

@app.websocket("/ws/notifications")
async def websocket_endpoint(websocket: WebSocket, token: str):
    """WebSocket endpoint for real-time notifications"""
    user_id = await ws_manager.connect(websocket, token)
    if not user_id:
        return
        
    try:
        while True:
            # Wait for any message from client (or just keep connection open)
            data = await websocket.receive_text()
            # Echo or handle client messages if needed
            
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, user_id)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
        ws_manager.disconnect(websocket, user_id)


# ============================================================================
# STRIPE WEBHOOK ENDPOINT
# ============================================================================

from fastapi import Request

@app.post("/api/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events with signature verification"""
    body = await request.body()
    signature = request.headers.get("stripe-signature", "")

    webhook_handler = get_webhook_handler(users_db)
    result = webhook_handler.verify_and_process_webhook(body.decode(), signature)

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Webhook processing failed"))

    return result


# ============================================================================
# PLAN ENFORCEMENT ENDPOINT
# ============================================================================

@app.get("/api/plan/limits")
async def get_plan_limits(user_id: str = Depends(verify_token)):
    """Get the current user's plan limits"""
    user = next((u for u in users_db.values() if u.get("id") == user_id), None)
    plan = user.get("plan", "free") if user else "free"
    limits = PlanLimits.get_limits(plan)
    return {
        "plan": plan,
        "limits": limits,
    }


@app.get("/api/plan/check/{feature}")
async def check_feature(feature: str, user_id: str = Depends(verify_token)):
    """Check if the current user can access a specific feature"""
    enforcer = get_plan_enforcer(users_db)
    allowed = enforcer.check_feature_access(user_id, feature)
    plan = enforcer.get_user_plan(user_id)
    return {
        "feature": feature,
        "allowed": allowed,
        "plan": plan,
        "upgrade_url": "/settings#billing" if not allowed else None,
    }


# ============================================================================
# STRIPE CUSTOMER LINKING ENDPOINT
# ============================================================================

@app.post("/api/billing/link-customer")
async def link_stripe_customer(stripe_customer_id: str, user_id: str = Depends(verify_token)):
    """Link a Stripe customer ID to the authenticated user (called after Stripe checkout)"""
    user = next((u for u in users_db.values() if u.get("id") == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["stripe_customer_id"] = stripe_customer_id
    return {"success": True, "stripe_customer_id": stripe_customer_id}


# ============================================================================
# WORKSPACE / ONBOARDING ENDPOINTS
# ============================================================================

class CreateWorkspaceRequest(BaseModel):
    name: str
    collection_name: Optional[str] = None


@app.post("/api/workspaces/create")
async def create_workspace(req: CreateWorkspaceRequest, user_id: str = Depends(verify_token)):
    """Create a workspace during onboarding"""
    success, message, workspace = quick_start.create_workspace(
        user_id=user_id,
        workspace_name=req.name,
        collection_name=req.collection_name,
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)

    # Link workspace to user
    user = next((u for u in users_db.values() if u.get("id") == user_id), None)
    if user:
        user["workspace_id"] = workspace["workspace_id"]

    workspaces_db[workspace["workspace_id"]] = workspace
    return {"success": True, "workspace": workspace}


@app.post("/api/onboarding/complete")
async def complete_onboarding(user_id: str = Depends(verify_token)):
    """Mark onboarding as complete for the current user"""
    user = next((u for u in users_db.values() if u.get("id") == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["onboarding_completed"] = True
    return {"success": True}


@app.get("/api/onboarding/steps")
async def get_onboarding_steps():
    """Get available onboarding steps"""
    return {"steps": quick_start.get_onboarding_steps()}


# ============================================================================
# AUTH VERIFY ENDPOINT (used by frontend on load)
# ============================================================================

@app.get("/api/auth/verify")
async def verify_auth(user_id: str = Depends(verify_token)):
    """Verify token and return user profile"""
    user = next((u for u in users_db.values() if u.get("id") == user_id), None)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user.get("name", user["email"]),
        "workspace_id": user.get("workspace_id"),
        "onboarding_completed": user.get("onboarding_completed", False),
        "plan": user.get("plan", "free"),
    }


# ============================================================================
# COLLECTION DELETE ENDPOINT
# ============================================================================

@app.delete("/api/collections/{collection_id}")
async def delete_collection(collection_id: str, user_id: str = Depends(verify_token)):
    """Delete a collection (ownership check)"""
    if collection_id not in collections_db:
        raise HTTPException(status_code=404, detail="Collection not found")
    collection = collections_db[collection_id]
    if collection.get("owner_id") and collection["owner_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this collection")
    del collections_db[collection_id]
    return {"success": True, "message": "Collection deleted"}


# ============================================================================
# SCAN HISTORY ENDPOINTS
# ============================================================================

@app.get("/api/scans")
async def list_scans(user_id: str = Depends(verify_token)):
    """List all scans for the current user"""
    user_scans = [s for s in scans_db.values() if s.get("user_id") == user_id]
    return {"scans": user_scans, "total": len(user_scans)}


@app.post("/api/scan/collection/{collection_id}")
async def scan_collection(
    collection_id: str,
    background_tasks: BackgroundTasks,
    user_id: str = Depends(verify_token),
):
    """Run a security scan on a collection (with plan enforcement)"""
    enforcer = get_plan_enforcer(users_db)
    # Count only scans from the current month (not all-time) to match max_scans_per_month
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    user_scans_count = len([s for s in scans_db.values() if s.get("user_id") == user_id and s.get("created_at", "") >= month_start])
    if not enforcer.check_scan_limit(user_id, user_scans_count):
        raise HTTPException(status_code=403, detail="Scan limit reached for your plan. Please upgrade.")

    if collection_id not in collections_db:
        raise HTTPException(status_code=404, detail="Collection not found")

    collection = collections_db[collection_id]
    if collection.get("owner_id") and collection["owner_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to scan this collection")
    scan_id = str(uuid.uuid4())

    # Run scan
    findings = []
    for req_item in collection.get("requests", []):
        url = req_item.get("url", "")
        if isinstance(url, dict):
            url = url.get("raw", "")
        if "http://" in str(url):
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "Insecure HTTP endpoint",
                "severity": "HIGH",
                "category": "Transport Security",
                "description": f"Endpoint uses HTTP instead of HTTPS: {url}",
                "remediation": "Use HTTPS for all API endpoints",
            })

    risk_score = min(100, len(findings) * 15)
    risk_level = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 60 else "HIGH" if risk_score < 80 else "CRITICAL"

    scan_result = {
        "id": scan_id,
        "user_id": user_id,
        "collection_id": collection_id,
        "collection_name": collection.get("name", "Unknown"),
        "status": "completed",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "findings": findings,
        "created_at": datetime.utcnow().isoformat(),
    }
    scans_db[scan_id] = scan_result
    findings_db[scan_id] = {"id": scan_id, "user_id": user_id, "findings": findings, "risk_score": risk_score, "risk_level": risk_level, "created_at": datetime.utcnow().isoformat()}

    return scan_result


# ============================================================================
# TEAM MANAGEMENT ENDPOINTS
# ============================================================================

class InviteTeamMemberRequest(BaseModel):
    email: str
    role: str = "viewer"

team_members_db: Dict[str, List[Dict]] = {}  # user_id -> list of members

@app.post("/api/team/invite")
async def invite_team_member(req: InviteTeamMemberRequest, user_id: str = Depends(verify_token)):
    """Invite a team member (with plan enforcement)"""
    enforcer = get_plan_enforcer(users_db)
    current_members = len(team_members_db.get(user_id, []))
    if not enforcer.check_team_member_limit(user_id, current_members):
        raise HTTPException(status_code=403, detail="Team member limit reached. Please upgrade.")

    member = {
        "id": str(uuid.uuid4()),
        "email": req.email,
        "role": req.role,
        "invited_at": datetime.utcnow().isoformat(),
        "status": "pending",
    }
    if user_id not in team_members_db:
        team_members_db[user_id] = []
    team_members_db[user_id].append(member)
    return {"success": True, "member": member}


@app.get("/api/team/members")
async def list_team_members(user_id: str = Depends(verify_token)):
    """List team members"""
    members = team_members_db.get(user_id, [])
    return {"members": members, "total": len(members)}


@app.delete("/api/team/members/{member_id}")
async def remove_team_member(member_id: str, user_id: str = Depends(verify_token)):
    """Remove a team member"""
    members = team_members_db.get(user_id, [])
    team_members_db[user_id] = [m for m in members if m["id"] != member_id]
    return {"success": True}


# ============================================================================
# ADMIN ENDPOINTS
# ============================================================================

def _require_admin(user_id: str):
    """Verify user has admin privileges (enterprise plan)"""
    user = next((u for u in users_db.values() if u.get("id") == user_id), None)
    if not user or user.get("plan") not in ("enterprise", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")


@app.get("/api/admin/users")
async def admin_list_users(user_id: str = Depends(verify_token)):
    """Admin: List all users"""
    _require_admin(user_id)
    return {
        "users": [
            {
                "id": u.get("id"),
                "email": u.get("email"),
                "plan": u.get("plan", "free"),
                "created_at": u.get("created_at"),
                "onboarding_completed": u.get("onboarding_completed", False),
            }
            for u in users_db.values()
        ],
        "total": len(users_db),
    }


@app.get("/api/admin/metrics")
async def admin_metrics(user_id: str = Depends(verify_token)):
    """Admin: System metrics"""
    _require_admin(user_id)
    return {
        "total_users": len(users_db),
        "total_collections": len(collections_db),
        "total_scans": len(scans_db),
        "total_findings": sum(len(s.get("findings", [])) for s in findings_db.values()),
        "active_workspaces": len(workspaces_db),
    }


@app.get("/api/admin/audit-log")
async def admin_audit_log(user_id: str = Depends(verify_token)):
    """Admin: Audit log"""
    _require_admin(user_id)
    return {"entries": audit_log[-100:], "total": len(audit_log)}


# ============================================================================
# HEALTH & STATUS ENDPOINTS
# ============================================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.get("/api/status")
async def get_status():
    """Get system status"""
    return {
        "collections": len(collections_db),
        "findings": len(findings_db),
        "blocked_requests": kill_switch.get_blocked_count(),
        "total_scans": len(scans_db),
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"}
    )


# ============================================================================
# STARTUP & SHUTDOWN
# ============================================================================

# ============================================================================
# ENHANCED COST TRACKING ENDPOINTS (God-Level LLM Cost Intelligence)
# ============================================================================

@app.post("/api/cost-tracker/track")
async def track_llm_cost(
    request_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    thinking_tokens: int = 0,
    session_id: Optional[str] = None,
    endpoint: Optional[str] = None,
    user_id: str = Depends(verify_token),
):
    """Track an LLM API call with multi-model cost calculation"""
    entry = enhanced_cost_tracker.track(
        request_id=request_id,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        thinking_tokens=thinking_tokens,
        session_id=session_id,
        endpoint=endpoint,
    )
    analytics_engine.log_event("cost.tracked", {
        "model": model, "cost": entry.cost_usd, "tokens": entry.usage.total_tokens,
    }, user_id=user_id)
    return {
        "request_id": entry.request_id,
        "model": entry.model,
        "cost_usd": entry.cost_usd,
        "tokens": {
            "prompt": entry.usage.prompt_tokens,
            "completion": entry.usage.completion_tokens,
            "thinking": entry.usage.thinking_tokens,
            "total": entry.usage.total_tokens,
        },
    }


@app.get("/api/cost-tracker/summary")
async def get_cost_summary(user_id: str = Depends(verify_token)):
    """Get comprehensive LLM cost summary"""
    return enhanced_cost_tracker.get_summary()


@app.get("/api/cost-tracker/models")
async def get_cost_by_model(user_id: str = Depends(verify_token)):
    """Get cost breakdown by model"""
    return {"models": enhanced_cost_tracker.get_model_breakdown()}


@app.get("/api/cost-tracker/utilization")
async def get_cost_utilization(user_id: str = Depends(verify_token)):
    """Get cost utilization across time windows (5h, 24h, 7d, 30d)"""
    return enhanced_cost_tracker.get_utilization()


@app.get("/api/cost-tracker/daily")
async def get_daily_costs(days: int = 30, user_id: str = Depends(verify_token)):
    """Get daily cost breakdown"""
    return {"daily": enhanced_cost_tracker.get_daily_breakdown(days)}


@app.get("/api/cost-tracker/anomalies")
async def get_cost_anomalies(user_id: str = Depends(verify_token)):
    """Get detected cost anomalies (spikes, budget warnings)"""
    return {"anomalies": enhanced_cost_tracker.get_anomalies()}


@app.post("/api/cost-tracker/budget")
async def set_cost_budget(
    window: str, budget_usd: float, user_id: str = Depends(verify_token),
):
    """Set budget for a utilization window"""
    success = enhanced_cost_tracker.set_window_budget(window, budget_usd)
    if not success:
        raise HTTPException(status_code=400, detail=f"Invalid window: {window}")
    return {"success": True, "window": window, "budget_usd": budget_usd}


# ============================================================================
# ADVANCED ANALYTICS ENDPOINTS (God-Level Intelligence)
# ============================================================================

@app.get("/api/analytics/comprehensive")
async def get_comprehensive_analytics(user_id: str = Depends(verify_token)):
    """Get comprehensive analytics (trends, heatmaps, risk, activity)"""
    return analytics_engine.get_comprehensive_analytics(user_id=user_id)


@app.get("/api/analytics/scan-trends")
async def get_scan_trends(days: int = 30, user_id: str = Depends(verify_token)):
    """Get scan volume and risk trends over time"""
    return analytics_engine.get_scan_trends(days=days)


@app.get("/api/analytics/risk-trend")
async def get_risk_trend(days: int = 30, user_id: str = Depends(verify_token)):
    """Get risk score trend over time"""
    return {"trend": analytics_engine.get_risk_trend(user_id=user_id, days=days)}


@app.get("/api/analytics/finding-heatmap")
async def get_finding_heatmap(user_id: str = Depends(verify_token)):
    """Get finding category x severity heatmap"""
    return analytics_engine.get_finding_heatmap()


@app.get("/api/analytics/endpoint-risk")
async def get_endpoint_risk(user_id: str = Depends(verify_token)):
    """Get risk distribution across API endpoints"""
    return {"endpoints": analytics_engine.get_endpoint_risk_distribution()}


@app.get("/api/analytics/activity-feed")
async def get_activity_feed(
    limit: int = 50,
    user_id: str = Depends(verify_token),
):
    """Get recent activity feed"""
    return {"activity": analytics_engine.get_activity_feed(user_id=user_id, limit=limit)}


# ============================================================================
# AI SECURITY ANALYSIS ENDPOINTS (OWASP Intelligence)
# ============================================================================

@app.post("/api/ai-security/analyze-collection/{collection_id}")
async def ai_analyze_collection(collection_id: str, user_id: str = Depends(verify_token)):
    """AI-powered OWASP Top 10 analysis of an API collection"""
    if collection_id not in collections_db:
        raise HTTPException(status_code=404, detail="Collection not found")
    collection = collections_db[collection_id]
    if collection.get("owner_id") and collection["owner_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = ai_security_analyzer.analyze_collection(collection.get("requests", []))
    analytics_engine.log_event("ai_analysis.completed", {
        "collection_id": collection_id,
        "findings": result["total_findings"],
        "risk_score": result["risk_score"],
    }, user_id=user_id)
    return result


@app.get("/api/ai-security/owasp-reference")
async def get_owasp_reference(user_id: str = Depends(verify_token)):
    """Get OWASP API Security Top 10 reference data"""
    return {"owasp_top_10": ai_security_analyzer.get_owasp_coverage_report()}


@app.post("/api/ai-security/remediation-plan")
async def get_remediation_plan(collection_id: str, user_id: str = Depends(verify_token)):
    """Generate a prioritized remediation plan for a collection"""
    if collection_id not in collections_db:
        raise HTTPException(status_code=404, detail="Collection not found")
    collection = collections_db[collection_id]
    if collection.get("owner_id") and collection["owner_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    analysis = ai_security_analyzer.analyze_collection(collection.get("requests", []))
    plan = ai_security_analyzer.get_remediation_plan(analysis["findings"])
    return {"remediation_plan": plan, "total_items": len(plan)}


# ============================================================================
# WEBHOOK INTEGRATION ENDPOINTS (Multi-Platform Notifications)
# ============================================================================

class WebhookCreateRequest(BaseModel):
    name: str
    platform: str  # slack, discord, teams, generic
    url: str
    events: List[str]


class WebhookUpdateRequest(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    events: Optional[List[str]] = None
    enabled: Optional[bool] = None


@app.post("/api/webhooks")
async def create_webhook(req: WebhookCreateRequest, user_id: str = Depends(verify_token)):
    """Register a webhook endpoint (Slack, Discord, Teams, or Generic)"""
    wh = webhook_service.register_webhook(
        user_id=user_id,
        name=req.name,
        platform=req.platform,
        url=req.url,
        events=req.events,
    )
    analytics_engine.log_event("webhook.created", {
        "platform": req.platform, "events": req.events,
    }, user_id=user_id)
    return {"success": True, "webhook_id": wh.webhook_id}


@app.get("/api/webhooks")
async def list_webhooks(user_id: str = Depends(verify_token)):
    """List all configured webhooks"""
    return {"webhooks": webhook_service.get_webhooks(user_id)}


@app.put("/api/webhooks/{webhook_id}")
async def update_webhook(
    webhook_id: str, req: WebhookUpdateRequest, user_id: str = Depends(verify_token),
):
    """Update a webhook configuration"""
    result = webhook_service.update_webhook(webhook_id, user_id, req.dict(exclude_none=True))
    if not result:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return result


@app.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user_id: str = Depends(verify_token)):
    """Delete a webhook"""
    if not webhook_service.delete_webhook(webhook_id, user_id):
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"success": True}


@app.get("/api/webhooks/events")
async def get_webhook_events(user_id: str = Depends(verify_token)):
    """Get list of supported webhook event types"""
    return {"events": webhook_service.get_supported_events()}


@app.get("/api/webhooks/platforms")
async def get_webhook_platforms(user_id: str = Depends(verify_token)):
    """Get list of supported webhook platforms"""
    return {"platforms": webhook_service.get_supported_platforms()}


@app.get("/api/webhooks/history")
async def get_webhook_history(user_id: str = Depends(verify_token)):
    """Get webhook delivery history"""
    return {"deliveries": webhook_service.get_delivery_history(user_id)}


@app.post("/api/webhooks/test/{webhook_id}")
async def test_webhook(webhook_id: str, user_id: str = Depends(verify_token)):
    """Send a test event to a webhook"""
    results = webhook_service.dispatch(
        event_type="scan.completed",
        data={"test": True, "risk_score": 42, "total_findings": 3, "collection_name": "Test Collection"},
        user_id=user_id,
    )
    return {"success": True, "deliveries": results}


# ============================================================================
# ENHANCED POLICY ENGINE ENDPOINTS (Granular Feature Control)
# ============================================================================

@app.get("/api/policy/check/{feature_id}")
async def check_policy(feature_id: str, user_id: str = Depends(verify_token)):
    """Check if user has access to a specific feature"""
    result = policy_engine.check_feature_access(user_id, feature_id)
    return result


@app.get("/api/policy/plans")
async def get_all_plans(user_id: str = Depends(verify_token)):
    """Get comparison of all plan tiers with features"""
    return {"plans": policy_engine.get_all_plans()}


@app.get("/api/policy/usage")
async def get_policy_usage(user_id: str = Depends(verify_token)):
    """Get usage summary for the current user"""
    return policy_engine.get_usage_summary(user_id)


@app.get("/api/policy/features/{tier}")
async def get_plan_features_detail(tier: str, user_id: str = Depends(verify_token)):
    """Get all features available for a plan tier"""
    return policy_engine.get_plan_features(tier)


# ============================================================================
# SCAN SESSION HISTORY ENDPOINTS (Scan Memory & Comparison)
# ============================================================================

@app.get("/api/scan-sessions")
async def get_scan_sessions(
    collection_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    user_id: str = Depends(verify_token),
):
    """Get scan session history"""
    return {
        "sessions": scan_session_history.get_user_history(
            user_id=user_id, limit=limit, collection_id=collection_id, status=status,
        )
    }


@app.get("/api/scan-sessions/{session_id}")
async def get_scan_session(session_id: str, user_id: str = Depends(verify_token)):
    """Get details of a specific scan session"""
    session = scan_session_history.get_session(session_id, user_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.post("/api/scan-sessions/{session_id}/notes")
async def add_scan_note(session_id: str, note: str, user_id: str = Depends(verify_token)):
    """Add a note to a scan session"""
    if not scan_session_history.add_note(session_id, note):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"success": True}


@app.post("/api/scan-sessions/compare")
async def compare_scan_sessions(
    baseline_session_id: str,
    compare_session_id: str,
    user_id: str = Depends(verify_token),
):
    """Compare two scan sessions (diff)"""
    result = scan_session_history.compare_sessions(
        baseline_session_id, compare_session_id, user_id,
    )
    if not result:
        raise HTTPException(status_code=404, detail="One or both sessions not found")
    return result


@app.get("/api/scan-sessions/stats")
async def get_scan_stats(user_id: str = Depends(verify_token)):
    """Get overall scan statistics"""
    return scan_session_history.get_user_stats(user_id)


# ============================================================================
# STARTUP & SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup_event():
    print("DevPulse API starting up...")
    print("Services initialized:")
    print("  - Postman Parser")
    print("  - Risk Score Engine")
    print("  - Kill Switch")
    print("  - Shadow API Scanner")
    print("  - PCI DSS Generator")
    print("  - Thinking Token Tracker")
    print("  - Enhanced Cost Tracker (Multi-Model)")
    print("  - Advanced Analytics Engine")
    print("  - AI Security Analyzer (OWASP Top 10)")
    print("  - Webhook Integration Service (Slack/Discord/Teams)")
    print("  - Enhanced Policy Engine")
    print("  - Scan Session History")


@app.on_event("shutdown")
async def shutdown_event():
    print("DevPulse API shutting down...")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
