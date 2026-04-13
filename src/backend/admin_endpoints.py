"""
DevPulse - Admin API Endpoints
Endpoints for the admin dashboard to fetch metrics and system data
"""

import logging
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta

from .models import User, Collection, Scan, AuditLog
from .database import get_db
from .auth import verify_admin  # shared auth module

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/stats")
async def get_admin_stats(
    db: Session = Depends(get_db),
    admin: User = Depends(verify_admin)
) -> Dict[str, Any]:
    """Get system statistics"""
    try:
        # User stats
        total_users = db.query(func.count(User.id)).scalar() or 0
        users_free = db.query(func.count(User.id)).filter(User.plan == "free").scalar() or 0
        users_pro = db.query(func.count(User.id)).filter(User.plan == "pro").scalar() or 0
        users_enterprise = db.query(func.count(User.id)).filter(User.plan == "enterprise").scalar() or 0

        # Collection stats
        total_collections = db.query(func.count(Collection.id)).scalar() or 0

        # Scan stats
        total_scans = db.query(func.count(Scan.id)).scalar() or 0
        active_scans = db.query(func.count(Scan.id)).filter(Scan.status == "running").scalar() or 0

        # Revenue (MRR)
        mrr = (users_pro * 29) + (users_enterprise * 99)

        # Scans per day (last 7 days)
        scans_per_day = []
        for i in range(7):
            date = datetime.utcnow() - timedelta(days=6-i)
            count = db.query(func.count(Scan.id)).filter(
                Scan.created_at >= date,
                Scan.created_at < date + timedelta(days=1)
            ).scalar() or 0
            scans_per_day.append(count)

        return {
            "total_users": total_users,
            "users_free": users_free,
            "users_pro": users_pro,
            "users_enterprise": users_enterprise,
            "total_collections": total_collections,
            "total_scans": total_scans,
            "active_scans": active_scans,
            "mrr": mrr,
            "scans_per_day": scans_per_day,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting admin stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users")
async def get_users(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(verify_admin)
) -> Dict[str, Any]:
    """Get list of users"""
    try:
        users = db.query(User).order_by(User.created_at.desc()).offset(offset).limit(limit).all()
        total = db.query(func.count(User.id)).scalar() or 0

        recent_users = [
            {
                "id": u.id,
                "email": u.email,
                "name": u.name,
                "plan": u.plan,
                "email_verified": u.email_verified,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "last_login": u.last_login.isoformat() if u.last_login else None
            }
            for u in users
        ]

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "recent_users": recent_users
        }
    
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/collections")
async def get_collections(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(verify_admin)
) -> Dict[str, Any]:
    """Get list of collections"""
    try:
        collections = db.query(Collection).order_by(Collection.created_at.desc()).offset(offset).limit(limit).all()
        total = db.query(func.count(Collection.id)).scalar() or 0

        collection_list = [
            {
                "id": c.id,
                "user_id": c.user_id,
                "name": c.name,
                "format": c.format,
                "total_requests": c.total_requests,
                "created_at": c.created_at.isoformat() if c.created_at else None
            }
            for c in collections
        ]

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "collections": collection_list
        }
    
    except Exception as e:
        logger.error(f"Error getting collections: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans")
async def get_scans(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(verify_admin)
) -> Dict[str, Any]:
    """Get list of scans"""
    try:
        scans = db.query(Scan).order_by(Scan.started_at.desc()).offset(offset).limit(limit).all()
        total = db.query(func.count(Scan.id)).scalar() or 0

        scan_list = [
            {
                "id": s.id,
                "collection_id": s.collection_id,
                "collection_name": db.query(Collection.name).filter(Collection.id == s.collection_id).scalar() or "Unknown",
                "status": s.status,
                "risk_score": s.risk_score or 0,
                "total_findings": s.total_findings,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None
            }
            for s in scans
        ]

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "recent_scans": scan_list
        }
    
    except Exception as e:
        logger.error(f"Error getting scans: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(verify_admin)
) -> Dict[str, Any]:
    """Get audit logs"""
    try:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
        total = db.query(func.count(AuditLog.id)).scalar() or 0

        log_list = [
            {
                "id": l.id,
                "user_id": l.user_id,
                "user_email": db.query(User.email).filter(User.id == l.user_id).scalar() or "Unknown",
                "action": l.action,
                "resource_type": l.resource_type,
                "resource_id": l.resource_id,
                "ip_address": l.ip_address,
                "created_at": l.created_at.isoformat() if l.created_at else None
            }
            for l in logs
        ]

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "logs": log_list
        }
    
    except Exception as e:
        logger.error(f"Error getting audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def admin_health(
    db: Session = Depends(get_db),
    admin: User = Depends(verify_admin)
) -> Dict[str, Any]:
    """Get system health status"""
    try:
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": 0  # Would be calculated from app start time
        }
    
    except Exception as e:
        logger.error(f"Error getting health: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users/{user_id}/disable")
async def disable_user(
    user_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(verify_admin)
) -> Dict[str, Any]:
    """Disable a user account"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.email_verified = False
        db.commit()

        logger.warning(f"User disabled by admin: {user_id}")
        return {"success": True, "message": "User disabled"}
    
    except Exception as e:
        logger.error(f"Error disabling user: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users/{user_id}/upgrade")
async def upgrade_user_plan(
    user_id: str,
    plan: str,
    db: Session = Depends(get_db),
    admin: User = Depends(verify_admin)
) -> Dict[str, Any]:
    """Upgrade user plan"""
    try:
        if plan not in ["free", "pro", "enterprise"]:
            raise HTTPException(status_code=400, detail="Invalid plan")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.plan = plan
        db.commit()

        logger.info(f"User plan upgraded by admin: {user_id} -> {plan}")
        return {"success": True, "message": f"User upgraded to {plan}"}
    
    except Exception as e:
        logger.error(f"Error upgrading user: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
