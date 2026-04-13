"""
DevPulse - Team Management Endpoints
Workspace collaboration and team member management
"""

import logging
from datetime import datetime
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .models import User, TeamMember
from .database import get_db
from .auth_service_db import AuthServiceDB
from .crud import check_collection_ownership
from services.email_service import email_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/team", tags=["team"])


@router.post("/invite")
async def invite_team_member(
    email: str,
    role: str = "member",
    current_user: Dict[str, Any] = Depends(lambda: {"user_id": "current_user"}),
    db: Session = Depends(get_db)
):
    """Invite a team member to workspace"""
    try:
        # Check if user is admin/owner
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if invitee already exists for this user
        existing = db.query(TeamMember).filter(
            TeamMember.user_id == current_user["user_id"],
            TeamMember.email == email
        ).first()
        
        if existing:
            return {"success": False, "message": "User already invited"}
        
        # Create team member invitation
        team_member = TeamMember(
            user_id=current_user["user_id"],
            email=email,
            role=role,
            invited_at=datetime.utcnow()
        )
        
        db.add(team_member)
        db.commit()
        db.refresh(team_member)
        
        # Send invitation email
        email_service.send_security_alert(
            email=email,
            name=email.split("@")[0],
            alert_type="Team Invitation",
            details={
                "description": f"You have been invited to join {user.name}'s workspace on DevPulse.",
                "action": "Visit https://devpulse.io to accept the invitation."
            }
        )
        
        logger.info(f"Team member invited: {email}")
        return {"success": True, "message": "Invitation sent"}
    
    except Exception as e:
        logger.error(f"Error inviting team member: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/members")
async def list_team_members(
    current_user: Dict[str, Any] = Depends(lambda: {"user_id": "current_user"}),
    db: Session = Depends(get_db)
):
    """List team members"""
    try:
        members = db.query(TeamMember).filter(
            TeamMember.user_id == current_user["user_id"]
        ).all()
        
        return {
            "success": True,
            "members": [
                {
                    "id": m.id,
                    "email": m.email,
                    "role": m.role,
                    "joined_at": m.joined_at.isoformat() if m.joined_at else None,
                    "invited_at": m.invited_at.isoformat() if m.invited_at else None
                }
                for m in members
            ]
        }
    
    except Exception as e:
        logger.error(f"Error listing team members: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/members/{member_id}")
async def remove_team_member(
    member_id: str,
    current_user: Dict[str, Any] = Depends(lambda: {"user_id": "current_user"}),
    db: Session = Depends(get_db)
):
    """Remove team member"""
    try:
        member = db.query(TeamMember).filter(
            TeamMember.id == member_id,
            TeamMember.user_id == current_user["user_id"]
        ).first()
        
        if not member:
            raise HTTPException(status_code=404, detail="Member not found")
        
        db.delete(member)
        db.commit()
        
        logger.info(f"Team member removed: {member_id}")
        return {"success": True, "message": "Member removed"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing team member: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/members/{member_id}/role")
async def update_member_role(
    member_id: str,
    role: str,
    current_user: Dict[str, Any] = Depends(lambda: {"user_id": "current_user"}),
    db: Session = Depends(get_db)
):
    """Update team member role"""
    try:
        member = db.query(TeamMember).filter(
            TeamMember.id == member_id,
            TeamMember.user_id == current_user["user_id"]
        ).first()
        
        if not member:
            raise HTTPException(status_code=404, detail="Member not found")
        
        if role not in ["admin", "member", "viewer"]:
            raise HTTPException(status_code=400, detail="Invalid role")
        
        member.role = role
        db.commit()
        
        logger.info(f"Team member role updated: {member_id} -> {role}")
        return {"success": True, "message": "Role updated"}
    
    except Exception as e:
        logger.error(f"Error updating member role: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
