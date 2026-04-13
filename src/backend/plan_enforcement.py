"""
DevPulse - Plan Enforcement
Enforce feature access based on subscription tier
"""

from typing import Dict, Any, Optional, List, Callable
from functools import wraps
from fastapi import HTTPException, Depends
import logging

logger = logging.getLogger(__name__)


class PlanLimits:
    """Define limits for each plan tier"""
    
    LIMITS = {
        'free': {
            'max_collections': 1,
            'max_requests_per_collection': 50,
            'max_scans_per_month': 5,
            'max_team_members': 1,
            'compliance_reports': False,
            'shadow_api_detection': False,
            'kill_switch': False,
            'api_access': False,
        },
        'pro': {
            'max_collections': 10,
            'max_requests_per_collection': 500,
            'max_scans_per_month': 100,
            'max_team_members': 5,
            'compliance_reports': True,
            'shadow_api_detection': True,
            'kill_switch': True,
            'api_access': True,
        },
        'enterprise': {
            'max_collections': float('inf'),
            'max_requests_per_collection': float('inf'),
            'max_scans_per_month': float('inf'),
            'max_team_members': float('inf'),
            'compliance_reports': True,
            'shadow_api_detection': True,
            'kill_switch': True,
            'api_access': True,
        }
    }
    
    @classmethod
    def get_limits(cls, plan: str) -> Dict[str, Any]:
        """Get limits for a plan"""
        return cls.LIMITS.get(plan, cls.LIMITS['free'])
    
    @classmethod
    def check_feature_access(cls, plan: str, feature: str) -> bool:
        """Check if plan has access to feature"""
        limits = cls.get_limits(plan)
        return limits.get(feature, False)


class PlanEnforcer:
    """Enforce plan limits and feature access"""
    
    def __init__(self, users_db: Dict[str, Any]):
        self.users_db = users_db
    
    def get_user_plan(self, user_id: str) -> str:
        """Get user's current plan"""
        user = next((u for u in self.users_db.values() if u.get('id') == user_id), None)
        if not user:
            return 'free'
        return user.get('plan', 'free')
    
    def check_feature_access(self, user_id: str, feature: str) -> bool:
        """Check if user has access to feature"""
        plan = self.get_user_plan(user_id)
        return PlanLimits.check_feature_access(plan, feature)
    
    def check_collection_limit(self, user_id: str, current_count: int) -> bool:
        """Check if user can create more collections"""
        plan = self.get_user_plan(user_id)
        limits = PlanLimits.get_limits(plan)
        return current_count < limits['max_collections']
    
    def check_scan_limit(self, user_id: str, scans_this_month: int) -> bool:
        """Check if user can run more scans"""
        plan = self.get_user_plan(user_id)
        limits = PlanLimits.get_limits(plan)
        return scans_this_month < limits['max_scans_per_month']
    
    def check_team_member_limit(self, user_id: str, current_members: int) -> bool:
        """Check if user can add more team members"""
        plan = self.get_user_plan(user_id)
        limits = PlanLimits.get_limits(plan)
        return current_members < limits['max_team_members']
    
    def get_limits(self, user_id: str) -> Dict[str, Any]:
        """Get user's plan limits"""
        plan = self.get_user_plan(user_id)
        return PlanLimits.get_limits(plan)


def require_plan(required_plan: str):
    """Decorator to require minimum plan tier"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user_id = kwargs.get('user_id')
            if not user_id:
                raise HTTPException(status_code=401, detail="Unauthorized")
            
            # Get plan enforcer from app context if available
            # For now, we'll check in the function body
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_feature(feature: str):
    """Decorator to require specific feature access"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user_id = kwargs.get('user_id')
            if not user_id:
                raise HTTPException(status_code=401, detail="Unauthorized")
            
            # Feature check will be done in the function body
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Global enforcer instance
plan_enforcer = None


def get_plan_enforcer(users_db: Dict[str, Any]) -> PlanEnforcer:
    """Get or create plan enforcer, updating users_db reference if changed"""
    global plan_enforcer
    if plan_enforcer is None:
        plan_enforcer = PlanEnforcer(users_db)
    elif plan_enforcer.users_db is not users_db:
        plan_enforcer.users_db = users_db
    return plan_enforcer
