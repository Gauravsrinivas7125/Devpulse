"""
DevPulse - Usage Counter System
Track and enforce usage limits
"""

from typing import Any, Dict, Optional
from datetime import datetime, timedelta
from enum import Enum
import json
import threading  # SECURITY: Add thread-safe locking


class PlanType(Enum):
    """Subscription plan types"""
    FREE = "free"
    PRO = "pro"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class PlanLimits:
    """Usage limits per plan"""
    
    LIMITS = {
        PlanType.FREE: {
            "requests_per_month": 1000,
            "collections": 5,
            "team_members": 1,
            "api_calls": 10000,
            "storage_gb": 1,
        },
        PlanType.PRO: {
            "requests_per_month": 50000,
            "collections": 50,
            "team_members": 5,
            "api_calls": 500000,
            "storage_gb": 100,
        },
        PlanType.TEAM: {
            "requests_per_month": 500000,
            "collections": 500,
            "team_members": 50,
            "api_calls": 5000000,
            "storage_gb": 1000,
        },
        PlanType.ENTERPRISE: {
            "requests_per_month": float('inf'),
            "collections": float('inf'),
            "team_members": float('inf'),
            "api_calls": float('inf'),
            "storage_gb": float('inf'),
        },
    }
    
    @classmethod
    def get_limit(cls, plan: PlanType, metric: str) -> float:
        """Get limit for a metric"""
        return cls.LIMITS.get(plan, {}).get(metric, 0)


class RedisClient:
    """Simulated Redis client for atomic operations"""
    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()
    
    def incr(self, key: str, amount: int = 1) -> int:
        with self._lock:
            val = self._data.get(key, 0) + amount
            self._data[key] = val
            return val
    
    def get(self, key: str) -> int:
        with self._lock:
            return self._data.get(key, 0)
    
    def check_and_incr(self, key: str, amount: int, limit: float) -> tuple:
        """Atomic check-and-increment: returns (allowed: bool, new_value: int)"""
        with self._lock:
            current = self._data.get(key, 0)
            if current + amount > limit and limit != float('inf'):
                return False, current
            new_val = current + amount
            self._data[key] = new_val
            return True, new_val

# SECURITY: Global Redis simulator
redis = RedisClient()

class UsageCounter:
    """Track usage for a user/organization"""
    
    def __init__(self, user_id: str, plan: PlanType = PlanType.FREE):
        self.user_id = user_id
        self.plan = plan
        self.current_month_start = self._get_month_start()
        self.usage: Dict[str, int] = {
            "requests_per_month": 0,  # renamed from 'requests_this_month' to match PlanLimits key
            "collections": 0,
            "team_members": 1,
            "api_calls": 0,
            "storage_gb": 0,  # renamed from 'storage_bytes' to match PlanLimits key
        }
        self.last_reset = datetime.utcnow()
    
    def _get_month_start(self) -> datetime:
        """Get start of current month"""
        now = datetime.utcnow()
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    def _check_month_reset(self):
        """Reset monthly counters if needed"""
        current_month_start = self._get_month_start()
        if current_month_start > self.current_month_start:
            self.current_month_start = current_month_start
            self.usage["requests_per_month"] = 0
            self.last_reset = datetime.utcnow()
    
    def increment(self, metric: str, amount: int = 1) -> bool:
        """
        Increment usage counter (atomic using Redis-style INCR)
        
        Returns:
            True if increment was allowed, False if limit exceeded
        """
        self._check_month_reset()
        
        # SECURITY: Atomic check-and-increment inside RedisClient lock
        key = f"usage:{self.user_id}:{metric}"
        limit = PlanLimits.get_limit(self.plan, metric)
        
        allowed, new_val = redis.check_and_incr(key, amount, limit)
        if not allowed:
            return False
        
        self.usage[metric] = new_val
        return True
    
    def get_usage(self) -> Dict[str, Any]:
        """Get current usage"""
        self._check_month_reset()
        
        result = {}
        for metric, current in self.usage.items():
            limit = PlanLimits.get_limit(self.plan, metric)
            remaining = max(0, limit - current) if limit not in (float('inf'), 0) else (float('inf') if limit == float('inf') else 0)
            percentage = (current / limit * 100) if (limit not in (float('inf'), 0)) else 0
            
            result[metric] = {
                "current": current,
                "limit": limit,
                "remaining": remaining,
                "percentage_used": percentage,
            }
        
        return result
    
    def is_limit_exceeded(self, metric: str) -> bool:
        """Check if limit is exceeded"""
        self._check_month_reset()
        limit = PlanLimits.get_limit(self.plan, metric)
        current = self.usage.get(metric, 0)
        return current >= limit and limit != float('inf')
    
    def get_status(self) -> Dict[str, Any]:
        """Get usage status"""
        self._check_month_reset()
        
        status = {
            "user_id": self.user_id,
            "plan": self.plan.value,
            "month_start": self.current_month_start.isoformat(),
            "usage": self.get_usage(),
            "warnings": [],
            "errors": [],
        }
        
        # Check for warnings (80%+ of limit)
        for metric, usage in status["usage"].items():
            if usage["limit"] != float('inf'):
                percentage = usage["percentage_used"]
                if percentage >= 80:
                    status["warnings"].append(f"{metric}: {percentage:.1f}% of limit used")
                if percentage >= 100:
                    status["errors"].append(f"{metric}: Limit exceeded!")
        
        return status
    
    def to_dict(self) -> Dict:
        """Serialize to dict"""
        return {
            "user_id": self.user_id,
            "plan": self.plan.value,
            "usage": self.usage,
            "current_month_start": self.current_month_start.isoformat(),
            "last_reset": self.last_reset.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'UsageCounter':
        """Deserialize from dict"""
        counter = cls(
            user_id=data["user_id"],
            plan=PlanType(data.get("plan", "free"))
        )
        counter.usage = data.get("usage", counter.usage)
        counter.current_month_start = datetime.fromisoformat(data["current_month_start"])
        counter.last_reset = datetime.fromisoformat(data["last_reset"])
        return counter


class UsageCounterManager:
    """Manage usage counters for multiple users"""
    
    def __init__(self):
        self.counters: Dict[str, UsageCounter] = {}
    
    def get_or_create(self, user_id: str, plan: PlanType = PlanType.FREE) -> UsageCounter:
        """Get or create counter for user"""
        if user_id not in self.counters:
            self.counters[user_id] = UsageCounter(user_id, plan)
        return self.counters[user_id]
    
    def increment(self, user_id: str, metric: str, amount: int = 1) -> bool:
        """Increment usage for user"""
        counter = self.get_or_create(user_id)
        return counter.increment(metric, amount)
    
    def get_usage(self, user_id: str) -> Dict:
        """Get usage for user"""
        counter = self.get_or_create(user_id)
        return counter.get_usage()
    
    def upgrade_plan(self, user_id: str, new_plan: PlanType):
        """Upgrade user plan"""
        counter = self.get_or_create(user_id)
        counter.plan = new_plan
    
    def check_limit(self, user_id: str, metric: str) -> bool:
        """Check if user has exceeded limit"""
        counter = self.get_or_create(user_id)
        return counter.is_limit_exceeded(metric)


# Global manager instance
usage_manager = UsageCounterManager()


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Create counter for user
    counter = UsageCounter("user_123", PlanType.FREE)
    
    # Increment requests
    print("Incrementing requests...")
    for i in range(5):
        success = counter.increment("requests_per_month")
        print(f"  Request {i+1}: {'✓' if success else '✗ (limit exceeded)'}")
    
    # Get usage
    print("\nCurrent usage:")
    usage = counter.get_usage()
    for metric, data in usage.items():
        print(f"  {metric}: {data['current']}/{data['limit']} ({data['percentage_used']:.1f}%)")
    
    # Get status
    print("\nStatus:")
    status = counter.get_status()
    print(f"  Plan: {status['plan']}")
    print(f"  Warnings: {len(status['warnings'])}")
    print(f"  Errors: {len(status['errors'])}")
    
    # Test upgrade
    print("\nUpgrading to PRO...")
    manager = UsageCounterManager()
    manager.upgrade_plan("user_123", PlanType.PRO)
    upgraded_counter = manager.get_or_create("user_123", PlanType.PRO)
    usage = upgraded_counter.get_usage()
    print(f"  New limit: {usage['requests_per_month']['limit']}")
