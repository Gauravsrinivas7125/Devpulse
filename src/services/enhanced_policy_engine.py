"""
DevPulse Enhanced Policy Enforcement Engine
Inspired by Claude Code's policyLimits service patterns.
Feature-level granular controls with caching, background refresh,
and fail-open/fail-closed semantics.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
import threading
import hashlib
import json


class FailMode(str, Enum):
    OPEN = "fail_open"    # Allow access on policy check failure
    CLOSED = "fail_closed"  # Deny access on policy check failure


class PlanTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass
class FeaturePolicy:
    feature_id: str
    name: str
    description: str
    allowed_tiers: List[PlanTier]
    usage_limit: Optional[int] = None  # None = unlimited
    rate_limit_per_minute: Optional[int] = None
    fail_mode: FailMode = FailMode.CLOSED
    requires_mfa: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyCache:
    policies: Dict[str, FeaturePolicy]
    checksum: str
    fetched_at: datetime
    ttl_seconds: int = 300  # 5-minute cache


@dataclass
class UsageRecord:
    user_id: str
    feature_id: str
    count: int = 0
    window_start: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    window_seconds: int = 86400  # 24h default


# Default feature policies per plan tier
DEFAULT_POLICIES: List[FeaturePolicy] = [
    FeaturePolicy(
        feature_id="scan.run",
        name="Run Security Scan",
        description="Execute API security scans on collections",
        allowed_tiers=[PlanTier.FREE, PlanTier.PRO, PlanTier.ENTERPRISE],
        usage_limit=None,  # Overridden per tier below
        fail_mode=FailMode.CLOSED,
    ),
    FeaturePolicy(
        feature_id="scan.ai_analysis",
        name="AI-Powered Analysis",
        description="Use AI to analyze scan results with OWASP patterns",
        allowed_tiers=[PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
    ),
    FeaturePolicy(
        feature_id="scan.export",
        name="Export Scan Results",
        description="Export scan results to PDF/CSV/JSON",
        allowed_tiers=[PlanTier.FREE, PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.OPEN,
    ),
    FeaturePolicy(
        feature_id="compliance.generate",
        name="Generate Compliance Reports",
        description="Generate PCI DSS, SOC 2, HIPAA compliance reports",
        allowed_tiers=[PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
    ),
    FeaturePolicy(
        feature_id="compliance.pci",
        name="PCI DSS Compliance",
        description="PCI DSS specific compliance scanning and reporting",
        allowed_tiers=[PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
    ),
    FeaturePolicy(
        feature_id="webhook.manage",
        name="Webhook Integrations",
        description="Configure webhook notifications (Slack, Discord, Teams)",
        allowed_tiers=[PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
    ),
    FeaturePolicy(
        feature_id="analytics.advanced",
        name="Advanced Analytics",
        description="Access trend analysis, heatmaps, and cost intelligence",
        allowed_tiers=[PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
    ),
    FeaturePolicy(
        feature_id="analytics.cost_tracking",
        name="LLM Cost Tracking",
        description="Track and analyze LLM API costs across models",
        allowed_tiers=[PlanTier.FREE, PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.OPEN,
    ),
    FeaturePolicy(
        feature_id="killswitch.manage",
        name="Kill Switch",
        description="Emergency kill switch for API endpoints",
        allowed_tiers=[PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
    ),
    FeaturePolicy(
        feature_id="shadow_api.detect",
        name="Shadow API Detection",
        description="Detect and monitor undocumented shadow APIs",
        allowed_tiers=[PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
    ),
    FeaturePolicy(
        feature_id="team.manage",
        name="Team Management",
        description="Invite team members and manage roles",
        allowed_tiers=[PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
    ),
    FeaturePolicy(
        feature_id="admin.dashboard",
        name="Admin Dashboard",
        description="Access admin dashboard with user management and metrics",
        allowed_tiers=[PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
        requires_mfa=True,
    ),
    FeaturePolicy(
        feature_id="api.rate_limit",
        name="API Rate Limit Override",
        description="Higher API rate limits",
        allowed_tiers=[PlanTier.PRO, PlanTier.ENTERPRISE],
        rate_limit_per_minute=100,
        fail_mode=FailMode.OPEN,
    ),
    FeaturePolicy(
        feature_id="scan.session_history",
        name="Scan Session History",
        description="View and compare historical scan sessions",
        allowed_tiers=[PlanTier.PRO, PlanTier.ENTERPRISE],
        fail_mode=FailMode.CLOSED,
    ),
]

# Per-tier usage limits
TIER_LIMITS: Dict[str, Dict[str, int]] = {
    PlanTier.FREE: {
        "scan.run": 5,            # 5 scans per day
        "collections": 3,         # 3 collections max
        "team_members": 1,        # Solo only
        "scan.export": 2,         # 2 exports per day
        "api_calls_per_min": 10,
    },
    PlanTier.PRO: {
        "scan.run": 100,          # 100 scans per day
        "collections": 50,        # 50 collections
        "team_members": 10,       # Up to 10 members
        "scan.export": 50,        # 50 exports per day
        "compliance.generate": 20,
        "api_calls_per_min": 100,
    },
    PlanTier.ENTERPRISE: {
        "scan.run": -1,           # Unlimited (-1)
        "collections": -1,
        "team_members": -1,
        "scan.export": -1,
        "compliance.generate": -1,
        "api_calls_per_min": 1000,
    },
}


class EnhancedPolicyEngine:
    """
    Feature-level policy enforcement with caching,
    granular controls, and fail-open/fail-closed semantics.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._policies: Dict[str, FeaturePolicy] = {p.feature_id: p for p in DEFAULT_POLICIES}
        self._usage: Dict[str, UsageRecord] = {}  # key: f"{user_id}:{feature_id}"
        self._rate_limits: Dict[str, List[float]] = {}  # key: f"{user_id}:{feature_id}", val: timestamps
        self._cache: Optional[PolicyCache] = None
        self._user_tiers: Dict[str, PlanTier] = {}
        self._build_cache()

    def _build_cache(self) -> None:
        """Build policy cache with checksum."""
        policy_data = json.dumps(
            {k: v.feature_id for k, v in sorted(self._policies.items())},
            sort_keys=True,
        )
        checksum = hashlib.sha256(policy_data.encode()).hexdigest()[:16]
        self._cache = PolicyCache(
            policies=dict(self._policies),
            checksum=checksum,
            fetched_at=datetime.utcnow(),
        )

    def set_user_tier(self, user_id: str, tier: str) -> None:
        """Set or update a user's plan tier."""
        with self._lock:
            self._user_tiers[user_id] = PlanTier(tier)

    def get_user_tier(self, user_id: str) -> PlanTier:
        """Get a user's plan tier (default: FREE)."""
        return self._user_tiers.get(user_id, PlanTier.FREE)

    # -----------------------------------------------------------------------
    # Policy Checks
    # -----------------------------------------------------------------------

    def check_feature_access(self, user_id: str, feature_id: str) -> Dict:
        """
        Check if a user has access to a feature.
        Returns access decision with reason.
        """
        with self._lock:
            policy = self._policies.get(feature_id)
            if not policy:
                return {"allowed": True, "reason": "no_policy_defined"}

            user_tier = self.get_user_tier(user_id)

            # Tier check
            if user_tier not in policy.allowed_tiers:
                if policy.fail_mode == FailMode.OPEN:
                    return {
                        "allowed": True,
                        "reason": "fail_open",
                        "warning": f"Feature '{feature_id}' requires {[t.value for t in policy.allowed_tiers]} tier",
                    }
                return {
                    "allowed": False,
                    "reason": "tier_restricted",
                    "required_tier": [t.value for t in policy.allowed_tiers],
                    "current_tier": user_tier.value,
                    "upgrade_message": f"Upgrade to {policy.allowed_tiers[0].value} to access {policy.name}",
                }

            # Usage limit check
            tier_limits = TIER_LIMITS.get(user_tier, {})
            limit = tier_limits.get(feature_id)
            if limit is not None and limit != -1:
                usage_key = f"{user_id}:{feature_id}"
                usage = self._usage.get(usage_key)
                if usage:
                    # Check if window expired
                    window_start = datetime.fromisoformat(usage.window_start)
                    if datetime.utcnow() - window_start > timedelta(seconds=usage.window_seconds):
                        usage.count = 0
                        usage.window_start = datetime.utcnow().isoformat()
                    if usage.count >= limit:
                        return {
                            "allowed": False,
                            "reason": "usage_limit_exceeded",
                            "limit": limit,
                            "used": usage.count,
                            "resets_at": (window_start + timedelta(seconds=usage.window_seconds)).isoformat(),
                        }

            # Rate limit check
            if policy.rate_limit_per_minute:
                rate_key = f"{user_id}:{feature_id}"
                now = datetime.utcnow().timestamp()
                if rate_key not in self._rate_limits:
                    self._rate_limits[rate_key] = []
                # Prune old entries (older than 1 minute)
                self._rate_limits[rate_key] = [
                    ts for ts in self._rate_limits[rate_key]
                    if now - ts < 60
                ]
                if len(self._rate_limits[rate_key]) >= policy.rate_limit_per_minute:
                    return {
                        "allowed": False,
                        "reason": "rate_limited",
                        "limit_per_minute": policy.rate_limit_per_minute,
                        "current_rate": len(self._rate_limits[rate_key]),
                    }

            return {"allowed": True, "reason": "policy_passed", "tier": user_tier.value}

    def record_usage(self, user_id: str, feature_id: str) -> Dict:
        """Record a feature usage. Call after successful feature access."""
        with self._lock:
            usage_key = f"{user_id}:{feature_id}"
            if usage_key not in self._usage:
                self._usage[usage_key] = UsageRecord(
                    user_id=user_id,
                    feature_id=feature_id,
                )
            usage = self._usage[usage_key]

            # Reset if window expired
            window_start = datetime.fromisoformat(usage.window_start)
            if datetime.utcnow() - window_start > timedelta(seconds=usage.window_seconds):
                usage.count = 0
                usage.window_start = datetime.utcnow().isoformat()

            usage.count += 1

            # Record rate limit timestamp
            rate_key = f"{user_id}:{feature_id}"
            if rate_key not in self._rate_limits:
                self._rate_limits[rate_key] = []
            self._rate_limits[rate_key].append(datetime.utcnow().timestamp())

            user_tier = self.get_user_tier(user_id)
            tier_limits = TIER_LIMITS.get(user_tier, {})
            limit = tier_limits.get(feature_id, -1)

            return {
                "feature_id": feature_id,
                "used": usage.count,
                "limit": limit if limit != -1 else "unlimited",
                "remaining": max(0, limit - usage.count) if limit != -1 else "unlimited",
            }

    # -----------------------------------------------------------------------
    # Plan Information
    # -----------------------------------------------------------------------

    def get_plan_features(self, tier: str) -> Dict:
        """Get all features available for a plan tier."""
        plan_tier = PlanTier(tier)
        features = []
        for policy in self._policies.values():
            features.append({
                "feature_id": policy.feature_id,
                "name": policy.name,
                "description": policy.description,
                "available": plan_tier in policy.allowed_tiers,
                "requires_mfa": policy.requires_mfa,
                "usage_limit": TIER_LIMITS.get(plan_tier, {}).get(policy.feature_id, "N/A"),
            })
        return {
            "tier": tier,
            "features": features,
            "limits": TIER_LIMITS.get(plan_tier, {}),
        }

    def get_all_plans(self) -> List[Dict]:
        """Get comparison of all plan tiers."""
        plans = []
        for tier in PlanTier:
            plan_data = self.get_plan_features(tier.value)
            available_count = sum(1 for f in plan_data["features"] if f["available"])
            plans.append({
                "tier": tier.value,
                "feature_count": available_count,
                "total_features": len(plan_data["features"]),
                "limits": plan_data["limits"],
                "features": plan_data["features"],
            })
        return plans

    def get_usage_summary(self, user_id: str) -> Dict:
        """Get usage summary for a user across all features."""
        with self._lock:
            user_tier = self.get_user_tier(user_id)
            tier_limits = TIER_LIMITS.get(user_tier, {})
            usage_data = []

            for feature_id in tier_limits:
                usage_key = f"{user_id}:{feature_id}"
                usage = self._usage.get(usage_key)
                limit = tier_limits[feature_id]
                count = usage.count if usage else 0

                usage_data.append({
                    "feature_id": feature_id,
                    "used": count,
                    "limit": limit if limit != -1 else "unlimited",
                    "utilization_pct": round(count / limit * 100, 1) if limit > 0 else 0,
                })

            return {
                "user_id": user_id,
                "tier": user_tier.value,
                "usage": usage_data,
            }

    def get_policy_cache_info(self) -> Dict:
        """Get cache info for diagnostics."""
        if not self._cache:
            return {"cached": False}
        return {
            "cached": True,
            "checksum": self._cache.checksum,
            "fetched_at": self._cache.fetched_at.isoformat(),
            "ttl_seconds": self._cache.ttl_seconds,
            "policy_count": len(self._cache.policies),
            "is_stale": (datetime.utcnow() - self._cache.fetched_at).total_seconds() > self._cache.ttl_seconds,
        }


# Global instance
policy_engine = EnhancedPolicyEngine()
