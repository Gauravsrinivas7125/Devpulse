"""
DevPulse - Admin Dashboard Service
Track signups, downloads, premium plans, and revenue
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import json


class SubscriptionPlan(str, Enum):
    """Subscription plans"""
    FREE = "free"
    PRO = "pro"
    TEAM = "team"
    ENTERPRISE = "enterprise"


@dataclass
class SignupEvent:
    """User signup event"""
    user_id: str
    email: str
    plan: SubscriptionPlan
    signup_date: datetime
    source: str = "web"  # web, cli, api, extension


@dataclass
class DownloadEvent:
    """Download event"""
    download_id: str
    asset_type: str  # cli, desktop, mobile, extension
    platform: str  # linux, macos, windows, ios, android
    download_date: datetime
    user_id: Optional[str] = None


@dataclass
class RevenueEvent:
    """Revenue/payment event"""
    transaction_id: str
    user_id: str
    plan: SubscriptionPlan
    amount: float
    currency: str = "USD"
    payment_date: datetime
    status: str = "completed"  # completed, pending, failed


class AdminDashboard:
    """Admin dashboard service"""
    
    def __init__(self):
        self.signups: List[SignupEvent] = []
        self.downloads: List[DownloadEvent] = []
        self.revenue: List[RevenueEvent] = []
        self.created_at = datetime.utcnow()
    
    def record_signup(self, user_id: str, email: str, plan: SubscriptionPlan, source: str = "web"):
        """Record a new signup"""
        event = SignupEvent(
            user_id=user_id,
            email=email,
            plan=plan,
            signup_date=datetime.utcnow(),
            source=source
        )
        self.signups.append(event)
    
    def record_download(self, asset_type: str, platform: str, user_id: Optional[str] = None):
        """Record a download"""
        event = DownloadEvent(
            download_id=f"dl_{len(self.downloads)}",
            asset_type=asset_type,
            platform=platform,
            download_date=datetime.utcnow(),
            user_id=user_id
        )
        self.downloads.append(event)
    
    def record_revenue(self, user_id: str, plan: SubscriptionPlan, amount: float):
        """Record a revenue event"""
        event = RevenueEvent(
            transaction_id=f"txn_{len(self.revenue)}",
            user_id=user_id,
            plan=plan,
            amount=amount,
            payment_date=datetime.utcnow()
        )
        self.revenue.append(event)
    
    def get_signups_today(self) -> int:
        """Get signups today"""
        today = datetime.utcnow().date()
        return sum(1 for s in self.signups if s.signup_date.date() == today)
    
    def get_signups_this_month(self) -> int:
        """Get signups this month"""
        now = datetime.utcnow()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return sum(1 for s in self.signups if s.signup_date >= month_start)
    
    def get_signups_by_plan(self) -> Dict[str, int]:
        """Get signups by plan"""
        counts = {plan.value: 0 for plan in SubscriptionPlan}
        for signup in self.signups:
            counts[signup.plan.value] += 1
        return counts
    
    def get_downloads_by_asset(self) -> Dict[str, int]:
        """Get downloads by asset type"""
        counts = {}
        for download in self.downloads:
            asset = download.asset_type
            counts[asset] = counts.get(asset, 0) + 1
        return counts
    
    def get_downloads_by_platform(self) -> Dict[str, int]:
        """Get downloads by platform"""
        counts = {}
        for download in self.downloads:
            platform = download.platform
            counts[platform] = counts.get(platform, 0) + 1
        return counts
    
    def get_total_revenue(self) -> float:
        """Get total revenue"""
        return sum(r.amount for r in self.revenue if r.status == "completed")
    
    def get_revenue_this_month(self) -> float:
        """Get revenue this month"""
        now = datetime.utcnow()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return sum(
            r.amount for r in self.revenue
            if r.payment_date >= month_start and r.status == "completed"
        )
    
    def get_revenue_by_plan(self) -> Dict[str, float]:
        """Get revenue by plan"""
        revenue = {plan.value: 0.0 for plan in SubscriptionPlan}
        for event in self.revenue:
            if event.status == "completed":
                revenue[event.plan.value] += event.amount
        return revenue
    
    def get_mrr(self) -> float:
        """Get Monthly Recurring Revenue"""
        # Simplified: count active subscriptions * plan price
        plan_prices = {
            SubscriptionPlan.FREE: 0,
            SubscriptionPlan.PRO: 29,
            SubscriptionPlan.TEAM: 99,
            SubscriptionPlan.ENTERPRISE: 999,
        }
        
        active_users = {}
        for signup in self.signups:
            active_users[signup.user_id] = signup.plan
        
        mrr = sum(plan_prices[plan] for plan in active_users.values())
        return mrr
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get dashboard summary"""
        return {
            "summary": {
                "total_signups": len(self.signups),
                "signups_today": self.get_signups_today(),
                "signups_this_month": self.get_signups_this_month(),
                "total_downloads": len(self.downloads),
                "total_revenue": round(self.get_total_revenue(), 2),
                "revenue_this_month": round(self.get_revenue_this_month(), 2),
                "mrr": round(self.get_mrr(), 2),
            },
            "signups_by_plan": self.get_signups_by_plan(),
            "downloads_by_asset": self.get_downloads_by_asset(),
            "downloads_by_platform": self.get_downloads_by_platform(),
            "revenue_by_plan": {k: round(v, 2) for k, v in self.get_revenue_by_plan().items()},
            "recent_signups": [asdict(s) for s in self.signups[-10:]],
            "recent_downloads": [asdict(d) for d in self.downloads[-10:]],
        }


# Global admin dashboard instance
admin_dashboard = AdminDashboard()


if __name__ == "__main__":
    # Test the dashboard
    dashboard = AdminDashboard()
    
    # Record some test data
    dashboard.record_signup("user_001", "alice@example.com", SubscriptionPlan.PRO)
    dashboard.record_signup("user_002", "bob@example.com", SubscriptionPlan.FREE)
    dashboard.record_signup("user_003", "charlie@example.com", SubscriptionPlan.TEAM)
    
    dashboard.record_download("cli", "linux", "user_001")
    dashboard.record_download("desktop", "macos")
    dashboard.record_download("extension", "chrome")
    
    dashboard.record_revenue("user_001", SubscriptionPlan.PRO, 29.0)
    dashboard.record_revenue("user_003", SubscriptionPlan.TEAM, 99.0)
    
    # Print summary
    summary = dashboard.get_dashboard_summary()
    print(json.dumps(summary, indent=2, default=str))
