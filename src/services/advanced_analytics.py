"""
DevPulse Advanced Analytics Engine
Inspired by Claude Code's analytics service patterns.
Event-based analytics with trend analysis, risk trending,
and finding category heatmaps.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict
import threading
import math


@dataclass
class AnalyticsEvent:
    event_name: str
    metadata: Dict[str, Any]
    timestamp: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None


class AdvancedAnalyticsEngine:
    """
    Event-based analytics engine with trend analysis,
    risk score trending, and finding category heatmaps.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: List[AnalyticsEvent] = []
        self._scan_history: List[Dict] = []
        self._risk_history: List[Dict] = []
        self._finding_categories: Dict[str, int] = defaultdict(int)

    def log_event(
        self,
        event_name: str,
        metadata: Dict[str, Any],
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        """Log an analytics event (non-blocking, thread-safe)."""
        event = AnalyticsEvent(
            event_name=event_name,
            metadata=metadata,
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            session_id=session_id,
        )
        with self._lock:
            self._events.append(event)

    def record_scan(self, scan_data: Dict) -> None:
        """Record a scan result for trend analysis."""
        with self._lock:
            self._scan_history.append({
                **scan_data,
                "recorded_at": datetime.utcnow().isoformat(),
            })

    def record_risk_score(self, user_id: str, score: float, level: str) -> None:
        """Record a risk score snapshot for trending."""
        with self._lock:
            self._risk_history.append({
                "user_id": user_id,
                "score": score,
                "level": level,
                "timestamp": datetime.utcnow().isoformat(),
            })

    def record_finding(self, category: str, severity: str) -> None:
        """Record a finding for category heatmap."""
        with self._lock:
            key = f"{category}:{severity}"
            self._finding_categories[key] += 1

    # -----------------------------------------------------------------------
    # Trend Analysis
    # -----------------------------------------------------------------------

    def get_scan_trends(self, days: int = 30) -> Dict:
        """Get scan volume and risk trends over time."""
        with self._lock:
            cutoff = datetime.utcnow() - timedelta(days=days)
            daily: Dict[str, Dict] = {}

            for scan in self._scan_history:
                ts_str = scan.get("recorded_at") or scan.get("created_at", "")
                if not ts_str:
                    continue
                try:
                    ts = datetime.fromisoformat(ts_str)
                except ValueError:
                    continue
                if ts < cutoff:
                    continue

                day = ts.strftime("%Y-%m-%d")
                if day not in daily:
                    daily[day] = {
                        "date": day,
                        "scan_count": 0,
                        "total_findings": 0,
                        "avg_risk_score": 0,
                        "risk_scores": [],
                        "critical_count": 0,
                        "high_count": 0,
                    }
                d = daily[day]
                d["scan_count"] += 1
                findings = scan.get("total_findings", 0)
                d["total_findings"] += findings
                risk = scan.get("risk_score", 0)
                d["risk_scores"].append(risk)

                # Count severities from findings list
                for f in scan.get("findings", []):
                    sev = f.get("severity", "").upper()
                    if sev == "CRITICAL":
                        d["critical_count"] += 1
                    elif sev == "HIGH":
                        d["high_count"] += 1

            # Calculate averages
            result = []
            for d in sorted(daily.values(), key=lambda x: x["date"]):
                scores = d.pop("risk_scores")
                d["avg_risk_score"] = round(sum(scores) / len(scores), 1) if scores else 0
                result.append(d)

            return {
                "daily_trends": result,
                "total_scans": sum(d["scan_count"] for d in result),
                "total_findings": sum(d["total_findings"] for d in result),
                "period_days": days,
            }

    def get_risk_trend(self, user_id: Optional[str] = None, days: int = 30) -> List[Dict]:
        """Get risk score trend over time for a user or globally."""
        with self._lock:
            cutoff = datetime.utcnow() - timedelta(days=days)
            entries = [
                r for r in self._risk_history
                if (user_id is None or r["user_id"] == user_id)
                and datetime.fromisoformat(r["timestamp"]) >= cutoff
            ]

            # Group by day
            daily: Dict[str, List[float]] = {}
            for entry in entries:
                day = datetime.fromisoformat(entry["timestamp"]).strftime("%Y-%m-%d")
                if day not in daily:
                    daily[day] = []
                daily[day].append(entry["score"])

            return [
                {
                    "date": day,
                    "avg_score": round(sum(scores) / len(scores), 1),
                    "max_score": max(scores),
                    "min_score": min(scores),
                    "data_points": len(scores),
                }
                for day, scores in sorted(daily.items())
            ]

    def get_finding_heatmap(self) -> Dict:
        """Get finding category × severity heatmap."""
        with self._lock:
            categories: Dict[str, Dict[str, int]] = {}
            for key, count in self._finding_categories.items():
                parts = key.split(":", 1)
                if len(parts) != 2:
                    continue
                category, severity = parts
                if category not in categories:
                    categories[category] = {
                        "category": category,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                        "total": 0,
                    }
                sev_lower = severity.lower()
                if sev_lower in categories[category]:
                    categories[category][sev_lower] += count
                categories[category]["total"] += count

            return {
                "heatmap": sorted(
                    categories.values(),
                    key=lambda x: x["total"],
                    reverse=True,
                ),
                "total_categories": len(categories),
            }

    def get_endpoint_risk_distribution(self) -> List[Dict]:
        """Get risk distribution across API endpoints."""
        with self._lock:
            endpoints: Dict[str, Dict] = {}
            for scan in self._scan_history:
                for finding in scan.get("findings", []):
                    for ep in finding.get("affected_endpoints", []):
                        if ep not in endpoints:
                            endpoints[ep] = {
                                "endpoint": ep,
                                "finding_count": 0,
                                "severities": defaultdict(int),
                                "categories": set(),
                            }
                        endpoints[ep]["finding_count"] += 1
                        sev = finding.get("severity", "info").lower()
                        endpoints[ep]["severities"][sev] += 1
                        endpoints[ep]["categories"].add(finding.get("category", ""))

            return [
                {
                    "endpoint": ep,
                    "finding_count": data["finding_count"],
                    "severities": dict(data["severities"]),
                    "categories": list(data["categories"]),
                    "risk_weight": (
                        data["severities"].get("critical", 0) * 10
                        + data["severities"].get("high", 0) * 5
                        + data["severities"].get("medium", 0) * 2
                        + data["severities"].get("low", 0) * 1
                    ),
                }
                for ep, data in sorted(
                    endpoints.items(),
                    key=lambda x: x[1]["finding_count"],
                    reverse=True,
                )
            ]

    # -----------------------------------------------------------------------
    # Activity Feed
    # -----------------------------------------------------------------------

    def get_activity_feed(
        self,
        user_id: Optional[str] = None,
        limit: int = 50,
        event_types: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Get recent activity feed (filterable)."""
        with self._lock:
            filtered = self._events
            if user_id:
                filtered = [e for e in filtered if e.user_id == user_id]
            if event_types:
                filtered = [e for e in filtered if e.event_name in event_types]

            return [
                {
                    "event": e.event_name,
                    "metadata": e.metadata,
                    "timestamp": e.timestamp,
                    "user_id": e.user_id,
                }
                for e in filtered[-limit:]
            ][::-1]  # Most recent first

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def get_comprehensive_analytics(self, user_id: Optional[str] = None) -> Dict:
        """Get comprehensive analytics summary."""
        return {
            "scan_trends": self.get_scan_trends(),
            "risk_trend": self.get_risk_trend(user_id=user_id),
            "finding_heatmap": self.get_finding_heatmap(),
            "endpoint_risk": self.get_endpoint_risk_distribution(),
            "recent_activity": self.get_activity_feed(user_id=user_id, limit=20),
            "generated_at": datetime.utcnow().isoformat(),
        }


# Global instance
analytics_engine = AdvancedAnalyticsEngine()
