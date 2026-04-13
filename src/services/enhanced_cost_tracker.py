"""
DevPulse Enhanced Cost Tracker
Inspired by Claude Code's cost-tracker.ts patterns.
Multi-model LLM cost tracking with per-session breakdowns,
utilization windows, and anomaly detection.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import threading


# Model pricing per 1M tokens (USD)
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    "gpt-4": {"input": 30.00, "output": 60.00, "thinking": 30.00},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00, "thinking": 10.00},
    "gpt-4o": {"input": 5.00, "output": 15.00, "thinking": 5.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60, "thinking": 0.15},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50, "thinking": 0.50},
    "claude-3-opus": {"input": 15.00, "output": 75.00, "thinking": 15.00},
    "claude-3.5-sonnet": {"input": 3.00, "output": 15.00, "thinking": 3.00},
    "claude-3-haiku": {"input": 0.25, "output": 1.25, "thinking": 0.25},
    "claude-4-sonnet": {"input": 3.00, "output": 15.00, "thinking": 3.00},
    "gemini-pro": {"input": 0.50, "output": 1.50, "thinking": 0.50},
    "gemini-1.5-pro": {"input": 3.50, "output": 10.50, "thinking": 3.50},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.30, "thinking": 0.075},
    "llama-3-70b": {"input": 0.79, "output": 0.79, "thinking": 0.79},
    "llama-3-8b": {"input": 0.05, "output": 0.05, "thinking": 0.05},
    "mistral-large": {"input": 4.00, "output": 12.00, "thinking": 4.00},
    "mistral-medium": {"input": 2.70, "output": 8.10, "thinking": 2.70},
}


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    thinking_tokens: int = 0
    total_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0


@dataclass
class CostEntry:
    request_id: str
    model: str
    usage: TokenUsage
    cost_usd: float
    timestamp: str
    session_id: Optional[str] = None
    duration_ms: Optional[int] = None
    endpoint: Optional[str] = None


@dataclass
class RateLimit:
    utilization: float  # percentage 0-100
    resets_at: Optional[str] = None


@dataclass
class UtilizationWindow:
    window_name: str  # e.g., "5_hour", "7_day"
    window_seconds: int
    entries: List[CostEntry] = field(default_factory=list)
    budget_usd: Optional[float] = None

    @property
    def total_cost(self) -> float:
        cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
        return sum(
            e.cost_usd for e in self.entries
            if datetime.fromisoformat(e.timestamp) >= cutoff
        )

    @property
    def utilization(self) -> Optional[float]:
        if self.budget_usd and self.budget_usd > 0:
            return min(100.0, (self.total_cost / self.budget_usd) * 100)
        return None

    def prune(self) -> None:
        cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
        self.entries = [
            e for e in self.entries
            if datetime.fromisoformat(e.timestamp) >= cutoff
        ]


@dataclass
class CostAnomaly:
    anomaly_type: str  # "spike", "budget_exceeded", "unusual_model"
    severity: str  # "warning", "critical"
    message: str
    detected_at: str
    details: Dict


class EnhancedCostTracker:
    """
    Multi-model LLM cost tracker with utilization windows,
    anomaly detection, and per-session breakdowns.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: List[CostEntry] = []
        self._model_usage: Dict[str, TokenUsage] = {}
        self._session_costs: Dict[str, float] = {}
        self._anomalies: List[CostAnomaly] = []

        # Utilization windows (inspired by Claude Code's rate limit tracking)
        self._windows: Dict[str, UtilizationWindow] = {
            "5_hour": UtilizationWindow(
                window_name="5_hour",
                window_seconds=5 * 3600,
                budget_usd=50.0,
            ),
            "24_hour": UtilizationWindow(
                window_name="24_hour",
                window_seconds=24 * 3600,
                budget_usd=200.0,
            ),
            "7_day": UtilizationWindow(
                window_name="7_day",
                window_seconds=7 * 24 * 3600,
                budget_usd=1000.0,
            ),
            "30_day": UtilizationWindow(
                window_name="30_day",
                window_seconds=30 * 24 * 3600,
                budget_usd=5000.0,
            ),
        }

        # Anomaly detection thresholds
        self._spike_threshold = 3.0  # 3x average cost = spike
        self._budget_warning_pct = 80.0  # warn at 80% of window budget

    def calculate_cost(
        self,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        thinking_tokens: int = 0,
    ) -> float:
        """Calculate USD cost for a given token usage."""
        pricing = MODEL_PRICING.get(model)
        if not pricing:
            # Fall back to a generic mid-tier pricing
            pricing = {"input": 5.00, "output": 15.00, "thinking": 5.00}

        cost = (
            (prompt_tokens / 1_000_000) * pricing["input"]
            + (completion_tokens / 1_000_000) * pricing["output"]
            + (thinking_tokens / 1_000_000) * pricing["thinking"]
        )
        return round(cost, 6)

    def track(
        self,
        request_id: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        thinking_tokens: int = 0,
        session_id: Optional[str] = None,
        duration_ms: Optional[int] = None,
        endpoint: Optional[str] = None,
    ) -> CostEntry:
        """Track a single LLM API call."""
        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            thinking_tokens=thinking_tokens,
            total_tokens=prompt_tokens + completion_tokens + thinking_tokens,
        )
        cost = self.calculate_cost(model, prompt_tokens, completion_tokens, thinking_tokens)
        entry = CostEntry(
            request_id=request_id,
            model=model,
            usage=usage,
            cost_usd=cost,
            timestamp=datetime.utcnow().isoformat(),
            session_id=session_id,
            duration_ms=duration_ms,
            endpoint=endpoint,
        )

        with self._lock:
            self._entries.append(entry)

            # Update model usage
            if model not in self._model_usage:
                self._model_usage[model] = TokenUsage()
            mu = self._model_usage[model]
            mu.prompt_tokens += prompt_tokens
            mu.completion_tokens += completion_tokens
            mu.thinking_tokens += thinking_tokens
            mu.total_tokens += usage.total_tokens

            # Update session costs
            if session_id:
                self._session_costs[session_id] = (
                    self._session_costs.get(session_id, 0) + cost
                )

            # Update utilization windows
            for window in self._windows.values():
                window.entries.append(entry)
                window.prune()

            # Check for anomalies
            self._detect_anomalies(entry)

        return entry

    def _detect_anomalies(self, entry: CostEntry) -> None:
        """Detect cost anomalies (spikes, budget warnings)."""
        # Spike detection: compare to rolling average
        if len(self._entries) > 10:
            recent_costs = [e.cost_usd for e in self._entries[-20:-1]]
            avg_cost = sum(recent_costs) / len(recent_costs) if recent_costs else 0
            if avg_cost > 0 and entry.cost_usd > avg_cost * self._spike_threshold:
                self._anomalies.append(CostAnomaly(
                    anomaly_type="spike",
                    severity="warning",
                    message=f"Cost spike detected: ${entry.cost_usd:.4f} is {entry.cost_usd/avg_cost:.1f}x the rolling average",
                    detected_at=datetime.utcnow().isoformat(),
                    details={
                        "entry_cost": entry.cost_usd,
                        "average_cost": avg_cost,
                        "model": entry.model,
                        "multiplier": entry.cost_usd / avg_cost,
                    },
                ))

        # Budget warning detection
        for name, window in self._windows.items():
            util = window.utilization
            if util is not None and util >= self._budget_warning_pct:
                severity = "critical" if util >= 95.0 else "warning"
                self._anomalies.append(CostAnomaly(
                    anomaly_type="budget_exceeded",
                    severity=severity,
                    message=f"{name} window at {util:.1f}% of budget (${window.total_cost:.2f} / ${window.budget_usd:.2f})",
                    detected_at=datetime.utcnow().isoformat(),
                    details={
                        "window": name,
                        "utilization_pct": util,
                        "total_cost": window.total_cost,
                        "budget": window.budget_usd,
                    },
                ))

    def get_total_cost(self) -> float:
        """Get total cost across all entries."""
        with self._lock:
            return sum(e.cost_usd for e in self._entries)

    def get_model_breakdown(self) -> List[Dict]:
        """Get cost breakdown by model."""
        with self._lock:
            model_costs: Dict[str, Dict] = {}
            for entry in self._entries:
                if entry.model not in model_costs:
                    model_costs[entry.model] = {
                        "model": entry.model,
                        "total_cost": 0,
                        "total_tokens": 0,
                        "call_count": 0,
                        "avg_cost_per_call": 0,
                    }
                mc = model_costs[entry.model]
                mc["total_cost"] += entry.cost_usd
                mc["total_tokens"] += entry.usage.total_tokens
                mc["call_count"] += 1

            result = list(model_costs.values())
            for mc in result:
                if mc["call_count"] > 0:
                    mc["avg_cost_per_call"] = mc["total_cost"] / mc["call_count"]
            return sorted(result, key=lambda x: x["total_cost"], reverse=True)

    def get_utilization(self) -> Dict:
        """Get utilization across all windows."""
        with self._lock:
            result = {}
            for name, window in self._windows.items():
                window.prune()
                result[name] = {
                    "window": name,
                    "total_cost": round(window.total_cost, 4),
                    "budget": window.budget_usd,
                    "utilization_pct": round(window.utilization, 1) if window.utilization is not None else None,
                    "entry_count": len(window.entries),
                    "resets_at": (
                        datetime.utcnow() + timedelta(seconds=window.window_seconds)
                    ).isoformat() if window.budget_usd else None,
                }
            return result

    def get_daily_breakdown(self, days: int = 30) -> List[Dict]:
        """Get cost breakdown by day."""
        with self._lock:
            daily: Dict[str, Dict] = {}
            cutoff = datetime.utcnow() - timedelta(days=days)
            for entry in self._entries:
                ts = datetime.fromisoformat(entry.timestamp)
                if ts < cutoff:
                    continue
                day = ts.strftime("%Y-%m-%d")
                if day not in daily:
                    daily[day] = {"date": day, "cost": 0, "tokens": 0, "calls": 0}
                daily[day]["cost"] += entry.cost_usd
                daily[day]["tokens"] += entry.usage.total_tokens
                daily[day]["calls"] += 1

            return sorted(daily.values(), key=lambda x: x["date"])

    def get_session_breakdown(self) -> Dict[str, float]:
        """Get cost breakdown by session."""
        with self._lock:
            return dict(self._session_costs)

    def get_anomalies(self, limit: int = 50) -> List[Dict]:
        """Get recent anomalies."""
        with self._lock:
            return [
                {
                    "type": a.anomaly_type,
                    "severity": a.severity,
                    "message": a.message,
                    "detected_at": a.detected_at,
                    "details": a.details,
                }
                for a in self._anomalies[-limit:]
            ]

    def get_summary(self) -> Dict:
        """Get comprehensive cost summary."""
        with self._lock:
            total_cost = sum(e.cost_usd for e in self._entries)
            total_tokens = sum(e.usage.total_tokens for e in self._entries)
            total_calls = len(self._entries)

            # Find most expensive model
            model_costs: Dict[str, float] = {}
            for entry in self._entries:
                model_costs[entry.model] = model_costs.get(entry.model, 0) + entry.cost_usd
            most_expensive = max(model_costs, key=model_costs.get) if model_costs else None

            return {
                "total_cost_usd": round(total_cost, 4),
                "total_tokens": total_tokens,
                "total_calls": total_calls,
                "avg_cost_per_call": round(total_cost / total_calls, 6) if total_calls > 0 else 0,
                "avg_tokens_per_call": total_tokens // total_calls if total_calls > 0 else 0,
                "most_expensive_model": most_expensive,
                "models_used": len(model_costs),
                "active_sessions": len(self._session_costs),
                "anomaly_count": len(self._anomalies),
            }

    def set_window_budget(self, window_name: str, budget_usd: float) -> bool:
        """Set budget for a utilization window."""
        with self._lock:
            if window_name in self._windows:
                self._windows[window_name].budget_usd = budget_usd
                return True
            return False

    def format_cost(self, cost: float) -> str:
        """Format cost for display."""
        if cost < 0.01:
            return f"${cost:.4f}"
        if cost < 1.0:
            return f"${cost:.3f}"
        return f"${cost:.2f}"


# Global instance
enhanced_cost_tracker = EnhancedCostTracker()
