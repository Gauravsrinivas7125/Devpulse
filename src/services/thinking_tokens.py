"""
DevPulse - Thinking Token Attribution System (Market-Ready, Patent 2 Core)
Intercepts LLM responses, separates reasoning vs completion tokens,
performs differential cost analysis, and detects thinking-token anomalies.

Patent 2: "Thinking Token Attribution and Differential Cost Analysis"
Key innovation: Real-time separation of reasoning tokens from completion
tokens with timing-based attribution and anomaly detection.
"""

import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class ThinkingTokenTracker:
    """
    Patent 2 Core: Thinking Token Attribution Engine.
    
    Intercepts LLM API responses, separates reasoning (thinking) tokens
    from completion tokens, attributes costs differentially, and detects
    anomalous thinking-token usage patterns.
    """
    
    # Model pricing (2025-2026 rates)
    PRICING = {
        "o1": {
            "prompt": 0.015,
            "completion": 0.060,
            "thinking": 0.150,  # 2.5x completion price
        },
        "o1-mini": {
            "prompt": 0.003,
            "completion": 0.012,
            "thinking": 0.030,
        },
        "o1-pro": {
            "prompt": 0.060,
            "completion": 0.240,
            "thinking": 0.600,
        },
        "o3-mini": {
            "prompt": 0.0011,
            "completion": 0.0044,
            "thinking": 0.011,
        },
        "gpt-4": {
            "prompt": 0.03,
            "completion": 0.06,
            "thinking": 0.0,
        },
        "gpt-4o": {
            "prompt": 0.005,
            "completion": 0.015,
            "thinking": 0.0,
        },
        "gpt-4o-mini": {
            "prompt": 0.00015,
            "completion": 0.0006,
            "thinking": 0.0,
        },
        "gpt-3.5": {
            "prompt": 0.0005,
            "completion": 0.0015,
            "thinking": 0.0,
        },
        "claude-3.5-sonnet": {
            "prompt": 0.003,
            "completion": 0.015,
            "thinking": 0.0,
        },
        "claude-3-opus": {
            "prompt": 0.015,
            "completion": 0.075,
            "thinking": 0.0,
        },
        "deepseek-r1": {
            "prompt": 0.00055,
            "completion": 0.0022,
            "thinking": 0.0055,  # R1 has thinking tokens
        },
    }
    
    # Anomaly detection thresholds
    THINKING_RATIO_ALERT = 5.0  # thinking tokens > 5x completion tokens
    COST_SPIKE_THRESHOLD = 3.0  # cost > 3x moving average
    
    def __init__(self):
        self.token_records: List[Dict] = []
        self.cost_by_model: Dict[str, float] = defaultdict(float)
        self.cost_by_operation: Dict[str, float] = defaultdict(float)
        self.thinking_tokens_total = 0
        self.anomalies: List[Dict] = []
        self._moving_avg_window: List[float] = []
    
    def track_tokens(
        self,
        request_id: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        thinking_tokens: int = 0,
        operation: str = "unknown",
        response_time_ms: Optional[float] = None,
        raw_response: Optional[Dict] = None,
    ) -> Dict:
        """
        Track token usage with Patent 2 differential analysis.
        
        Intercepts an LLM response, separates reasoning vs completion tokens,
        performs differential cost attribution, detects anomalies, and logs
        timing-based signals for thinking-token efficiency analysis.
        """
        pricing = self.PRICING.get(model, self.PRICING["gpt-4"])
        
        # If raw_response provided, attempt to extract thinking tokens
        if raw_response and thinking_tokens == 0:
            thinking_tokens = self._extract_thinking_tokens(raw_response, model)
        
        # Calculate costs
        prompt_cost = (prompt_tokens / 1000) * pricing["prompt"]
        completion_cost = (completion_tokens / 1000) * pricing["completion"]
        thinking_cost = (thinking_tokens / 1000) * pricing["thinking"]
        total_cost = prompt_cost + completion_cost + thinking_cost
        
        # Differential analysis (Patent 2 core)
        thinking_ratio = (thinking_tokens / completion_tokens) if completion_tokens > 0 else 0
        thinking_cost_share = (thinking_cost / total_cost * 100) if total_cost > 0 else 0
        
        # Timing-based attribution
        estimated_thinking_time_ms = None
        tokens_per_second = None
        if response_time_ms and response_time_ms > 0:
            total_output = completion_tokens + thinking_tokens
            tokens_per_second = (total_output / response_time_ms) * 1000
            if thinking_tokens > 0 and total_output > 0:
                estimated_thinking_time_ms = response_time_ms * (thinking_tokens / total_output)
        
        record = {
            "request_id": request_id,
            "model": model,
            "operation": operation,
            "tokens": {
                "prompt": prompt_tokens,
                "completion": completion_tokens,
                "thinking": thinking_tokens,
                "total": prompt_tokens + completion_tokens + thinking_tokens,
            },
            "cost": {
                "prompt": round(prompt_cost, 6),
                "completion": round(completion_cost, 6),
                "thinking": round(thinking_cost, 6),
                "total": round(total_cost, 6),
            },
            "differential": {
                "thinking_ratio": round(thinking_ratio, 2),
                "thinking_cost_share_pct": round(thinking_cost_share, 1),
                "cost_without_thinking": round(prompt_cost + completion_cost, 6),
                "thinking_premium": round(thinking_cost, 6),
            },
            "timing": {
                "response_time_ms": response_time_ms,
                "estimated_thinking_time_ms": round(estimated_thinking_time_ms, 1) if estimated_thinking_time_ms else None,
                "tokens_per_second": round(tokens_per_second, 1) if tokens_per_second else None,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Store record
        self.token_records.append(record)
        
        # Update aggregates
        self.cost_by_model[model] += total_cost
        self.cost_by_operation[operation] += total_cost
        self.thinking_tokens_total += thinking_tokens
        
        # Anomaly detection (Patent 2)
        self._detect_anomalies(record)
        
        return record
    
    def _extract_thinking_tokens(self, raw_response: Dict, model: str) -> int:
        """
        Extract thinking tokens from raw LLM API response.
        Handles OpenAI o1/o3 format and DeepSeek R1 format.
        """
        usage = raw_response.get("usage", {})
        
        # OpenAI o1/o3 format
        completion_details = usage.get("completion_tokens_details", {})
        reasoning_tokens = completion_details.get("reasoning_tokens", 0)
        if reasoning_tokens:
            return reasoning_tokens
        
        # DeepSeek R1 format
        if "reasoning_content" in str(raw_response.get("choices", [{}])):
            # Estimate from content length (rough heuristic)
            for choice in raw_response.get("choices", []):
                message = choice.get("message", {})
                reasoning = message.get("reasoning_content", "")
                if reasoning:
                    return len(reasoning.split()) * 2  # rough token estimate
        
        return 0
    
    def _detect_anomalies(self, record: Dict) -> None:
        """Detect thinking-token anomalies (Patent 2 innovation)"""
        total_cost = record["cost"]["total"]
        thinking_ratio = record["differential"]["thinking_ratio"]
        
        # Update moving average
        self._moving_avg_window.append(total_cost)
        if len(self._moving_avg_window) > 20:
            self._moving_avg_window.pop(0)
        
        moving_avg = sum(self._moving_avg_window) / len(self._moving_avg_window) if self._moving_avg_window else 0
        
        # Check for excessive thinking ratio
        if thinking_ratio > self.THINKING_RATIO_ALERT:
            self.anomalies.append({
                "type": "excessive_thinking",
                "request_id": record["request_id"],
                "model": record["model"],
                "thinking_ratio": thinking_ratio,
                "description": f"Thinking tokens {thinking_ratio:.1f}x completion tokens (threshold: {self.THINKING_RATIO_ALERT}x)",
                "severity": "HIGH",
                "timestamp": record["timestamp"],
            })
        
        # Check for cost spike
        if moving_avg > 0 and total_cost > moving_avg * self.COST_SPIKE_THRESHOLD:
            self.anomalies.append({
                "type": "cost_spike",
                "request_id": record["request_id"],
                "model": record["model"],
                "cost": total_cost,
                "moving_average": round(moving_avg, 6),
                "spike_factor": round(total_cost / moving_avg, 1),
                "description": f"Cost ${total_cost:.4f} is {total_cost / moving_avg:.1f}x the moving average",
                "severity": "MEDIUM",
                "timestamp": record["timestamp"],
            })
    
    def calculate_cost(self, token_data: Dict) -> Dict:
        """Calculate cost for token data"""
        model = token_data.get("model", "gpt-4")
        pricing = self.PRICING.get(model, self.PRICING["gpt-4"])
        
        prompt_tokens = token_data.get("prompt_tokens", 0)
        completion_tokens = token_data.get("completion_tokens", 0)
        thinking_tokens = token_data.get("thinking_tokens", 0)
        
        prompt_cost = (prompt_tokens / 1000) * pricing["prompt"]
        completion_cost = (completion_tokens / 1000) * pricing["completion"]
        thinking_cost = (thinking_tokens / 1000) * pricing["thinking"]
        
        return {
            "prompt": round(prompt_cost, 6),
            "completion": round(completion_cost, 6),
            "thinking": round(thinking_cost, 6),
            "total": round(prompt_cost + completion_cost + thinking_cost, 6)
        }
    
    def get_analytics(self) -> Dict:
        """Get token usage analytics with Patent 2 differential insights"""
        total_cost = sum(r["cost"]["total"] for r in self.token_records)
        total_tokens = sum(r["tokens"]["total"] for r in self.token_records)
        
        thinking_cost = sum(r["cost"]["thinking"] for r in self.token_records)
        thinking_percentage = (thinking_cost / total_cost * 100) if total_cost > 0 else 0
        
        # Differential analysis aggregates
        cost_without_thinking = sum(
            r.get("differential", {}).get("cost_without_thinking", r["cost"]["total"])
            for r in self.token_records
        )
        avg_thinking_ratio = 0.0
        thinking_records = [r for r in self.token_records if r["tokens"]["thinking"] > 0]
        if thinking_records:
            avg_thinking_ratio = sum(
                r.get("differential", {}).get("thinking_ratio", 0)
                for r in thinking_records
            ) / len(thinking_records)
        
        top_operations = sorted(
            self.cost_by_operation.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        model_breakdown = [
            {
                "model": model,
                "cost": round(cost, 2),
                "percentage": round(cost / total_cost * 100, 1) if total_cost > 0 else 0,
            }
            for model, cost in sorted(
                self.cost_by_model.items(),
                key=lambda x: x[1],
                reverse=True
            )
        ]
        
        return {
            "summary": {
                "total_cost": round(total_cost, 2),
                "total_tokens": total_tokens,
                "total_requests": len(self.token_records),
                "thinking_tokens": self.thinking_tokens_total,
                "thinking_cost": round(thinking_cost, 2),
                "thinking_percentage": round(thinking_percentage, 1),
            },
            "differential_analysis": {
                "total_thinking_premium": round(thinking_cost, 2),
                "cost_without_thinking": round(cost_without_thinking, 2),
                "avg_thinking_ratio": round(avg_thinking_ratio, 2),
                "thinking_models_used": len([
                    m for m, p in self.PRICING.items()
                    if p["thinking"] > 0 and m in self.cost_by_model
                ]),
            },
            "anomalies": {
                "total": len(self.anomalies),
                "recent": self.anomalies[-10:],
            },
            "by_model": model_breakdown,
            "top_operations": [
                {"operation": op, "cost": round(cost, 2)}
                for op, cost in top_operations
            ],
            "cost_per_request": round(total_cost / len(self.token_records), 2) if self.token_records else 0,
            "cost_per_token": round(total_cost / total_tokens * 1000, 6) if total_tokens > 0 else 0,
        }
    
    def get_expensive_operations(self, limit: int = 10) -> List[Dict]:
        """Get most expensive operations"""
        operation_costs = defaultdict(float)
        operation_counts = defaultdict(int)
        
        for record in self.token_records:
            operation = record["operation"]
            operation_costs[operation] += record["cost"]["total"]
            operation_counts[operation] += 1
        
        expensive = sorted(
            [
                {
                    "operation": op,
                    "total_cost": round(cost, 2),
                    "count": operation_counts[op],
                    "avg_cost": round(cost / operation_counts[op], 2)
                }
                for op, cost in operation_costs.items()
            ],
            key=lambda x: x["total_cost"],
            reverse=True
        )
        
        return expensive[:limit]
    
    def get_thinking_token_breakdown(self) -> Dict:
        """Get thinking token usage breakdown"""
        thinking_records = [r for r in self.token_records if r["tokens"]["thinking"] > 0]
        
        if not thinking_records:
            return {
                "total_thinking_tokens": 0,
                "total_thinking_cost": 0,
                "records": []
            }
        
        total_thinking_tokens = sum(r["tokens"]["thinking"] for r in thinking_records)
        total_thinking_cost = sum(r["cost"]["thinking"] for r in thinking_records)
        
        return {
            "total_thinking_tokens": total_thinking_tokens,
            "total_thinking_cost": round(total_thinking_cost, 2),
            "average_thinking_tokens": round(total_thinking_tokens / len(thinking_records), 0),
            "records": thinking_records
        }
    
    def get_cost_trend(self, window: int = 10) -> List[Dict]:
        """Get cost trend over last N records"""
        recent_records = self.token_records[-window:]
        
        trend = []
        cumulative_cost = 0
        
        for i, record in enumerate(recent_records):
            cumulative_cost += record["cost"]["total"]
            trend.append({
                "request": i + 1,
                "cost": round(record["cost"]["total"], 2),
                "cumulative_cost": round(cumulative_cost, 2),
                "model": record["model"],
                "operation": record["operation"]
            })
        
        return trend
    
    def estimate_monthly_cost(self) -> Dict:
        """Estimate monthly cost based on current usage"""
        if not self.token_records:
            return {"estimated_monthly_cost": 0}
        
        # Calculate average daily cost
        first_timestamp = datetime.fromisoformat(self.token_records[0]["timestamp"])
        last_timestamp = datetime.fromisoformat(self.token_records[-1]["timestamp"])
        
        days_elapsed = (last_timestamp - first_timestamp).days + 1
        if days_elapsed < 1:
            days_elapsed = 1
        
        total_cost = sum(r["cost"]["total"] for r in self.token_records)
        daily_average = total_cost / days_elapsed
        monthly_estimate = daily_average * 30
        
        return {
            "estimated_monthly_cost": round(monthly_estimate, 2),
            "daily_average": round(daily_average, 2),
            "days_tracked": days_elapsed
        }


# Example usage
if __name__ == "__main__":
    tracker = ThinkingTokenTracker()
    
    # Track some token usage
    tracker.track_tokens(
        request_id="req_001",
        model="o1",
        prompt_tokens=500,
        completion_tokens=1000,
        thinking_tokens=5000,
        operation="vulnerability_analysis"
    )
    
    tracker.track_tokens(
        request_id="req_002",
        model="gpt-4",
        prompt_tokens=300,
        completion_tokens=500,
        thinking_tokens=0,
        operation="code_review"
    )
    
    tracker.track_tokens(
        request_id="req_003",
        model="o1",
        prompt_tokens=400,
        completion_tokens=800,
        thinking_tokens=3000,
        operation="vulnerability_analysis"
    )
    
    # Get analytics
    analytics = tracker.get_analytics()
    print(f"Total Cost: ${analytics['summary']['total_cost']}")
    print(f"Total Tokens: {analytics['summary']['total_tokens']}")
    print(f"Thinking Cost: ${analytics['summary']['thinking_cost']}")
    print(f"Thinking Percentage: {analytics['summary']['thinking_percentage']}%")
    
    print("\nExpensive Operations:")
    for op in tracker.get_expensive_operations():
        print(f"  {op['operation']}: ${op['total_cost']} ({op['count']} calls)")
    
    print("\nMonthly Estimate:")
    estimate = tracker.estimate_monthly_cost()
    print(f"  ${estimate['estimated_monthly_cost']}/month")
