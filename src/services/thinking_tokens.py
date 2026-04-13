"""
DevPulse - Thinking Token Attribution System
Track and attribute LLM reasoning costs
"""

from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict


class ThinkingTokenTracker:
    """Track thinking tokens for LLM calls"""
    
    # OpenAI pricing (as of 2024)
    PRICING = {
        "o1": {
            "prompt": 0.015,  # $0.015 per 1K tokens
            "completion": 0.060,  # $0.060 per 1K tokens
            "thinking": 0.150,  # $0.150 per 1K tokens (3x more expensive)
        },
        "gpt-4": {
            "prompt": 0.03,
            "completion": 0.06,
            "thinking": 0.0,  # GPT-4 doesn't have thinking tokens
        },
        "gpt-3.5": {
            "prompt": 0.0005,
            "completion": 0.0015,
            "thinking": 0.0,
        }
    }
    
    def __init__(self):
        self.token_records: List[Dict] = []
        self.cost_by_model: Dict[str, float] = defaultdict(float)
        self.cost_by_operation: Dict[str, float] = defaultdict(float)
        self.thinking_tokens_total = 0
    
    def track_tokens(
        self,
        request_id: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        thinking_tokens: int = 0,
        operation: str = "unknown"
    ) -> Dict:
        """
        Track token usage for an LLM call
        
        Args:
            request_id: Unique request identifier
            model: Model name (e.g., "o1", "gpt-4")
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens
            thinking_tokens: Number of thinking tokens (o1 only)
            operation: Operation type (e.g., "vulnerability_analysis")
            
        Returns:
            Token tracking record
        """
        # Get pricing for model
        pricing = self.PRICING.get(model, self.PRICING["gpt-4"])
        
        # Calculate costs
        prompt_cost = (prompt_tokens / 1000) * pricing["prompt"]
        completion_cost = (completion_tokens / 1000) * pricing["completion"]
        thinking_cost = (thinking_tokens / 1000) * pricing["thinking"]
        total_cost = prompt_cost + completion_cost + thinking_cost
        
        # Create record
        record = {
            "request_id": request_id,
            "model": model,
            "operation": operation,
            "tokens": {
                "prompt": prompt_tokens,
                "completion": completion_tokens,
                "thinking": thinking_tokens,
                "total": prompt_tokens + completion_tokens + thinking_tokens
            },
            "cost": {
                "prompt": round(prompt_cost, 6),
                "completion": round(completion_cost, 6),
                "thinking": round(thinking_cost, 6),
                "total": round(total_cost, 6)
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store record
        self.token_records.append(record)
        
        # Update aggregates
        self.cost_by_model[model] += total_cost
        self.cost_by_operation[operation] += total_cost
        self.thinking_tokens_total += thinking_tokens
        
        return record
    
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
        """Get token usage analytics"""
        total_cost = sum(r["cost"]["total"] for r in self.token_records)
        total_tokens = sum(r["tokens"]["total"] for r in self.token_records)
        
        # Calculate percentages
        thinking_cost = sum(r["cost"]["thinking"] for r in self.token_records)
        thinking_percentage = (thinking_cost / total_cost * 100) if total_cost > 0 else 0
        
        # Top operations
        top_operations = sorted(
            self.cost_by_operation.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        # Model breakdown
        model_breakdown = [
            {
                "model": model,
                "cost": round(cost, 2),
                "percentage": round(cost / total_cost * 100, 1) if total_cost > 0 else 0
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
                "thinking_percentage": round(thinking_percentage, 1)
            },
            "by_model": model_breakdown,
            "top_operations": [
                {"operation": op, "cost": round(cost, 2)}
                for op, cost in top_operations
            ],
            "cost_per_request": round(total_cost / len(self.token_records), 2) if self.token_records else 0,
            "cost_per_token": round(total_cost / total_tokens * 1000, 6) if total_tokens > 0 else 0
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
