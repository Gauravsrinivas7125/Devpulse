"""
Thinking Token Tracker - Standalone Module
==========================================

Track, attribute, and analyze LLM reasoning token costs.
Includes Reasoning Efficiency Score (RES) calculation.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict
import math


class ReasoningEfficiencyScore:
    """
    Reasoning Efficiency Score (RES)
    ================================
    Measures how efficiently an LLM uses thinking tokens relative to output quality.

    Formula:
        RES = (quality_score * output_tokens) / (thinking_tokens * cost_per_token) * 100

    Scale: 0-100
        90-100: Exceptional - Minimal thinking for high-quality output
        70-89:  Good - Reasonable thinking-to-output ratio
        50-69:  Average - Some optimization possible
        30-49:  Below Average - Excessive reasoning detected
        0-29:   Poor - Possible infinite loop or waste
    """

    @staticmethod
    def calculate(
        thinking_tokens: int,
        output_tokens: int,
        quality_score: float = 0.8,
        cost_per_1k_thinking: float = 0.15,
    ) -> Dict[str, Any]:
        if thinking_tokens == 0:
            return {
                "score": 100.0,
                "grade": "N/A",
                "description": "No thinking tokens used",
                "ratio": 0.0,
            }

        ratio = thinking_tokens / max(output_tokens, 1)
        cost = (thinking_tokens / 1000) * cost_per_1k_thinking

        # RES formula: higher output with less thinking = better score
        raw_score = (quality_score * output_tokens) / (thinking_tokens * max(cost, 0.001)) * 10
        score = min(100.0, max(0.0, raw_score))

        if score >= 90:
            grade, desc = "A+", "Exceptional efficiency"
        elif score >= 70:
            grade, desc = "A", "Good efficiency"
        elif score >= 50:
            grade, desc = "B", "Average efficiency"
        elif score >= 30:
            grade, desc = "C", "Below average - optimization recommended"
        else:
            grade, desc = "D", "Poor - possible reasoning loop detected"

        return {
            "score": round(score, 1),
            "grade": grade,
            "description": desc,
            "ratio": round(ratio, 2),
            "thinking_tokens": thinking_tokens,
            "output_tokens": output_tokens,
            "estimated_cost": round(cost, 4),
        }

    @staticmethod
    def batch_calculate(records: List[Dict]) -> Dict[str, Any]:
        """Calculate aggregate RES across multiple requests"""
        if not records:
            return {"average_score": 0, "total_records": 0, "grades": {}}

        scores = []
        grade_counts = defaultdict(int)

        for record in records:
            res = ReasoningEfficiencyScore.calculate(
                thinking_tokens=record.get("thinking_tokens", 0),
                output_tokens=record.get("output_tokens", record.get("completion_tokens", 0)),
            )
            scores.append(res["score"])
            grade_counts[res["grade"]] += 1

        return {
            "average_score": round(sum(scores) / len(scores), 1),
            "min_score": round(min(scores), 1),
            "max_score": round(max(scores), 1),
            "total_records": len(records),
            "grades": dict(grade_counts),
        }


class ThinkingTokenTracker:
    """
    Track thinking tokens for LLM calls with cost attribution.
    Standalone version - no external dependencies required.
    """

    PRICING = {
        "o1": {"prompt": 0.015, "completion": 0.060, "thinking": 0.150},
        "o1-mini": {"prompt": 0.003, "completion": 0.012, "thinking": 0.030},
        "o1-preview": {"prompt": 0.015, "completion": 0.060, "thinking": 0.150},
        "gpt-4": {"prompt": 0.030, "completion": 0.060, "thinking": 0.0},
        "gpt-4-turbo": {"prompt": 0.010, "completion": 0.030, "thinking": 0.0},
        "gpt-4o": {"prompt": 0.005, "completion": 0.015, "thinking": 0.0},
        "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015, "thinking": 0.0},
        "claude-3-opus": {"prompt": 0.015, "completion": 0.075, "thinking": 0.150},
        "claude-3-sonnet": {"prompt": 0.003, "completion": 0.015, "thinking": 0.030},
        "claude-3-haiku": {"prompt": 0.00025, "completion": 0.00125, "thinking": 0.0},
    }

    def __init__(self):
        self.records: List[Dict] = []
        self.cost_by_model: Dict[str, float] = defaultdict(float)
        self.cost_by_operation: Dict[str, float] = defaultdict(float)
        self.thinking_tokens_total = 0

    def add_model_pricing(self, model: str, prompt: float, completion: float, thinking: float = 0.0):
        """Register custom model pricing (per 1K tokens)"""
        self.PRICING[model] = {"prompt": prompt, "completion": completion, "thinking": thinking}

    def track_tokens(
        self,
        request_id: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        thinking_tokens: int = 0,
        operation: str = "unknown",
        metadata: Optional[Dict] = None,
    ) -> Dict:
        pricing = self.PRICING.get(model, self.PRICING.get("gpt-4", {"prompt": 0.03, "completion": 0.06, "thinking": 0.0}))

        prompt_cost = (prompt_tokens / 1000) * pricing["prompt"]
        completion_cost = (completion_tokens / 1000) * pricing["completion"]
        thinking_cost = (thinking_tokens / 1000) * pricing["thinking"]
        total_cost = prompt_cost + completion_cost + thinking_cost

        # Calculate RES
        res = ReasoningEfficiencyScore.calculate(thinking_tokens, completion_tokens)

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
            "reasoning_efficiency": res,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        }

        self.records.append(record)
        self.cost_by_model[model] += total_cost
        self.cost_by_operation[operation] += total_cost
        self.thinking_tokens_total += thinking_tokens

        return record

    def calculate_cost(self, token_data: Dict) -> Dict:
        model = token_data.get("model", "gpt-4")
        pricing = self.PRICING.get(model, self.PRICING["gpt-4"])
        pt = token_data.get("prompt_tokens", 0)
        ct = token_data.get("completion_tokens", 0)
        tt = token_data.get("thinking_tokens", 0)
        pc = (pt / 1000) * pricing["prompt"]
        cc = (ct / 1000) * pricing["completion"]
        tc = (tt / 1000) * pricing["thinking"]
        return {
            "prompt": round(pc, 6),
            "completion": round(cc, 6),
            "thinking": round(tc, 6),
            "total": round(pc + cc + tc, 6),
        }

    def get_analytics(self) -> Dict:
        total_cost = sum(r["cost"]["total"] for r in self.records)
        total_tokens = sum(r["tokens"]["total"] for r in self.records)
        thinking_cost = sum(r["cost"]["thinking"] for r in self.records)
        thinking_pct = (thinking_cost / total_cost * 100) if total_cost > 0 else 0

        model_breakdown = [
            {"model": m, "cost": round(c, 2), "percentage": round(c / total_cost * 100, 1) if total_cost > 0 else 0}
            for m, c in sorted(self.cost_by_model.items(), key=lambda x: x[1], reverse=True)
        ]

        # Aggregate RES
        res_data = [
            {"thinking_tokens": r["tokens"]["thinking"], "completion_tokens": r["tokens"]["completion"]}
            for r in self.records
        ]
        aggregate_res = ReasoningEfficiencyScore.batch_calculate(res_data)

        return {
            "summary": {
                "total_cost": round(total_cost, 2),
                "total_tokens": total_tokens,
                "total_requests": len(self.records),
                "thinking_tokens": self.thinking_tokens_total,
                "thinking_cost": round(thinking_cost, 2),
                "thinking_percentage": round(thinking_pct, 1),
            },
            "reasoning_efficiency": aggregate_res,
            "by_model": model_breakdown,
            "cost_per_request": round(total_cost / len(self.records), 2) if self.records else 0,
        }

    def detect_anomalies(self, threshold_multiplier: float = 3.0) -> List[Dict]:
        """Detect cost anomalies (requests costing >3x the average)"""
        if len(self.records) < 5:
            return []

        avg_cost = sum(r["cost"]["total"] for r in self.records) / len(self.records)
        threshold = avg_cost * threshold_multiplier

        return [
            {
                "request_id": r["request_id"],
                "cost": r["cost"]["total"],
                "threshold": round(threshold, 4),
                "multiplier": round(r["cost"]["total"] / avg_cost, 1) if avg_cost > 0 else 0,
                "model": r["model"],
                "thinking_tokens": r["tokens"]["thinking"],
            }
            for r in self.records
            if r["cost"]["total"] > threshold
        ]
