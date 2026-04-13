"""
DevPulse Thinking Tokens Library
================================

Standalone library for tracking and attributing LLM reasoning token costs.
Supports OpenAI o1, GPT-4, GPT-3.5, Claude, and custom models.

Usage:
    from thinking_tokens_lib import ThinkingTokenTracker

    tracker = ThinkingTokenTracker()
    result = tracker.track_tokens(
        request_id="req_001",
        model="o1",
        prompt_tokens=500,
        completion_tokens=1000,
        thinking_tokens=5000,
    )
    print(f"Cost: ${result['cost']['total']}")
"""

from .tracker import ThinkingTokenTracker, ReasoningEfficiencyScore

__version__ = "1.0.0"
__all__ = ["ThinkingTokenTracker", "ReasoningEfficiencyScore"]
