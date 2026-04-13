"""
DevPulse - Autonomous Kill Switch Service (Market-Ready, Patent 3 Core)
Real-time detection and blocking of dangerous API calls with autonomous
agent loop detection, budget-based auto-kill, and audit trail.

Patent 3: "Autonomous Agent Kill Switch with Budget Enforcement"
Key innovation: Detects infinite/runaway autonomous agent loops and
automatically terminates connections when budget thresholds are exceeded.
"""

import re
import logging
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from collections import defaultdict
from .slack_alerts import alerts_service

logger = logging.getLogger(__name__)


class KillSwitch:
    """
    Patent 3 Core: Autonomous Kill Switch with Budget Enforcement.
    
    Detects:
    1. Traditional injection/attack patterns (SQL, XSS, etc.)
    2. Autonomous agent infinite loops (repeated calls, circular patterns)
    3. Budget threshold breaches (per-model, per-operation, global)
    
    Auto-kills connections when thresholds are exceeded.
    """
    
    # Budget defaults (USD)
    DEFAULT_BUDGET_LIMIT = 100.0  # $100 global budget
    DEFAULT_MODEL_BUDGET = 50.0   # $50 per model
    DEFAULT_OP_BUDGET = 25.0      # $25 per operation
    
    # Loop detection
    LOOP_WINDOW_SECONDS = 60      # Check last 60 seconds
    LOOP_REPEAT_THRESHOLD = 10    # Same call 10+ times = loop
    LOOP_SEQUENCE_LENGTH = 3      # Detect A→B→C→A→B→C patterns
    LOOP_SEQUENCE_REPEATS = 3     # Sequence must repeat 3+ times
    
    def __init__(self):
        self.enabled = True
        self.blocked_requests = []
        self.threat_patterns = self._initialize_patterns()
        self.rate_limits = {}  # endpoint -> (count, timestamp)
        
        # Patent 3: Budget tracking
        self.budget_limit = self.DEFAULT_BUDGET_LIMIT
        self.model_budgets: Dict[str, float] = {}  # model -> limit
        self.operation_budgets: Dict[str, float] = {}  # operation -> limit
        self.cost_accumulator: Dict[str, float] = defaultdict(float)
        self.model_cost_accumulator: Dict[str, float] = defaultdict(float)
        self.operation_cost_accumulator: Dict[str, float] = defaultdict(float)
        self.total_cost = 0.0
        
        # Patent 3: Loop detection
        self.call_history: List[Dict] = []  # Recent call log for loop detection
        self.loop_detections: List[Dict] = []  # Detected loops
        self.kill_audit_trail: List[Dict] = []  # Complete audit trail
    
    def _initialize_patterns(self) -> List[Dict]:
        """Initialize threat detection patterns"""
        return [
            {
                "name": "SQL Injection",
                "patterns": [
                    r"(\bUNION\b.*\bSELECT\b)",
                    r"(\bDROP\b.*\bTABLE\b)",
                    r"(\bINSERT\b.*\bINTO\b)",
                    r"(';.*--)",
                    r"(\bOR\b.*=.*)",
                ],
                "severity": "CRITICAL",
                "action": "BLOCK"
            },
            {
                "name": "Command Injection",
                "patterns": [
                    r"(;.*\|)",
                    r"(`.*`)",
                    r"(\$\(.*\))",
                    r"(&&.*rm)",
                    r"(\|\|.*cat)",
                ],
                "severity": "CRITICAL",
                "action": "BLOCK"
            },
            {
                "name": "Path Traversal",
                "patterns": [
                    r"(\.\.\/)+",
                    r"(%2e%2e\/)+",
                    r"(\.\.\\)+",
                ],
                "severity": "HIGH",
                "action": "BLOCK"
            },
            {
                "name": "XXE Injection",
                "patterns": [
                    r"(<!ENTITY.*SYSTEM)",
                    r"(DOCTYPE.*\[)",
                ],
                "severity": "HIGH",
                "action": "BLOCK"
            },
            {
                "name": "XSS Attempt",
                "patterns": [
                    r"(<script[^>]*>)",
                    r"(javascript:)",
                    r"(onerror=)",
                    r"(onload=)",
                ],
                "severity": "HIGH",
                "action": "BLOCK"
            },
        ]
    
    def analyze_request(self, request_data: Dict) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Analyze request for threats
        
        Returns:
            (should_block, reason, severity)
        """
        if not self.enabled:
            return False, None, None
        
        # Check threat patterns
        for pattern_group in self.threat_patterns:
            for pattern in pattern_group["patterns"]:
                # Check in URL
                if "url" in request_data:
                    if re.search(pattern, request_data["url"], re.IGNORECASE):
                        return True, pattern_group["name"], pattern_group["severity"]
                
                # Check in body
                if "body" in request_data:
                    if re.search(pattern, str(request_data["body"]), re.IGNORECASE):
                        return True, pattern_group["name"], pattern_group["severity"]
                
                # Check in headers
                if "headers" in request_data:
                    for header_value in request_data["headers"].values():
                        if re.search(pattern, str(header_value), re.IGNORECASE):
                            return True, pattern_group["name"], pattern_group["severity"]
        
        # Check rate limits
        endpoint = request_data.get("endpoint", "unknown")
        if self._exceeds_rate_limit(endpoint):
            return True, "Rate Limit Exceeded", "MEDIUM"
        
        # Check for missing authentication on sensitive endpoints
        if self._requires_auth(endpoint) and not request_data.get("authenticated"):
            return True, "Unauthorized Access", "CRITICAL"
        
        return False, None, None
    
    def block_request(self, request_id: str, reason: str, user_id: str = "unknown") -> Dict:
        """Block a request and log it, then send Slack alert"""
        block_record = {
            "request_id": request_id,
            "reason": reason,
            "blocked_at": datetime.utcnow().isoformat(),
            "status": "BLOCKED"
        }
        
        self.blocked_requests.append(block_record)
        
        # Send Slack alert for kill switch trigger (Trigger 4: Investor demo moment)
        alerts_service.send_kill_switch_alert(
            reason=reason,
            request_id=request_id,
            user_id=user_id,
            blocked_count=len(self.blocked_requests)
        )
        
        return block_record
    
    def _exceeds_rate_limit(self, endpoint: str, limit: int = 100, window: int = 60) -> bool:
        """Check if endpoint exceeds rate limit"""
        now = datetime.utcnow().timestamp()
        
        if endpoint not in self.rate_limits:
            self.rate_limits[endpoint] = (1, now)
            return False
        
        count, timestamp = self.rate_limits[endpoint]
        
        # Reset if outside window
        if now - timestamp > window:
            self.rate_limits[endpoint] = (1, now)
            return False
        
        # Check limit
        if count >= limit:
            return True
        
        # Increment count
        self.rate_limits[endpoint] = (count + 1, timestamp)
        return False
    
    def _requires_auth(self, endpoint: str) -> bool:
        """Check if endpoint requires authentication"""
        protected_endpoints = [
            "/admin",
            "/api/admin",
            "/api/internal",
            "/api/system",
            "/api/config",
        ]
        
        return any(endpoint.startswith(pe) for pe in protected_endpoints)
    
    def enable(self) -> None:
        """Enable kill switch"""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable kill switch"""
        self.enabled = False
    
    def is_enabled(self) -> bool:
        """Check if kill switch is enabled"""
        return self.enabled
    
    def get_blocked_count(self) -> int:
        """Get total blocked requests"""
        return len(self.blocked_requests)
    
    def get_active_patterns(self) -> List[str]:
        """Get list of active threat patterns"""
        return [p["name"] for p in self.threat_patterns]
    
    def get_blocked_requests(self, limit: int = 100) -> List[Dict]:
        """Get recent blocked requests"""
        return self.blocked_requests[-limit:]
    
    def clear_blocked_requests(self) -> None:
        """Clear blocked requests log"""
        self.blocked_requests = []
    
    def add_custom_pattern(self, name: str, pattern: str, severity: str = "HIGH") -> None:
        """Add custom threat pattern"""
        self.threat_patterns.append({
            "name": name,
            "patterns": [pattern],
            "severity": severity,
            "action": "BLOCK",
        })
    
    # ── Patent 3: Budget Management ──────────────────────────────────────
    
    def set_budget(self, global_limit: float = 100.0,
                   model_limits: Optional[Dict[str, float]] = None,
                   operation_limits: Optional[Dict[str, float]] = None) -> None:
        """Configure budget limits for auto-kill."""
        self.budget_limit = global_limit
        if model_limits:
            self.model_budgets.update(model_limits)
        if operation_limits:
            self.operation_budgets.update(operation_limits)
    
    def record_cost(self, cost: float, model: str = "unknown",
                    operation: str = "unknown") -> Dict:
        """
        Record a cost event and check budget thresholds.
        Returns kill decision if budget exceeded.
        """
        self.total_cost += cost
        self.model_cost_accumulator[model] += cost
        self.operation_cost_accumulator[operation] += cost
        
        # Check global budget
        if self.total_cost >= self.budget_limit:
            return self._trigger_budget_kill(
                "global_budget_exceeded",
                f"Global budget ${self.budget_limit:.2f} exceeded (spent: ${self.total_cost:.2f})",
                "CRITICAL",
                model=model,
                operation=operation,
            )
        
        # Check model budget
        model_limit = self.model_budgets.get(model, self.DEFAULT_MODEL_BUDGET)
        if self.model_cost_accumulator[model] >= model_limit:
            return self._trigger_budget_kill(
                "model_budget_exceeded",
                f"Model '{model}' budget ${model_limit:.2f} exceeded (spent: ${self.model_cost_accumulator[model]:.2f})",
                "HIGH",
                model=model,
                operation=operation,
            )
        
        # Check operation budget
        op_limit = self.operation_budgets.get(operation, self.DEFAULT_OP_BUDGET)
        if self.operation_cost_accumulator[operation] >= op_limit:
            return self._trigger_budget_kill(
                "operation_budget_exceeded",
                f"Operation '{operation}' budget ${op_limit:.2f} exceeded (spent: ${self.operation_cost_accumulator[operation]:.2f})",
                "HIGH",
                model=model,
                operation=operation,
            )
        
        return {"action": "ALLOW", "total_cost": round(self.total_cost, 4)}
    
    def _trigger_budget_kill(self, kill_type: str, reason: str,
                             severity: str, **kwargs: str) -> Dict:
        """Execute a budget-based auto-kill (Patent 3)."""
        kill_record = {
            "type": kill_type,
            "reason": reason,
            "severity": severity,
            "action": "KILL",
            "total_cost": round(self.total_cost, 4),
            "timestamp": datetime.utcnow().isoformat(),
            **kwargs,
        }
        self.kill_audit_trail.append(kill_record)
        logger.warning("KILL SWITCH TRIGGERED: %s", reason)
        
        # Send Slack alert
        alerts_service.send_kill_switch_alert(
            reason=reason,
            request_id=kill_type,
            user_id="budget_enforcer",
            blocked_count=len(self.kill_audit_trail),
        )
        
        return kill_record
    
    # ── Patent 3: Loop Detection ─────────────────────────────────────────
    
    def record_agent_call(self, agent_id: str, endpoint: str,
                          model: str = "unknown",
                          operation: str = "unknown") -> Dict:
        """
        Record an autonomous agent API call and detect loops.
        Returns kill decision if infinite loop detected.
        """
        now = datetime.utcnow()
        call_entry = {
            "agent_id": agent_id,
            "endpoint": endpoint,
            "model": model,
            "operation": operation,
            "timestamp": now.isoformat(),
            "ts": now.timestamp(),
        }
        self.call_history.append(call_entry)
        
        # Prune old entries outside window
        cutoff = now.timestamp() - self.LOOP_WINDOW_SECONDS
        self.call_history = [c for c in self.call_history if c["ts"] > cutoff]
        
        # Detect repeated single-call loops
        agent_calls = [c for c in self.call_history if c["agent_id"] == agent_id]
        endpoint_counts: Dict[str, int] = defaultdict(int)
        for c in agent_calls:
            endpoint_counts[c["endpoint"]] += 1
        
        for ep, count in endpoint_counts.items():
            if count >= self.LOOP_REPEAT_THRESHOLD:
                return self._trigger_loop_kill(
                    agent_id, "repeat_loop",
                    f"Agent '{agent_id}' called '{ep}' {count} times in {self.LOOP_WINDOW_SECONDS}s",
                    endpoint=ep,
                )
        
        # Detect circular sequence loops (A→B→C→A→B→C)
        if len(agent_calls) >= self.LOOP_SEQUENCE_LENGTH * self.LOOP_SEQUENCE_REPEATS:
            endpoints_seq = [c["endpoint"] for c in agent_calls]
            loop_found = self._detect_circular_pattern(endpoints_seq)
            if loop_found:
                return self._trigger_loop_kill(
                    agent_id, "circular_loop",
                    f"Agent '{agent_id}' stuck in circular pattern: {' → '.join(loop_found)}",
                    pattern=loop_found,
                )
        
        return {"action": "ALLOW", "agent_id": agent_id}
    
    def _detect_circular_pattern(self, sequence: List[str]) -> Optional[List[str]]:
        """Detect repeating circular patterns in a call sequence."""
        n = len(sequence)
        for pattern_len in range(self.LOOP_SEQUENCE_LENGTH, n // self.LOOP_SEQUENCE_REPEATS + 1):
            pattern = sequence[-pattern_len:]
            repeats = 0
            pos = n - pattern_len
            while pos >= pattern_len:
                chunk = sequence[pos - pattern_len:pos]
                if chunk == pattern:
                    repeats += 1
                    pos -= pattern_len
                else:
                    break
            if repeats >= self.LOOP_SEQUENCE_REPEATS - 1:
                return pattern
        return None
    
    def _trigger_loop_kill(self, agent_id: str, loop_type: str,
                           reason: str, **kwargs: object) -> Dict:
        """Execute a loop-based auto-kill (Patent 3)."""
        kill_record = {
            "type": loop_type,
            "agent_id": agent_id,
            "reason": reason,
            "severity": "CRITICAL",
            "action": "KILL",
            "timestamp": datetime.utcnow().isoformat(),
        }
        # Add any extra context (endpoint, pattern, etc.)
        for k, v in kwargs.items():
            kill_record[k] = v
        
        self.loop_detections.append(kill_record)
        self.kill_audit_trail.append(kill_record)
        logger.warning("LOOP KILL: %s", reason)
        
        alerts_service.send_kill_switch_alert(
            reason=reason,
            request_id=f"loop_{agent_id}",
            user_id=agent_id,
            blocked_count=len(self.kill_audit_trail),
        )
        
        return kill_record
    
    # ── Audit & Status ───────────────────────────────────────────────────
    
    def get_audit_trail(self, limit: int = 50) -> List[Dict]:
        """Get the full kill audit trail."""
        return self.kill_audit_trail[-limit:]
    
    def get_budget_status(self) -> Dict:
        """Get current budget utilization."""
        return {
            "global": {
                "limit": self.budget_limit,
                "spent": round(self.total_cost, 4),
                "remaining": round(max(0, self.budget_limit - self.total_cost), 4),
                "utilization_pct": round(self.total_cost / self.budget_limit * 100, 1) if self.budget_limit > 0 else 0,
            },
            "by_model": {
                model: {
                    "spent": round(spent, 4),
                    "limit": self.model_budgets.get(model, self.DEFAULT_MODEL_BUDGET),
                }
                for model, spent in self.model_cost_accumulator.items()
            },
            "by_operation": {
                op: {
                    "spent": round(spent, 4),
                    "limit": self.operation_budgets.get(op, self.DEFAULT_OP_BUDGET),
                }
                for op, spent in self.operation_cost_accumulator.items()
            },
        }
    
    def get_loop_detections(self) -> List[Dict]:
        """Get all detected agent loops."""
        return self.loop_detections
    
    def reset_budgets(self) -> None:
        """Reset all budget accumulators (e.g. start of new billing period)."""
        self.total_cost = 0.0
        self.model_cost_accumulator.clear()
        self.operation_cost_accumulator.clear()
    
    def to_dict(self) -> Dict:
        """Full status dictionary for API responses."""
        return {
            "enabled": self.enabled,
            "blocked_count": len(self.blocked_requests),
            "kill_count": len(self.kill_audit_trail),
            "loop_detections": len(self.loop_detections),
            "budget": self.get_budget_status(),
            "recent_blocks": self.blocked_requests[-5:],
            "recent_kills": self.kill_audit_trail[-5:],
            "active_patterns": self.get_active_patterns(),
        }
