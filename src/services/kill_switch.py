"""
DevPulse - Autonomous Kill Switch Service
Real-time detection and blocking of dangerous API calls
"""

import re
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from .slack_alerts import alerts_service


class KillSwitch:
    """Autonomous kill switch for blocking dangerous API calls"""
    
    def __init__(self):
        self.enabled = True
        self.blocked_requests = []
        self.threat_patterns = self._initialize_patterns()
        self.rate_limits = {}  # endpoint -> (count, timestamp)
    
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
            "action": "BLOCK"
        })


# Example usage
if __name__ == "__main__":
    kill_switch = KillSwitch()
    
    # Test benign request
    benign_request = {
        "url": "https://api.example.com/users",
        "method": "GET",
        "headers": {"Authorization": "Bearer token123"},
        "authenticated": True,
        "endpoint": "/api/users"
    }
    
    should_block, reason, severity = kill_switch.analyze_request(benign_request)
    print(f"Benign request - Block: {should_block}, Reason: {reason}")
    
    # Test SQL injection attempt
    sql_injection_request = {
        "url": "https://api.example.com/users?id=1' UNION SELECT * FROM admin--",
        "method": "GET",
        "headers": {},
        "endpoint": "/api/users"
    }
    
    should_block, reason, severity = kill_switch.analyze_request(sql_injection_request)
    print(f"SQL Injection - Block: {should_block}, Reason: {reason}, Severity: {severity}")
    
    # Test unauthorized admin access
    admin_request = {
        "url": "https://api.example.com/admin/users",
        "method": "GET",
        "headers": {},
        "authenticated": False,
        "endpoint": "/admin/users"
    }
    
    should_block, reason, severity = kill_switch.analyze_request(admin_request)
    print(f"Unauthorized Admin - Block: {should_block}, Reason: {reason}, Severity: {severity}")
    
    print(f"\nTotal blocked: {kill_switch.get_blocked_count()}")
    print(f"Active patterns: {kill_switch.get_active_patterns()}")
