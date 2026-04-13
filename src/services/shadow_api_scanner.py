"""
DevPulse - Shadow API Scanner
Detect undocumented API endpoints
"""

import re
import logging
from typing import List, Dict, Set
from urllib.parse import urlparse
import ipaddress  # SECURITY: SSRF protection

logger = logging.getLogger(__name__)


class ShadowAPIScanner:
    """Detect undocumented/shadow API endpoints"""
    
    def __init__(self):
        self.known_endpoints: Set[str] = set()
        self.shadow_apis: List[Dict] = []
    
    def detect_shadow_apis(self, requests: List[Dict]) -> List[Dict]:
        """
        Detect shadow APIs by comparing against known endpoints
        
        Args:
            requests: List of API requests from collection
            
        Returns:
            List of detected shadow APIs
        """
        # Extract known endpoints from collection
        known_endpoints = self._extract_endpoints(requests)
        self.known_endpoints = set(known_endpoints)
        
        shadow_apis = []
        
        # In real scenario, would analyze traffic logs
        # For now, we'll detect common shadow API patterns
        for endpoint in known_endpoints:
            # Check for common shadow API patterns
            shadow_patterns = self._detect_shadow_patterns(endpoint)
            shadow_apis.extend(shadow_patterns)
        
        self.shadow_apis = shadow_apis
        return shadow_apis
    
    def _extract_endpoints(self, requests: List[Dict]) -> List[str]:
        """Extract all endpoints from requests"""
        endpoints = []
        
        for request in requests:
            url = request.get("url", "")
            if url:
                endpoint = self._extract_path(url)
                if endpoint:
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_path(self, url: str) -> str:
        """Extract path from URL"""
        try:
            parsed = urlparse(url)
            
            # SECURITY: BLOCK SSRF vulnerabilities
            if not self._is_safe_url(parsed.netloc):
                logger.error(f"SECURITY: SSRF attempt blocked for host: {parsed.netloc}")
                return ""  # Return empty to block processing
            
            path = parsed.path
            
            # Remove query parameters and fragments
            if "?" in path:
                path = path.split("?")[0]
            if "#" in path:
                path = path.split("#")[0]
            
            return path
        except:
            return ""
    
    def _is_safe_url(self, netloc: str) -> bool:
        """Check if URL is safe (not SSRF)"""
        if not netloc:
            return False
        
        # Extract hostname (remove port if present)
        hostname = netloc.split(':')[0]
        
        # Blocklist of unsafe hosts
        unsafe_hosts = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '169.254.169.254',  # AWS metadata
        ]
        
        if hostname in unsafe_hosts:
            return False
        
        # Check for private IP ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            # Not an IP address, check hostname patterns
            if hostname.startswith('169.254.'):
                return False
        
        return True
    
    def _detect_shadow_patterns(self, endpoint: str) -> List[Dict]:
        """Detect common shadow API patterns for an endpoint"""
        shadow_apis = []
        
        # Common shadow API patterns
        patterns = [
            {
                "suffix": "/debug",
                "risk": "HIGH",
                "reason": "Debug endpoint may expose sensitive information"
            },
            {
                "suffix": "/internal",
                "risk": "HIGH",
                "reason": "Internal endpoint not meant for public use"
            },
            {
                "suffix": "/admin",
                "risk": "CRITICAL",
                "reason": "Admin endpoint may allow unauthorized access"
            },
            {
                "suffix": "/system",
                "risk": "HIGH",
                "reason": "System endpoint may expose infrastructure details"
            },
            {
                "suffix": "/config",
                "risk": "HIGH",
                "reason": "Configuration endpoint may expose secrets"
            },
            {
                "suffix": "/test",
                "risk": "MEDIUM",
                "reason": "Test endpoint should not be in production"
            },
            {
                "suffix": "/backup",
                "risk": "HIGH",
                "reason": "Backup endpoint may allow data exfiltration"
            },
            {
                "suffix": "/export",
                "risk": "MEDIUM",
                "reason": "Export endpoint may allow unauthorized data access"
            },
        ]
        
        for pattern in patterns:
            shadow_endpoint = endpoint + pattern["suffix"]
            
            # Check if this shadow endpoint exists
            if self._is_shadow_endpoint(shadow_endpoint):
                shadow_apis.append({
                    "endpoint": shadow_endpoint,
                    "risk_level": pattern["risk"],
                    "reason": pattern["reason"],
                    "recommendation": f"Review and secure or remove {shadow_endpoint}",
                    "first_seen": None,
                    "call_count": 0
                })
        
        return shadow_apis
    
    def _is_shadow_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint looks like a shadow API"""
        # In production, would check against actual traffic logs
        # For now, use heuristics
        
        shadow_keywords = [
            "debug", "internal", "admin", "system", "config",
            "test", "backup", "export", "import", "secret",
            "private", "hidden", "legacy", "old", "deprecated"
        ]
        
        endpoint_lower = endpoint.lower()
        
        for keyword in shadow_keywords:
            if keyword in endpoint_lower:
                return True
        
        return False
    
    def get_shadow_api_count(self) -> int:
        """Get count of detected shadow APIs"""
        return len(self.shadow_apis)
    
    def get_shadow_apis_by_risk(self, risk_level: str = None) -> List[Dict]:
        """Get shadow APIs filtered by risk level"""
        if risk_level:
            return [api for api in self.shadow_apis if api["risk_level"] == risk_level]
        return self.shadow_apis
    
    def get_risk_impact(self) -> int:
        """Calculate risk impact of shadow APIs"""
        impact = 0
        
        for api in self.shadow_apis:
            if api["risk_level"] == "CRITICAL":
                impact += 20
            elif api["risk_level"] == "HIGH":
                impact += 10
            elif api["risk_level"] == "MEDIUM":
                impact += 5
            else:
                impact += 1
        
        return min(100, impact)  # Cap at 100


# Example usage
if __name__ == "__main__":
    scanner = ShadowAPIScanner()
    
    # Sample requests
    requests = [
        {
            "name": "Get Users",
            "url": "https://api.example.com/api/users",
            "method": "GET"
        },
        {
            "name": "Create User",
            "url": "https://api.example.com/api/users",
            "method": "POST"
        },
        {
            "name": "Get Products",
            "url": "https://api.example.com/api/products",
            "method": "GET"
        },
    ]
    
    shadow_apis = scanner.detect_shadow_apis(requests)
    
    print(f"Total shadow APIs detected: {scanner.get_shadow_api_count()}")
    print(f"Risk impact: {scanner.get_risk_impact()}")
    
    print("\nShadow APIs by risk level:")
    for risk in ["CRITICAL", "HIGH", "MEDIUM"]:
        apis = scanner.get_shadow_apis_by_risk(risk)
        if apis:
            print(f"\n{risk}:")
            for api in apis:
                print(f"  - {api['endpoint']}: {api['reason']}")
