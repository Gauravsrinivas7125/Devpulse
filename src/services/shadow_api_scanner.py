"""
DevPulse - Shadow API Workspace Scanner (Market-Ready)
Detects undocumented API endpoints by scanning actual workspace source files
for route/endpoint definitions, and compares against documented endpoints
from Postman collections or OpenAPI specs.

Supports scanning:
  - Python (Flask, FastAPI, Django)
  - JavaScript/TypeScript (Express, Next.js, Koa, Hapi)
  - Java (Spring Boot)
  - Go (Gin, Echo, Chi)
  - Generic route patterns
"""

import os
import re
import logging
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse
import ipaddress

logger = logging.getLogger(__name__)


# ── Route detection patterns for each framework ─────────────────────────

ROUTE_PATTERNS: List[Dict] = [
    # Python - FastAPI
    {"regex": r'@(?:app|router)\.(get|post|put|delete|patch|options|head)\(\s*["\']([^"\']+)["\']',
     "framework": "FastAPI", "lang": "python", "extensions": [".py"]},
    # Python - Flask
    {"regex": r'@(?:app|blueprint|bp)\.(route|get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']',
     "framework": "Flask", "lang": "python", "extensions": [".py"]},
    # Python - Django
    {"regex": r'(?:path|re_path|url)\(\s*["\']([^"\']+)["\']',
     "framework": "Django", "lang": "python", "extensions": [".py"]},
    # JavaScript/TypeScript - Express
    {"regex": r'(?:app|router)\.(get|post|put|delete|patch|all|use)\(\s*["\']([^"\']+)["\']',
     "framework": "Express", "lang": "javascript", "extensions": [".js", ".ts", ".mjs"]},
    # JavaScript - Next.js API routes (file-based routing)
    {"regex": r'export\s+(?:default\s+)?(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH|handler)',
     "framework": "Next.js", "lang": "javascript", "extensions": [".js", ".ts", ".jsx", ".tsx"]},
    # Java - Spring Boot
    {"regex": r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
     "framework": "Spring", "lang": "java", "extensions": [".java"]},
    # Go - Gin
    {"regex": r'(?:r|router|group)\.(GET|POST|PUT|DELETE|PATCH|Handle)\(\s*"([^"]+)"',
     "framework": "Gin", "lang": "go", "extensions": [".go"]},
    # Go - Echo
    {"regex": r'(?:e|echo)\.(GET|POST|PUT|DELETE|PATCH)\(\s*"([^"]+)"',
     "framework": "Echo", "lang": "go", "extensions": [".go"]},
    # Generic URL patterns in code
    {"regex": r'["\']/(api|v\d+|rest)/[a-z0-9_/{}:*-]+["\']',
     "framework": "generic", "lang": "any", "extensions": [".py", ".js", ".ts", ".go", ".java", ".rb"]},
]

# Shadow-indicator keywords — endpoints containing these are flagged
SHADOW_KEYWORDS = [
    "debug", "internal", "admin", "system", "config",
    "test", "backup", "export", "import", "secret",
    "private", "hidden", "legacy", "old", "deprecated",
    "dev", "staging", "metrics", "health", "status",
    "dump", "trace", "profiler", "phpinfo", "actuator",
    "swagger", "graphql", "introspection",
]

SHADOW_RISK_MAP = {
    "admin": "CRITICAL",
    "secret": "CRITICAL",
    "debug": "HIGH",
    "internal": "HIGH",
    "system": "HIGH",
    "config": "HIGH",
    "backup": "HIGH",
    "dump": "HIGH",
    "trace": "HIGH",
    "private": "HIGH",
    "profiler": "HIGH",
    "phpinfo": "HIGH",
    "actuator": "HIGH",
    "introspection": "HIGH",
    "test": "MEDIUM",
    "export": "MEDIUM",
    "import": "MEDIUM",
    "legacy": "MEDIUM",
    "old": "MEDIUM",
    "deprecated": "MEDIUM",
    "dev": "MEDIUM",
    "staging": "MEDIUM",
    "metrics": "LOW",
    "health": "LOW",
    "status": "LOW",
    "swagger": "LOW",
    "graphql": "LOW",
    "hidden": "HIGH",
}


class ShadowAPIScanner:
    """
    Market-ready Shadow API Scanner.
    
    Scans actual workspace files for undocumented API endpoints, compares
    against documented endpoints (Postman/OpenAPI), and flags shadow APIs.
    Designed for VS Code extension integration.
    """
    
    def __init__(self):
        self.known_endpoints: Set[str] = set()
        self.shadow_apis: List[Dict] = []
        self.discovered_endpoints: List[Dict] = []
        self.scan_stats: Dict = {}
    
    # ── Collection-based detection (existing) ────────────────────────────
    
    def detect_shadow_apis(self, requests: List[Dict]) -> List[Dict]:
        """Detect shadow APIs by comparing against known endpoints."""
        known_endpoints = self._extract_endpoints(requests)
        self.known_endpoints = set(known_endpoints)
        
        shadow_apis = []
        for endpoint in known_endpoints:
            shadow_patterns = self._detect_shadow_patterns(endpoint)
            shadow_apis.extend(shadow_patterns)
        
        self.shadow_apis = shadow_apis
        return shadow_apis
    
    # ── Workspace File Scanning (Market-Ready Feature) ───────────────────
    
    def scan_workspace(
        self,
        workspace_path: str,
        documented_endpoints: Optional[Set[str]] = None,
        exclude_dirs: Optional[List[str]] = None,
    ) -> Dict:
        """
        Scan actual workspace files for API endpoints.
        
        Args:
            workspace_path: Root path of the workspace/project
            documented_endpoints: Set of known/documented endpoints (from Postman)
            exclude_dirs: Directories to skip (defaults to common non-source dirs)
            
        Returns:
            Scan results with discovered endpoints, shadow APIs, and stats
        """
        if not os.path.isdir(workspace_path):
            return {"error": f"Workspace path not found: {workspace_path}"}
        
        documented = documented_endpoints or self.known_endpoints
        
        default_excludes = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "dist", "build", ".next", ".nuxt", "coverage", ".tox",
            "vendor", "target", "bin", "obj", ".idea", ".vscode",
        }
        excludes = set(exclude_dirs) if exclude_dirs else default_excludes
        
        # Scan all source files
        all_endpoints: List[Dict] = []
        files_scanned = 0
        
        for root, dirs, files in os.walk(workspace_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in excludes]
            
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".mjs"}:
                    continue
                
                filepath = os.path.join(root, filename)
                files_scanned += 1
                
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except (OSError, IOError):
                    continue
                
                # Extract endpoints from this file
                file_endpoints = self._extract_routes_from_content(
                    content, filepath, ext,
                )
                all_endpoints.extend(file_endpoints)
        
        self.discovered_endpoints = all_endpoints
        
        # Compare against documented endpoints to find shadow APIs
        shadow_apis = self._identify_shadow_apis(all_endpoints, documented)
        self.shadow_apis.extend(shadow_apis)
        
        # Compute stats
        self.scan_stats = {
            "workspace_path": workspace_path,
            "files_scanned": files_scanned,
            "total_endpoints_discovered": len(all_endpoints),
            "documented_endpoints": len(documented),
            "undocumented_endpoints": len([
                e for e in all_endpoints
                if e["endpoint"] not in documented
            ]),
            "shadow_apis_found": len(shadow_apis),
            "risk_impact": self.get_risk_impact(),
        }
        
        return {
            "stats": self.scan_stats,
            "discovered_endpoints": all_endpoints,
            "shadow_apis": shadow_apis,
            "undocumented": [
                e for e in all_endpoints
                if e["endpoint"] not in documented
            ],
        }
    
    def _extract_routes_from_content(
        self, content: str, filepath: str, ext: str,
    ) -> List[Dict]:
        """Extract API route definitions from file content."""
        endpoints = []
        seen: Set[str] = set()
        
        for pattern_def in ROUTE_PATTERNS:
            # Check if this pattern applies to this file type
            if ext not in pattern_def["extensions"] and pattern_def["lang"] != "any":
                continue
            
            try:
                matches = re.finditer(pattern_def["regex"], content, re.IGNORECASE)
            except re.error:
                continue
            
            for match in matches:
                groups = match.groups()
                # The endpoint path is usually the last group
                endpoint = groups[-1] if groups else match.group(0)
                # Clean the endpoint
                endpoint = endpoint.strip("\"' ")
                if not endpoint.startswith("/"):
                    endpoint = "/" + endpoint
                
                # Determine HTTP method if captured
                method = groups[0].upper() if len(groups) > 1 else "ANY"
                if method in ("ROUTE", "USE", "HANDLE"):
                    method = "ANY"
                
                dedup_key = f"{method}:{endpoint}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                
                # Get line number
                line_num = content[:match.start()].count("\n") + 1
                
                endpoints.append({
                    "endpoint": endpoint,
                    "method": method,
                    "framework": pattern_def["framework"],
                    "file": filepath,
                    "line": line_num,
                    "documented": False,  # will be updated later
                })
        
        return endpoints
    
    def _identify_shadow_apis(
        self,
        discovered: List[Dict],
        documented: Set[str],
    ) -> List[Dict]:
        """Identify shadow APIs from discovered endpoints."""
        shadow_apis = []
        
        for ep_info in discovered:
            endpoint = ep_info["endpoint"].lower()
            is_documented = ep_info["endpoint"] in documented
            
            if is_documented:
                ep_info["documented"] = True
                continue
            
            # Check for shadow keywords
            for keyword in SHADOW_KEYWORDS:
                if keyword in endpoint:
                    risk = SHADOW_RISK_MAP.get(keyword, "MEDIUM")
                    shadow_apis.append({
                        "endpoint": ep_info["endpoint"],
                        "method": ep_info["method"],
                        "risk_level": risk,
                        "reason": f"Undocumented endpoint contains '{keyword}' — potential shadow API",
                        "file": ep_info["file"],
                        "line": ep_info["line"],
                        "framework": ep_info["framework"],
                        "recommendation": f"Document or remove {ep_info['endpoint']}",
                        "keyword_match": keyword,
                        "first_seen": None,
                        "call_count": 0,
                    })
                    break  # one match per endpoint
        
        return shadow_apis
    
    # ── Existing helpers ─────────────────────────────────────────────────
    
    def _extract_endpoints(self, requests: List[Dict]) -> List[str]:
        """Extract all endpoints from requests."""
        endpoints = []
        for request in requests:
            url = request.get("url", "")
            if url:
                endpoint = self._extract_path(url)
                if endpoint:
                    endpoints.append(endpoint)
        return endpoints
    
    def _extract_path(self, url: str) -> str:
        """Extract path from URL."""
        try:
            parsed = urlparse(url)
            if parsed.netloc and not self._is_safe_url(parsed.netloc):
                logger.error("SECURITY: SSRF attempt blocked for host: %s", parsed.netloc)
                return ""
            path = parsed.path
            if "?" in path:
                path = path.split("?")[0]
            if "#" in path:
                path = path.split("#")[0]
            return path
        except Exception:
            return ""
    
    def _is_safe_url(self, netloc: str) -> bool:
        """Check if URL is safe (not SSRF)."""
        if not netloc:
            return False
        hostname = netloc.split(":")[0]
        unsafe_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"]
        if hostname in unsafe_hosts:
            return False
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            if hostname.startswith("169.254."):
                return False
        return True
    
    def _detect_shadow_patterns(self, endpoint: str) -> List[Dict]:
        """Detect common shadow API patterns for an endpoint."""
        shadow_apis = []
        patterns = [
            {"suffix": "/debug", "risk": "HIGH", "reason": "Debug endpoint may expose sensitive information"},
            {"suffix": "/internal", "risk": "HIGH", "reason": "Internal endpoint not meant for public use"},
            {"suffix": "/admin", "risk": "CRITICAL", "reason": "Admin endpoint may allow unauthorized access"},
            {"suffix": "/system", "risk": "HIGH", "reason": "System endpoint may expose infrastructure details"},
            {"suffix": "/config", "risk": "HIGH", "reason": "Configuration endpoint may expose secrets"},
            {"suffix": "/test", "risk": "MEDIUM", "reason": "Test endpoint should not be in production"},
            {"suffix": "/backup", "risk": "HIGH", "reason": "Backup endpoint may allow data exfiltration"},
            {"suffix": "/export", "risk": "MEDIUM", "reason": "Export endpoint may allow unauthorized data access"},
        ]
        for pattern in patterns:
            shadow_endpoint = endpoint + pattern["suffix"]
            if self._is_shadow_endpoint(shadow_endpoint):
                shadow_apis.append({
                    "endpoint": shadow_endpoint,
                    "risk_level": pattern["risk"],
                    "reason": pattern["reason"],
                    "recommendation": f"Review and secure or remove {shadow_endpoint}",
                    "first_seen": None,
                    "call_count": 0,
                })
        return shadow_apis
    
    def _is_shadow_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint looks like a shadow API."""
        endpoint_lower = endpoint.lower()
        return any(kw in endpoint_lower for kw in SHADOW_KEYWORDS)
    
    # ── Public API ───────────────────────────────────────────────────────
    
    def get_shadow_api_count(self) -> int:
        """Get count of detected shadow APIs."""
        return len(self.shadow_apis)
    
    def get_shadow_apis_by_risk(self, risk_level: Optional[str] = None) -> List[Dict]:
        """Get shadow APIs filtered by risk level."""
        if risk_level:
            return [api for api in self.shadow_apis if api["risk_level"] == risk_level]
        return self.shadow_apis
    
    def get_risk_impact(self) -> int:
        """Calculate risk impact of shadow APIs."""
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
        return min(100, impact)
    
    def get_scan_results(self) -> Dict:
        """Get full scan results for API response."""
        return {
            "stats": self.scan_stats,
            "shadow_apis": self.shadow_apis,
            "discovered_endpoints": self.discovered_endpoints,
            "risk_impact": self.get_risk_impact(),
        }
    
    def to_dict(self) -> Dict:
        """Full status for API responses."""
        return {
            "shadow_api_count": self.get_shadow_api_count(),
            "risk_impact": self.get_risk_impact(),
            "shadow_apis": self.shadow_apis[-20:],
            "scan_stats": self.scan_stats,
            "discovered_endpoints_count": len(self.discovered_endpoints),
        }
