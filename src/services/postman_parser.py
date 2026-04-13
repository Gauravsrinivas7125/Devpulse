"""
DevPulse - Postman Collection Parser (Market-Ready)
Parses Postman v2.1 JSON collections, triggers OWASP security scans,
and runs credential detection on every extracted endpoint.
This is the "Postman Refugee Engine" - the primary acquisition channel.
"""

import json
import re
import uuid
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

# Credential patterns for detection (compiled for performance)
CREDENTIAL_PATTERNS: List[Dict[str, Any]] = [
    {"name": "AWS Access Key", "pattern": re.compile(r"AKIA[0-9A-Z]{16}"), "severity": "CRITICAL"},
    {"name": "AWS Secret Key", "pattern": re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), "severity": "CRITICAL"},
    {"name": "GitHub Token", "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), "severity": "CRITICAL"},
    {"name": "Slack Token", "pattern": re.compile(r"xox[bporas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}"), "severity": "CRITICAL"},
    {"name": "Stripe Key", "pattern": re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}"), "severity": "CRITICAL"},
    {"name": "Google API Key", "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "severity": "HIGH"},
    {"name": "JWT Token", "pattern": re.compile(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"), "severity": "HIGH"},
    {"name": "Bearer Token", "pattern": re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]+=*"), "severity": "MEDIUM"},
    {"name": "Basic Auth", "pattern": re.compile(r"(?i)basic\s+[A-Za-z0-9+/=]{10,}"), "severity": "HIGH"},
    {"name": "Private Key", "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "severity": "CRITICAL"},
    {"name": "Password in URL", "pattern": re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[^\s&]{3,}"), "severity": "HIGH"},
    {"name": "API Key Parameter", "pattern": re.compile(r"(?i)(?:api[_\-]?key|apikey|access[_\-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_.]{16,}"), "severity": "HIGH"},
    {"name": "Database Connection String", "pattern": re.compile(r"(?:mongodb|postgres|mysql|redis|amqp)://[^\s]+@[^\s]+"), "severity": "CRITICAL"},
    {"name": "SendGrid Key", "pattern": re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), "severity": "CRITICAL"},
    {"name": "Twilio Key", "pattern": re.compile(r"SK[0-9a-fA-F]{32}"), "severity": "HIGH"},
]

# OWASP API Security Top 10 (2023) patterns
OWASP_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "indicators": [
            re.compile(r"(?i)/(?:users?|accounts?|profiles?|orders?)/\{?\{?[a-z_]*id\}?\}?"),
            re.compile(r"(?i)\bid=\d+"),
        ],
        "severity": "HIGH",
        "description": "Endpoint accesses resources by ID without authorization checks",
    },
    {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "indicators": [
            re.compile(r"(?i)/(?:login|auth|signin|signup|register|token|oauth)"),
            re.compile(r"(?i)(?:password|credential|secret)"),
        ],
        "severity": "CRITICAL",
        "check_auth_header": True,
        "description": "Authentication endpoint may lack proper security controls",
    },
    {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "indicators": [
            re.compile(r"(?i)(?:PUT|PATCH)\s"),
            re.compile(r"(?i)\"(?:role|admin|is_admin|permission|privilege)\""),
        ],
        "severity": "HIGH",
        "description": "Endpoint may allow unauthorized property modification",
    },
    {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "indicators": [
            re.compile(r"(?i)/(?:upload|import|export|download|bulk|batch)"),
            re.compile(r"(?i)(?:limit|offset|page_size|per_page)=\d{3,}"),
        ],
        "severity": "MEDIUM",
        "description": "Endpoint may lack rate limiting or resource consumption controls",
    },
    {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "indicators": [
            re.compile(r"(?i)/(?:admin|internal|management|system|debug|config)"),
            re.compile(r"(?i)/api/v\d+/(?:admin|manage|control)"),
        ],
        "severity": "CRITICAL",
        "description": "Administrative endpoint may be accessible without proper authorization",
    },
    {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "indicators": [
            re.compile(r"(?i)/(?:checkout|payment|transfer|withdraw|purchase|order)"),
            re.compile(r"(?i)/(?:invite|referral|coupon|promo|discount)"),
        ],
        "severity": "HIGH",
        "description": "Business-critical endpoint may lack abuse prevention",
    },
    {
        "id": "API7:2023",
        "name": "Server Side Request Forgery",
        "indicators": [
            re.compile(r"(?i)(?:url|uri|link|redirect|callback|webhook)\s*[=:]"),
            re.compile(r"(?i)/(?:fetch|proxy|redirect|callback|webhook)"),
        ],
        "severity": "HIGH",
        "description": "Endpoint accepts URLs that could be used for SSRF attacks",
    },
    {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "indicators": [
            re.compile(r"(?i)http://(?!localhost|127\.0\.0\.1)"),
            re.compile(r"(?i)(?:x-powered-by|server|x-aspnet-version)"),
        ],
        "severity": "MEDIUM",
        "description": "Endpoint uses insecure configuration (HTTP, verbose headers)",
    },
    {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "indicators": [
            re.compile(r"(?i)/api/v[0-9]+/"),
            re.compile(r"(?i)/(?:beta|staging|dev|test|sandbox|old|legacy|deprecated)"),
        ],
        "severity": "MEDIUM",
        "description": "Endpoint may be an outdated or unmanaged API version",
    },
    {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "indicators": [
            re.compile(r"(?i)/(?:webhook|callback|hook|notify|integration)"),
            re.compile(r"(?i)(?:third.?party|external|partner)"),
        ],
        "severity": "MEDIUM",
        "description": "Endpoint consumes external data without proper validation",
    },
]


@dataclass
class CredentialFinding:
    """A credential detected in a collection"""
    credential_type: str
    location: str  # "header", "url", "body", "auth"
    request_name: str
    severity: str
    masked_value: str  # First 4 chars + "***"
    endpoint: str


@dataclass
class OWASPFinding:
    """An OWASP security finding from collection analysis"""
    owasp_id: str
    owasp_name: str
    severity: str
    description: str
    affected_endpoint: str
    request_name: str
    recommendation: str


@dataclass
class PostmanRequest:
    """Internal representation of a parsed Postman request"""
    id: str
    name: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    auth: Optional[Dict[str, Any]]
    tests: Optional[str]
    pre_request_script: Optional[str]
    description: Optional[str]
    created_at: str
    credential_findings: List[Dict[str, str]] = field(default_factory=list)
    owasp_findings: List[Dict[str, str]] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class PostmanParser:
    """
    Market-ready Postman collection parser with integrated OWASP security
    scanning and credential detection. Automatically runs security analysis
    on every imported collection.
    """
    
    def __init__(self):
        self.requests: List[PostmanRequest] = []
        self.collection_info: Dict[str, Any] = {}
        self.credential_findings: List[CredentialFinding] = []
        self.owasp_findings: List[OWASPFinding] = []
    
    def parse_collection(self, file_path: str) -> Dict[str, Any]:
        """Parse a Postman collection file with security scanning"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                collection_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            return {"error": f"Failed to parse collection: {str(e)}"}
        
        return self.parse_collection_data(collection_data)
    
    def _parse_items(self, items: List[Dict], parent_folder: str = ""):
        """Recursively parse collection items (handles nested folders)"""
        for item in items:
            if "item" in item and isinstance(item["item"], list):
                folder_name = item.get("name", "")
                self._parse_items(item["item"], parent_folder=folder_name)
            elif "request" in item:
                request_data = item["request"]
                parsed_request = self._parse_request(request_data, item.get("name", "Unknown"))
                if parsed_request:
                    self.requests.append(parsed_request)
    
    def _parse_request(self, request_data: Dict, name: str) -> Optional[PostmanRequest]:
        """Parse individual Postman request"""
        try:
            url_obj = request_data.get("url", {})
            if isinstance(url_obj, str):
                url = url_obj
            elif isinstance(url_obj, dict):
                url = url_obj.get("raw", "")
            else:
                url = ""
            
            if not url:
                return None
            
            method = request_data.get("method", "GET").upper()
            
            headers = {}
            header_list = request_data.get("header", [])
            for header in header_list:
                if isinstance(header, dict):
                    key = header.get("key", "")
                    value = header.get("value", "")
                    if key:
                        headers[key] = value
            
            body = None
            body_obj = request_data.get("body", {})
            if isinstance(body_obj, dict):
                if body_obj.get("mode") == "raw":
                    body = body_obj.get("raw", "")
                elif body_obj.get("mode") == "formdata":
                    body = json.dumps(body_obj.get("formdata", []))
                elif body_obj.get("mode") == "urlencoded":
                    body = json.dumps(body_obj.get("urlencoded", []))
            
            auth = request_data.get("auth", {})
            tests = request_data.get("tests", None)
            pre_request_script = request_data.get("pre_request_script", None)
            description = request_data.get("description", "")
            
            request = PostmanRequest(
                id=str(uuid.uuid4()),
                name=name,
                method=method,
                url=url,
                headers=headers,
                body=body,
                auth=auth if auth else None,
                tests=tests,
                pre_request_script=pre_request_script,
                description=description,
                created_at=datetime.utcnow().isoformat(),
            )
            
            return request
            
        except Exception as e:
            logger.warning("Error parsing request %s: %s", name, str(e))
            return None
    
    # ── Credential Detection ──────────────────────────────────────────
    
    def _mask_value(self, value: str) -> str:
        """Mask a credential value for safe display"""
        if len(value) <= 4:
            return "***"
        return value[:4] + "***" + value[-2:]
    
    def _scan_text_for_credentials(
        self, text: str, location: str, request_name: str, endpoint: str,
    ) -> List[CredentialFinding]:
        """Scan a text blob for credential patterns"""
        findings: List[CredentialFinding] = []
        if not text:
            return findings
        for cred_pattern in CREDENTIAL_PATTERNS:
            matches = cred_pattern["pattern"].findall(text)
            for match in matches:
                match_str = match if isinstance(match, str) else str(match)
                findings.append(CredentialFinding(
                    credential_type=cred_pattern["name"],
                    location=location,
                    request_name=request_name,
                    severity=cred_pattern["severity"],
                    masked_value=self._mask_value(match_str),
                    endpoint=endpoint,
                ))
        return findings
    
    def detect_credentials(self, request: PostmanRequest) -> List[CredentialFinding]:
        """Run credential detection on a single parsed request"""
        findings: List[CredentialFinding] = []
        
        # Scan URL
        findings.extend(self._scan_text_for_credentials(
            request.url, "url", request.name, request.url,
        ))
        
        # Scan headers
        for key, value in request.headers.items():
            findings.extend(self._scan_text_for_credentials(
                f"{key}: {value}", "header", request.name, request.url,
            ))
        
        # Scan body
        if request.body:
            findings.extend(self._scan_text_for_credentials(
                request.body, "body", request.name, request.url,
            ))
        
        # Scan auth config
        if request.auth:
            findings.extend(self._scan_text_for_credentials(
                json.dumps(request.auth), "auth", request.name, request.url,
            ))
        
        return findings
    
    # ── OWASP API Security Scanning ───────────────────────────────────
    
    def _get_owasp_recommendation(self, owasp_id: str) -> str:
        """Return actionable remediation for each OWASP category"""
        recommendations = {
            "API1:2023": "Implement object-level authorization checks. Validate that the authenticated user has permission to access the requested resource ID.",
            "API2:2023": "Use strong authentication mechanisms (OAuth 2.0, JWT with rotation). Enforce MFA for sensitive operations. Never expose credentials in responses.",
            "API3:2023": "Implement property-level authorization. Use allowlists for updatable fields. Never allow clients to set role/permission fields directly.",
            "API4:2023": "Implement rate limiting, pagination limits, and payload size restrictions. Use async processing for bulk operations.",
            "API5:2023": "Implement role-based access control (RBAC). Deny admin endpoints by default. Use separate auth for administrative functions.",
            "API6:2023": "Implement CAPTCHA, rate limiting, and business logic abuse detection. Monitor for automated attacks on business flows.",
            "API7:2023": "Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains. Disable redirects to arbitrary URLs.",
            "API8:2023": "Use HTTPS everywhere. Remove verbose error messages and server headers. Implement proper CORS policies.",
            "API9:2023": "Maintain an API inventory. Deprecate and remove old versions. Use API gateways to manage versioning.",
            "API10:2023": "Validate all data from third-party APIs. Implement circuit breakers. Use allowlists for external integrations.",
        }
        return recommendations.get(owasp_id, "Review the endpoint for security best practices.")
    
    def scan_owasp(self, request: PostmanRequest) -> List[OWASPFinding]:
        """Run OWASP API Security Top 10 (2023) analysis on a single request"""
        findings: List[OWASPFinding] = []
        
        # Build searchable text from all request parts
        search_text = f"{request.method} {request.url}"
        if request.body:
            search_text += f" {request.body}"
        for key, value in request.headers.items():
            search_text += f" {key}: {value}"
        
        for owasp_rule in OWASP_PATTERNS:
            matched = False
            for indicator in owasp_rule["indicators"]:
                if indicator.search(search_text):
                    matched = True
                    break
            
            # Special check: auth endpoints without auth header
            if owasp_rule.get("check_auth_header") and matched:
                has_auth_header = any(
                    k.lower() in ("authorization", "x-api-key")
                    for k in request.headers
                )
                if has_auth_header:
                    # Auth endpoint with auth header is expected
                    continue
            
            if matched:
                findings.append(OWASPFinding(
                    owasp_id=owasp_rule["id"],
                    owasp_name=owasp_rule["name"],
                    severity=owasp_rule["severity"],
                    description=owasp_rule["description"],
                    affected_endpoint=f"{request.method} {request.url}",
                    request_name=request.name,
                    recommendation=self._get_owasp_recommendation(owasp_rule["id"]),
                ))
        
        return findings
    
    # ── Main Parse + Scan Pipeline ────────────────────────────────────
    
    def parse_collection_data(self, collection_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a Postman collection and automatically run security scans.
        This is the primary import pipeline - every collection goes through
        credential detection and OWASP analysis on import.
        """
        # Reset state for a fresh parse
        self.requests = []
        self.collection_info = {}
        self.credential_findings = []
        self.owasp_findings = []

        # Extract collection info
        self.collection_info = {
            "name": collection_data.get("info", {}).get("name", "Unknown"),
            "description": collection_data.get("info", {}).get("description", ""),
            "version": collection_data.get("info", {}).get("version", "1.0"),
            "schema": collection_data.get("info", {}).get("schema", ""),
        }

        # Parse requests
        items = collection_data.get("item", [])
        self._parse_items(items)

        # Run security scans on every request
        for request in self.requests:
            cred_findings = self.detect_credentials(request)
            owasp_findings = self.scan_owasp(request)
            
            request.credential_findings = [asdict(f) for f in cred_findings]
            request.owasp_findings = [asdict(f) for f in owasp_findings]
            
            self.credential_findings.extend(cred_findings)
            self.owasp_findings.extend(owasp_findings)

        statistics = self.get_statistics()
        security_summary = self.get_security_summary()

        return {
            "success": True,
            "name": self.collection_info.get("name", "Unknown"),
            "format": "postman",
            "collection_info": self.collection_info,
            "total_requests": len(self.requests),
            "requests": [r.to_dict() for r in self.requests],
            "statistics": statistics,
            "security_scan": security_summary,
        }

    def get_requests_by_method(self, method: str) -> List[PostmanRequest]:
        """Filter requests by HTTP method"""
        return [r for r in self.requests if r.method == method.upper()]
    
    def get_requests_by_url_pattern(self, pattern: str) -> List[PostmanRequest]:
        """Filter requests by URL pattern"""
        return [r for r in self.requests if pattern.lower() in r.url.lower()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get collection statistics"""
        methods: Dict[str, int] = {}
        for req in self.requests:
            methods[req.method] = methods.get(req.method, 0) + 1
        
        return {
            "total_requests": len(self.requests),
            "methods": methods,
            "requests_with_auth": sum(1 for r in self.requests if r.auth),
            "requests_with_body": sum(1 for r in self.requests if r.body),
            "requests_with_tests": sum(1 for r in self.requests if r.tests),
        }
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get aggregated security scan results"""
        cred_by_severity: Dict[str, int] = {}
        for f in self.credential_findings:
            cred_by_severity[f.severity] = cred_by_severity.get(f.severity, 0) + 1
        
        owasp_by_id: Dict[str, int] = {}
        owasp_by_severity: Dict[str, int] = {}
        for f in self.owasp_findings:
            owasp_by_id[f.owasp_id] = owasp_by_id.get(f.owasp_id, 0) + 1
            owasp_by_severity[f.severity] = owasp_by_severity.get(f.severity, 0) + 1
        
        return {
            "credentials_detected": len(self.credential_findings),
            "credentials_by_severity": cred_by_severity,
            "credential_details": [asdict(f) for f in self.credential_findings],
            "owasp_findings": len(self.owasp_findings),
            "owasp_by_category": owasp_by_id,
            "owasp_by_severity": owasp_by_severity,
            "owasp_details": [asdict(f) for f in self.owasp_findings],
            "risk_level": self._compute_scan_risk_level(),
        }
    
    def _compute_scan_risk_level(self) -> str:
        """Compute overall risk level from scan findings"""
        critical_count = sum(
            1 for f in self.credential_findings if f.severity == "CRITICAL"
        ) + sum(
            1 for f in self.owasp_findings if f.severity == "CRITICAL"
        )
        high_count = sum(
            1 for f in self.credential_findings if f.severity == "HIGH"
        ) + sum(
            1 for f in self.owasp_findings if f.severity == "HIGH"
        )
        
        if critical_count > 0:
            return "CRITICAL"
        if high_count > 0:
            return "HIGH"
        if self.credential_findings or self.owasp_findings:
            return "MEDIUM"
        return "LOW"


def parse_postman_collection(file_path: str) -> Dict[str, Any]:
    """
    Convenience function to parse Postman collection with security scanning.
    
    Usage:
        result = parse_postman_collection("collection.json")
        if result.get("success"):
            print(f"Parsed {result['total_requests']} requests")
            print(f"Credentials found: {result['security_scan']['credentials_detected']}")
            print(f"OWASP findings: {result['security_scan']['owasp_findings']}")
    """
    parser = PostmanParser()
    return parser.parse_collection(file_path)
