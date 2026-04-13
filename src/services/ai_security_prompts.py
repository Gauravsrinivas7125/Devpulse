"""
DevPulse AI Security Prompts Service
Inspired by system-prompts-and-models-of-ai-tools repo patterns.
Structured vulnerability analysis prompts for AI-assisted scanning,
OWASP Top 10 patterns, and remediation templates.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class VulnerabilityPattern:
    id: str
    name: str
    category: str
    owasp_id: Optional[str]
    description: str
    detection_patterns: List[str]
    severity: str
    remediation: str
    references: List[str]


# OWASP API Security Top 10 (2023) patterns
OWASP_API_TOP_10: List[VulnerabilityPattern] = [
    VulnerabilityPattern(
        id="API1",
        name="Broken Object Level Authorization",
        category="Authorization",
        owasp_id="API1:2023",
        description="APIs expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues.",
        detection_patterns=[
            r"/api/\w+/\{?\w*[iI][dD]\}?",
            r"user_id|userId|account_id|accountId",
            r"GET\s+/api/\w+/\d+",
        ],
        severity="CRITICAL",
        remediation="Implement object-level authorization checks. Validate that the logged-in user has permission to access the requested object. Use random, unpredictable IDs (UUIDs).",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
    ),
    VulnerabilityPattern(
        id="API2",
        name="Broken Authentication",
        category="Authentication",
        owasp_id="API2:2023",
        description="Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.",
        detection_patterns=[
            r"password|token|secret|key|credential",
            r"Authorization:\s*Bearer",
            r"api[_-]?key",
            r"no.*auth|unauthenticated",
        ],
        severity="CRITICAL",
        remediation="Use standard authentication protocols (OAuth 2.0, OpenID Connect). Implement rate limiting on auth endpoints. Use strong password policies and MFA.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
    ),
    VulnerabilityPattern(
        id="API3",
        name="Broken Object Property Level Authorization",
        category="Authorization",
        owasp_id="API3:2023",
        description="APIs expose endpoints allowing users to read/update object properties they should not have access to.",
        detection_patterns=[
            r"PUT|PATCH",
            r"role|admin|permission|privilege",
            r"mass.?assign",
        ],
        severity="HIGH",
        remediation="Validate that the user has permission to access specific object properties. Use allowlists for writable properties. Never rely on client-side filtering.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
    ),
    VulnerabilityPattern(
        id="API4",
        name="Unrestricted Resource Consumption",
        category="Rate Limiting",
        owasp_id="API4:2023",
        description="APIs do not restrict the size or number of resources that can be requested, leading to DoS and cost inflation.",
        detection_patterns=[
            r"limit|offset|page|size|count",
            r"batch|bulk|upload",
            r"no.*rate.*limit|unlimited",
        ],
        severity="HIGH",
        remediation="Implement rate limiting, pagination, and request size limits. Set timeouts. Limit resource consumption per user/IP.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
    ),
    VulnerabilityPattern(
        id="API5",
        name="Broken Function Level Authorization",
        category="Authorization",
        owasp_id="API5:2023",
        description="Complex access control policies with different hierarchies, groups, and roles create gaps in authorization enforcement.",
        detection_patterns=[
            r"/admin|/internal|/debug|/management",
            r"role.*=.*admin",
            r"DELETE|PUT.*/(users|config|settings)",
        ],
        severity="CRITICAL",
        remediation="Implement consistent authorization checks. Default to deny. Ensure admin functions have proper role validation.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
    ),
    VulnerabilityPattern(
        id="API6",
        name="Unrestricted Access to Sensitive Business Flows",
        category="Business Logic",
        owasp_id="API6:2023",
        description="APIs expose business flows without compensating controls to detect and prevent automated abuse.",
        detection_patterns=[
            r"purchase|payment|transfer|checkout",
            r"register|signup|create.*account",
            r"vote|comment|review|rating",
        ],
        severity="MEDIUM",
        remediation="Identify business flows at risk of abuse. Implement anti-automation measures (CAPTCHA, rate limiting, bot detection).",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"],
    ),
    VulnerabilityPattern(
        id="API7",
        name="Server Side Request Forgery",
        category="Injection",
        owasp_id="API7:2023",
        description="APIs fetch remote resources without validating the user-supplied URI, enabling SSRF.",
        detection_patterns=[
            r"url|uri|link|redirect|callback",
            r"fetch|request|proxy|forward",
            r"webhook|hook|notify",
        ],
        severity="HIGH",
        remediation="Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains. Disable redirects. Use network-level controls.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"],
    ),
    VulnerabilityPattern(
        id="API8",
        name="Security Misconfiguration",
        category="Configuration",
        owasp_id="API8:2023",
        description="APIs and supporting systems contain misconfigurations creating security weaknesses.",
        detection_patterns=[
            r"cors|allow-origin|access-control",
            r"debug|verbose|stack.?trace",
            r"http://|TLS.*1\.[01]|SSL",
            r"default.*password|admin.*admin",
        ],
        severity="HIGH",
        remediation="Harden configurations. Disable debug mode. Use HTTPS. Configure CORS properly. Remove default credentials. Follow security hardening guides.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
    ),
    VulnerabilityPattern(
        id="API9",
        name="Improper Inventory Management",
        category="Inventory",
        owasp_id="API9:2023",
        description="APIs expose more endpoints than intended, often with outdated or unpatched versions running alongside production.",
        detection_patterns=[
            r"/v1/|/v2/|/beta/|/staging/|/test/",
            r"/old/|/legacy/|/deprecated/",
            r"swagger|openapi|api-docs",
        ],
        severity="MEDIUM",
        remediation="Maintain an up-to-date API inventory. Retire old versions. Use API gateways. Monitor for shadow APIs.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
    ),
    VulnerabilityPattern(
        id="API10",
        name="Unsafe Consumption of APIs",
        category="Integration",
        owasp_id="API10:2023",
        description="Developers trust data from third-party APIs without proper validation, creating indirect attack vectors.",
        detection_patterns=[
            r"third.?party|external|partner",
            r"import|ingest|consume|integrate",
            r"trust|whitelist|allowlist",
        ],
        severity="MEDIUM",
        remediation="Validate all data from third-party APIs. Do not trust external data implicitly. Implement timeouts and circuit breakers.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"],
    ),
]


# Scan analysis prompt templates (inspired by AI system prompt patterns)
SCAN_ANALYSIS_PROMPTS = {
    "vulnerability_summary": """Analyze the following API security scan results and provide a structured summary:

## Scan Results
{scan_results}

## Required Output Format
1. **Executive Summary**: 2-3 sentence overview of the security posture
2. **Critical Findings**: List critical/high severity issues with remediation priority
3. **Risk Assessment**: Overall risk score justification
4. **Recommended Actions**: Prioritized list of remediation steps
5. **Compliance Impact**: How findings affect PCI DSS / SOC 2 compliance
""",

    "remediation_plan": """Based on the following security findings, generate a detailed remediation plan:

## Findings
{findings}

## Required Output
For each finding:
- **Priority**: P0 (immediate), P1 (24h), P2 (1 week), P3 (1 month)
- **Effort**: Low / Medium / High
- **Steps**: Concrete remediation steps
- **Verification**: How to verify the fix
- **Code Example**: If applicable, show the fix
""",

    "trend_analysis": """Analyze the security trend data and identify patterns:

## Historical Data
{trend_data}

## Required Analysis
1. **Trend Direction**: Improving, Stable, or Degrading
2. **Key Changes**: What changed between scan periods
3. **Predictions**: Expected risk trajectory if current trend continues
4. **Recommendations**: Actions to improve the trend
""",
}


class AISecurityAnalyzer:
    """
    AI-powered security analysis with structured prompts
    for vulnerability assessment and remediation planning.
    """

    def __init__(self) -> None:
        self._patterns = {p.id: p for p in OWASP_API_TOP_10}

    def analyze_endpoint(self, method: str, path: str, headers: Dict = None, body: str = None) -> List[Dict]:
        """Analyze a single API endpoint against OWASP patterns."""
        import re

        findings = []
        check_text = f"{method} {path} {str(headers or '')} {body or ''}"

        for pattern in OWASP_API_TOP_10:
            for regex in pattern.detection_patterns:
                if re.search(regex, check_text, re.IGNORECASE):
                    findings.append({
                        "pattern_id": pattern.id,
                        "name": pattern.name,
                        "category": pattern.category,
                        "owasp_id": pattern.owasp_id,
                        "severity": pattern.severity,
                        "description": pattern.description,
                        "remediation": pattern.remediation,
                        "matched_pattern": regex,
                        "references": pattern.references,
                    })
                    break  # One match per pattern is enough

        return findings

    def analyze_collection(self, requests: List[Dict]) -> Dict:
        """Analyze an entire API collection against OWASP patterns."""
        all_findings = []
        endpoint_risks: Dict[str, List] = {}

        for req in requests:
            method = req.get("method", "GET")
            url = req.get("url", "")
            if isinstance(url, dict):
                url = url.get("raw", "")

            findings = self.analyze_endpoint(
                method=method,
                path=url,
                headers=req.get("headers"),
                body=req.get("body"),
            )

            if findings:
                all_findings.extend(findings)
                endpoint_risks[f"{method} {url}"] = findings

        # Deduplicate by pattern_id
        seen = set()
        unique_findings = []
        for f in all_findings:
            if f["pattern_id"] not in seen:
                seen.add(f["pattern_id"])
                unique_findings.append(f)

        # Calculate OWASP coverage
        detected_ids = {f["pattern_id"] for f in unique_findings}
        coverage = {
            p.id: {
                "name": p.name,
                "detected": p.id in detected_ids,
                "severity": p.severity,
            }
            for p in OWASP_API_TOP_10
        }

        return {
            "total_findings": len(unique_findings),
            "findings": unique_findings,
            "owasp_coverage": coverage,
            "endpoints_at_risk": len(endpoint_risks),
            "total_endpoints_scanned": len(requests),
            "risk_score": self._calculate_risk_score(unique_findings),
        }

    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        """Calculate risk score based on findings."""
        score = 0
        for f in findings:
            sev = f.get("severity", "").upper()
            if sev == "CRITICAL":
                score += 25
            elif sev == "HIGH":
                score += 15
            elif sev == "MEDIUM":
                score += 8
            elif sev == "LOW":
                score += 3
        return min(100, score)

    def get_remediation_plan(self, findings: List[Dict]) -> List[Dict]:
        """Generate a prioritized remediation plan."""
        priority_map = {"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3", "INFO": "P3"}
        effort_map = {"CRITICAL": "High", "HIGH": "Medium", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Low"}

        plan = []
        for f in sorted(findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.get("severity", "INFO"))):
            sev = f.get("severity", "INFO")
            plan.append({
                "finding": f["name"],
                "owasp_id": f.get("owasp_id"),
                "priority": priority_map.get(sev, "P3"),
                "effort": effort_map.get(sev, "Low"),
                "remediation": f["remediation"],
                "references": f.get("references", []),
            })

        return plan

    def get_prompt_for_analysis(self, prompt_type: str, context: Dict) -> Optional[str]:
        """Get a formatted AI analysis prompt."""
        template = SCAN_ANALYSIS_PROMPTS.get(prompt_type)
        if not template:
            return None
        try:
            return template.format(**context)
        except KeyError:
            return template

    def get_owasp_coverage_report(self) -> List[Dict]:
        """Get the full OWASP API Top 10 reference."""
        return [
            {
                "id": p.id,
                "name": p.name,
                "category": p.category,
                "owasp_id": p.owasp_id,
                "severity": p.severity,
                "description": p.description,
                "remediation": p.remediation,
                "references": p.references,
            }
            for p in OWASP_API_TOP_10
        ]


# Global instance
ai_security_analyzer = AISecurityAnalyzer()
