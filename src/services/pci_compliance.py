"""
DevPulse - PCI DSS v4.0.1 + GDPR Compliance Report Generator (Market-Ready)
Generates audit-ready compliance reports with proper OWASP→PCI DSS mapping,
GDPR compliance checks, and structured PDF-ready output.

Maps OWASP API Security Top 10 (2023) findings to:
  - PCI DSS v4.0.1 requirements
  - GDPR articles
Produces structured reports suitable for auditors and regulators.
"""

import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


# ── OWASP → PCI DSS v4.0.1 Mapping ──────────────────────────────────────
# Maps each OWASP API Security Top 10 category to the PCI DSS v4.0.1
# requirements it violates.

OWASP_TO_PCI: Dict[str, List[Dict[str, str]]] = {
    "API1:2023 Broken Object Level Authorization": [
        {"req": "7.2.1", "title": "Access Control System", "desc": "Restrict access based on need-to-know"},
        {"req": "7.2.2", "title": "Access Control Coverage", "desc": "Access control for all system components"},
    ],
    "API2:2023 Broken Authentication": [
        {"req": "8.3.1", "title": "Strong Authentication", "desc": "Unique authentication factors for users"},
        {"req": "8.3.6", "title": "Password Complexity", "desc": "Min 12 chars, or 8 with complexity"},
        {"req": "8.4.2", "title": "MFA for CDE Access", "desc": "MFA for all access to CDE"},
    ],
    "API3:2023 Broken Object Property Level Authorization": [
        {"req": "7.2.1", "title": "Access Control System", "desc": "Restrict access based on need-to-know"},
        {"req": "6.2.4", "title": "Secure Coding", "desc": "Prevent common software attacks"},
    ],
    "API4:2023 Unrestricted Resource Consumption": [
        {"req": "6.2.4", "title": "Secure Coding", "desc": "Prevent common software attacks"},
        {"req": "11.3.1", "title": "Vulnerability Scanning", "desc": "Internal vulnerability scans quarterly"},
    ],
    "API5:2023 Broken Function Level Authorization": [
        {"req": "7.2.1", "title": "Access Control System", "desc": "Restrict access based on need-to-know"},
        {"req": "7.2.5", "title": "Access Assignment", "desc": "Access assigned based on job classification"},
    ],
    "API6:2023 Unrestricted Access to Sensitive Business Flows": [
        {"req": "6.2.4", "title": "Secure Coding", "desc": "Prevent common software attacks"},
        {"req": "6.4.1", "title": "WAF / Attack Detection", "desc": "Web application firewall protection"},
    ],
    "API7:2023 Server Side Request Forgery": [
        {"req": "6.2.4", "title": "Secure Coding", "desc": "Prevent common software attacks"},
        {"req": "1.2.1", "title": "Network Security Controls", "desc": "Restrict inbound/outbound traffic"},
    ],
    "API8:2023 Security Misconfiguration": [
        {"req": "2.2.1", "title": "System Configuration", "desc": "Configuration standards for all components"},
        {"req": "6.3.1", "title": "Vulnerability Management", "desc": "Identify and manage security vulnerabilities"},
    ],
    "API9:2023 Improper Inventory Management": [
        {"req": "12.5.1", "title": "Asset Inventory", "desc": "Maintain inventory of system components"},
        {"req": "11.3.1", "title": "Vulnerability Scanning", "desc": "Internal vulnerability scans quarterly"},
    ],
    "API10:2023 Unsafe Consumption of APIs": [
        {"req": "6.2.4", "title": "Secure Coding", "desc": "Prevent common software attacks"},
        {"req": "12.8.1", "title": "Third-Party Management", "desc": "Maintain list of third-party service providers"},
    ],
}


# ── GDPR Article Mapping ─────────────────────────────────────────────────

GDPR_ARTICLES: List[Dict[str, Any]] = [
    {
        "article": "Art. 5(1)(f)",
        "title": "Integrity & Confidentiality",
        "description": "Personal data must be processed with appropriate security",
        "check_fn": "check_encryption_and_auth",
    },
    {
        "article": "Art. 25",
        "title": "Data Protection by Design",
        "description": "Implement appropriate technical and organisational measures",
        "check_fn": "check_data_protection_by_design",
    },
    {
        "article": "Art. 30",
        "title": "Records of Processing Activities",
        "description": "Maintain records of processing activities",
        "check_fn": "check_audit_logging",
    },
    {
        "article": "Art. 32",
        "title": "Security of Processing",
        "description": "Implement measures to ensure security appropriate to risk",
        "check_fn": "check_security_measures",
    },
    {
        "article": "Art. 33",
        "title": "Breach Notification",
        "description": "Notify supervisory authority within 72 hours of breach",
        "check_fn": "check_breach_notification",
    },
    {
        "article": "Art. 35",
        "title": "Data Protection Impact Assessment",
        "description": "Carry out DPIA for high-risk processing",
        "check_fn": "check_dpia",
    },
]


# ── PCI DSS v4.0.1 Full Requirements ────────────────────────────────────

PCI_DSS_V4_REQUIREMENTS: List[Dict[str, Any]] = [
    {"id": "1.2.1", "title": "Network Security Controls", "category": "Network Security", "severity": "CRITICAL",
     "description": "Restrict inbound and outbound traffic to that which is necessary"},
    {"id": "2.2.1", "title": "System Configuration Standards", "category": "Secure Configuration", "severity": "HIGH",
     "description": "Configuration standards developed for all system components"},
    {"id": "3.5.1", "title": "PAN Protection", "category": "Data Protection", "severity": "CRITICAL",
     "description": "PAN is secured wherever it is stored"},
    {"id": "4.2.1", "title": "Strong Cryptography", "category": "Encryption", "severity": "CRITICAL",
     "description": "Strong cryptography for transmission of PAN over open networks"},
    {"id": "6.2.4", "title": "Secure Software Development", "category": "Secure Development", "severity": "HIGH",
     "description": "Software engineering techniques prevent common attacks"},
    {"id": "6.3.1", "title": "Vulnerability Management", "category": "Vulnerability Management", "severity": "HIGH",
     "description": "Security vulnerabilities identified and managed"},
    {"id": "6.4.1", "title": "WAF Protection", "category": "Application Security", "severity": "HIGH",
     "description": "Public-facing web applications protected against attacks"},
    {"id": "7.2.1", "title": "Access Control System", "category": "Access Control", "severity": "HIGH",
     "description": "Access control system restricts access based on need-to-know"},
    {"id": "7.2.2", "title": "Access Control Coverage", "category": "Access Control", "severity": "HIGH",
     "description": "Access control system covers all system components"},
    {"id": "7.2.5", "title": "Access Assignment", "category": "Access Control", "severity": "MEDIUM",
     "description": "Access assigned based on job classification and function"},
    {"id": "8.3.1", "title": "Strong Authentication", "category": "Authentication", "severity": "HIGH",
     "description": "All user access uses unique authentication factors"},
    {"id": "8.3.6", "title": "Password Complexity", "category": "Authentication", "severity": "MEDIUM",
     "description": "Passwords meet minimum complexity requirements"},
    {"id": "8.4.2", "title": "MFA for CDE", "category": "Authentication", "severity": "CRITICAL",
     "description": "MFA implemented for all access into CDE"},
    {"id": "10.2.1", "title": "Audit Logging", "category": "Logging & Monitoring", "severity": "HIGH",
     "description": "Audit logs capture all access to system components"},
    {"id": "10.4.1", "title": "Log Review", "category": "Logging & Monitoring", "severity": "HIGH",
     "description": "Audit logs reviewed at least once daily"},
    {"id": "11.3.1", "title": "Vulnerability Scanning", "category": "Testing", "severity": "HIGH",
     "description": "Internal vulnerability scans performed at least quarterly"},
    {"id": "11.3.2", "title": "External Scanning", "category": "Testing", "severity": "HIGH",
     "description": "External vulnerability scans performed at least quarterly"},
    {"id": "12.5.1", "title": "Asset Inventory", "category": "Governance", "severity": "MEDIUM",
     "description": "Inventory of system components is maintained"},
    {"id": "12.8.1", "title": "Third-Party Management", "category": "Governance", "severity": "MEDIUM",
     "description": "List of third-party service providers is maintained"},
]


class PCIComplianceGenerator:
    """
    Market-ready PCI DSS v4.0.1 + GDPR compliance report generator.
    
    Takes OWASP findings from postman_parser / risk_score_engine and maps
    them to PCI DSS v4.0.1 requirements and GDPR articles. Produces
    structured reports ready for PDF export and auditor review.
    """
    
    def __init__(self):
        self.pci_requirements = PCI_DSS_V4_REQUIREMENTS
        self.gdpr_articles = GDPR_ARTICLES
        self.owasp_pci_map = OWASP_TO_PCI
    
    def generate_report(
        self,
        requests: Optional[List[Dict]] = None,
        owasp_findings: Optional[List[Dict]] = None,
        credential_findings: Optional[List[Dict]] = None,
        organization: str = "Unknown",
    ) -> Dict:
        """
        Generate a unified PCI DSS v4.0.1 + GDPR compliance report.
        
        Accepts OWASP findings (from postman_parser.scan_owasp) and
        credential findings (from postman_parser.detect_credentials).
        Falls back to request-based heuristic analysis if no findings provided.
        """
        requests = requests or []
        owasp_findings = owasp_findings or []
        credential_findings = credential_findings or []
        
        report_id = str(uuid.uuid4())[:8]
        
        # ── PCI DSS Assessment ───────────────────────────────────────────
        pci_results = self._assess_pci_requirements(
            requests, owasp_findings, credential_findings,
        )
        
        pci_compliant = sum(1 for r in pci_results if r["status"] == "COMPLIANT")
        pci_total = len(pci_results)
        pci_pct = round(pci_compliant / pci_total * 100, 1) if pci_total > 0 else 0
        
        # ── GDPR Assessment ──────────────────────────────────────────────
        gdpr_results = self._assess_gdpr(
            requests, owasp_findings, credential_findings,
        )
        
        gdpr_compliant = sum(1 for r in gdpr_results if r["status"] == "COMPLIANT")
        gdpr_total = len(gdpr_results)
        gdpr_pct = round(gdpr_compliant / gdpr_total * 100, 1) if gdpr_total > 0 else 0
        
        # ── OWASP → PCI Mapping ─────────────────────────────────────────
        owasp_pci_mappings = self._map_owasp_to_pci(owasp_findings)
        
        # ── Build Report ─────────────────────────────────────────────────
        overall_pct = round((pci_pct + gdpr_pct) / 2, 1)
        
        report = {
            "report_id": report_id,
            "organization": organization,
            "generated_at": datetime.utcnow().isoformat(),
            "framework_version": "PCI DSS v4.0.1 + GDPR",
            "pci_dss": {
                "version": "4.0.1",
                "requirements": pci_results,
                "compliant": pci_compliant,
                "non_compliant": pci_total - pci_compliant,
                "total": pci_total,
                "compliance_percentage": pci_pct,
                "status": "COMPLIANT" if pci_pct >= 80 else "NON_COMPLIANT",
            },
            "gdpr": {
                "articles": gdpr_results,
                "compliant": gdpr_compliant,
                "non_compliant": gdpr_total - gdpr_compliant,
                "total": gdpr_total,
                "compliance_percentage": gdpr_pct,
                "status": "COMPLIANT" if gdpr_pct >= 80 else "NON_COMPLIANT",
            },
            "owasp_pci_mappings": owasp_pci_mappings,
            "summary": {
                "overall_compliance_percentage": overall_pct,
                "overall_status": "COMPLIANT" if overall_pct >= 80 else "NON_COMPLIANT",
                "total_owasp_findings": len(owasp_findings),
                "total_credential_findings": len(credential_findings),
                "pci_compliance_percentage": pci_pct,
                "gdpr_compliance_percentage": gdpr_pct,
                "audit_trail": self._generate_audit_trail(),
            },
        }
        
        return report
    
    # ── PCI DSS v4.0.1 Assessment ────────────────────────────────────────
    
    def _assess_pci_requirements(
        self,
        requests: List[Dict],
        owasp_findings: List[Dict],
        credential_findings: List[Dict],
    ) -> List[Dict]:
        """Assess each PCI DSS v4.0.1 requirement against findings."""
        results = []
        
        # Build set of violated PCI requirements from OWASP findings
        violated_reqs: set = set()
        for finding in owasp_findings:
            owasp_id = finding.get("owasp_id", "")
            owasp_name = finding.get("owasp_category", "")
            # Match against our mapping
            for key, pci_reqs in self.owasp_pci_map.items():
                if owasp_id in key or owasp_name in key:
                    for pci_req in pci_reqs:
                        violated_reqs.add(pci_req["req"])
        
        # Credential findings always violate auth & encryption requirements
        if credential_findings:
            violated_reqs.update(["3.5.1", "4.2.1", "8.3.1"])
        
        # Check request-level indicators
        has_auth = any(
            req.get("auth_type") or "Authorization" in req.get("headers", {})
            for req in requests
        ) if requests else True
        has_https = any(
            req.get("url", "").startswith("https://")
            for req in requests
        ) if requests else True
        
        if not has_auth:
            violated_reqs.update(["7.2.1", "8.3.1", "8.4.2"])
        if not has_https:
            violated_reqs.update(["4.2.1"])
        
        for req_def in self.pci_requirements:
            is_violated = req_def["id"] in violated_reqs
            status = "NON_COMPLIANT" if is_violated else "COMPLIANT"
            
            # Find which OWASP findings mapped to this requirement
            mapped_owasp = []
            for key, pci_reqs in self.owasp_pci_map.items():
                for pci_req in pci_reqs:
                    if pci_req["req"] == req_def["id"]:
                        mapped_owasp.append(key)
            
            results.append({
                "id": req_def["id"],
                "title": req_def["title"],
                "category": req_def["category"],
                "severity": req_def["severity"],
                "description": req_def["description"],
                "status": status,
                "mapped_owasp_categories": mapped_owasp,
                "remediation": self._get_pci_remediation(req_def["id"], status),
            })
        
        return results
    
    # ── GDPR Assessment ──────────────────────────────────────────────────
    
    def _assess_gdpr(
        self,
        requests: List[Dict],
        owasp_findings: List[Dict],
        credential_findings: List[Dict],
    ) -> List[Dict]:
        """Assess GDPR article compliance."""
        results = []
        
        has_auth = any(
            req.get("auth_type") or "Authorization" in req.get("headers", {})
            for req in requests
        ) if requests else True
        has_https = any(
            req.get("url", "").startswith("https://")
            for req in requests
        ) if requests else True
        has_logging = any(
            "log" in req.get("name", "").lower()
            for req in requests
        ) if requests else True
        
        has_security_issues = len(owasp_findings) > 0 or len(credential_findings) > 0
        
        for article in self.gdpr_articles:
            check_fn = article["check_fn"]
            
            if check_fn == "check_encryption_and_auth":
                status = "NON_COMPLIANT" if (not has_auth or not has_https or credential_findings) else "COMPLIANT"
                finding = "Exposed credentials or missing encryption detected" if status == "NON_COMPLIANT" else "Encryption and authentication properly configured"
            elif check_fn == "check_data_protection_by_design":
                status = "NON_COMPLIANT" if has_security_issues else "COMPLIANT"
                finding = f"{len(owasp_findings)} OWASP findings indicate design weaknesses" if status == "NON_COMPLIANT" else "No design-level security issues detected"
            elif check_fn == "check_audit_logging":
                status = "COMPLIANT" if has_logging else "NON_COMPLIANT"
                finding = "Audit logging detected" if status == "COMPLIANT" else "No audit logging endpoints found"
            elif check_fn == "check_security_measures":
                status = "NON_COMPLIANT" if has_security_issues else "COMPLIANT"
                finding = "Security vulnerabilities found in API configuration" if status == "NON_COMPLIANT" else "Security measures are adequate"
            elif check_fn == "check_breach_notification":
                # Always recommend breach notification procedure
                status = "REVIEW_REQUIRED"
                finding = "Verify breach notification procedures are in place (72-hour SLA)"
            elif check_fn == "check_dpia":
                status = "REVIEW_REQUIRED"
                finding = "Data Protection Impact Assessment recommended for AI/LLM processing"
            else:
                status = "REVIEW_REQUIRED"
                finding = "Manual review required"
            
            results.append({
                "article": article["article"],
                "title": article["title"],
                "description": article["description"],
                "status": status,
                "finding": finding,
            })
        
        return results
    
    # ── OWASP → PCI Mapping ──────────────────────────────────────────────
    
    def _map_owasp_to_pci(self, owasp_findings: List[Dict]) -> List[Dict]:
        """Map specific OWASP findings to PCI DSS requirements."""
        mappings = []
        
        for finding in owasp_findings:
            owasp_cat = finding.get("owasp_category", "")
            matched_pci = []
            for key, pci_reqs in self.owasp_pci_map.items():
                if owasp_cat in key or finding.get("owasp_id", "") in key:
                    matched_pci = pci_reqs
                    break
            
            if matched_pci:
                mappings.append({
                    "owasp_finding": finding.get("title", owasp_cat),
                    "owasp_category": owasp_cat,
                    "severity": finding.get("severity", "MEDIUM"),
                    "pci_requirements_violated": [
                        {"req": p["req"], "title": p["title"]}
                        for p in matched_pci
                    ],
                })
        
        return mappings
    
    # ── Helpers ──────────────────────────────────────────────────────────
    
    def _get_pci_remediation(self, req_id: str, status: str) -> str:
        """Get remediation guidance for a PCI DSS requirement."""
        if status == "COMPLIANT":
            return "No action required"
        
        remediation_map = {
            "1.2.1": "Review and restrict inbound/outbound traffic rules. Document all allowed traffic flows.",
            "2.2.1": "Develop and apply configuration standards for all system components. Remove unnecessary services.",
            "3.5.1": "Encrypt stored PAN using strong cryptography. Implement key management procedures.",
            "4.2.1": "Enable TLS 1.2+ for all PAN transmissions. Disable weak cipher suites.",
            "6.2.4": "Implement secure coding practices. Train developers on OWASP Top 10.",
            "6.3.1": "Establish vulnerability management process. Prioritize by risk.",
            "6.4.1": "Deploy WAF in front of public-facing applications. Configure with OWASP rules.",
            "7.2.1": "Implement role-based access control. Restrict access to need-to-know basis.",
            "7.2.2": "Ensure access controls cover all system components. Review quarterly.",
            "7.2.5": "Assign access based on job classification. Review when roles change.",
            "8.3.1": "Implement unique authentication for all users. Enforce strong password policy.",
            "8.3.6": "Enforce minimum 12-character passwords or 8 with complexity. Implement lockout.",
            "8.4.2": "Implement MFA for all access to cardholder data environment.",
            "10.2.1": "Enable audit logging on all system components. Capture all access attempts.",
            "10.4.1": "Implement daily log review process. Use automated alerting for anomalies.",
            "11.3.1": "Schedule quarterly internal vulnerability scans. Remediate high/critical findings.",
            "11.3.2": "Engage ASV for quarterly external scans. Remediate findings before next scan.",
            "12.5.1": "Maintain complete hardware/software inventory. Update when changes occur.",
            "12.8.1": "Maintain list of all TPSPs. Include description of services provided.",
        }
        return remediation_map.get(req_id, "Review requirement and implement appropriate controls.")
    
    def _generate_audit_trail(self) -> List[Dict]:
        """Generate audit trail entry."""
        return [{
            "timestamp": datetime.utcnow().isoformat(),
            "action": "Compliance Report Generated",
            "user": "DevPulse Automated Scanner",
            "frameworks": ["PCI DSS v4.0.1", "GDPR"],
            "status": "Success",
        }]
    
    def export_to_pdf(self, report: Dict) -> bytes:
        """
        Export report to structured PDF-ready format.
        Produces well-formatted text that can be converted to PDF
        by any rendering library (reportlab, weasyprint, etc.).
        """
        lines = []
        lines.append("=" * 72)
        lines.append("DEVPULSE COMPLIANCE REPORT")
        lines.append(f"PCI DSS v4.0.1 + GDPR Assessment")
        lines.append("=" * 72)
        lines.append("")
        lines.append(f"Organization:  {report['organization']}")
        lines.append(f"Report ID:     {report['report_id']}")
        lines.append(f"Generated:     {report['generated_at']}")
        lines.append("")
        
        # Summary
        summary = report.get("summary", {})
        lines.append("-" * 72)
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 72)
        lines.append(f"Overall Compliance:  {summary.get('overall_compliance_percentage', 0)}%")
        lines.append(f"Overall Status:      {summary.get('overall_status', 'UNKNOWN')}")
        lines.append(f"PCI DSS Score:       {summary.get('pci_compliance_percentage', 0)}%")
        lines.append(f"GDPR Score:          {summary.get('gdpr_compliance_percentage', 0)}%")
        lines.append(f"OWASP Findings:      {summary.get('total_owasp_findings', 0)}")
        lines.append(f"Credential Issues:   {summary.get('total_credential_findings', 0)}")
        lines.append("")
        
        # PCI DSS Details
        pci = report.get("pci_dss", {})
        lines.append("-" * 72)
        lines.append(f"PCI DSS v4.0.1 ASSESSMENT  ({pci.get('compliance_percentage', 0)}%)")
        lines.append("-" * 72)
        for req in pci.get("requirements", []):
            status_marker = "PASS" if req["status"] == "COMPLIANT" else "FAIL"
            lines.append(f"  [{status_marker}] {req['id']} - {req['title']}")
            if req["status"] != "COMPLIANT":
                lines.append(f"         Remediation: {req.get('remediation', 'N/A')}")
        lines.append("")
        
        # GDPR Details
        gdpr = report.get("gdpr", {})
        lines.append("-" * 72)
        lines.append(f"GDPR ASSESSMENT  ({gdpr.get('compliance_percentage', 0)}%)")
        lines.append("-" * 72)
        for art in gdpr.get("articles", []):
            status_marker = "PASS" if art["status"] == "COMPLIANT" else "REVIEW" if art["status"] == "REVIEW_REQUIRED" else "FAIL"
            lines.append(f"  [{status_marker}] {art['article']} - {art['title']}")
            lines.append(f"         {art.get('finding', '')}")
        lines.append("")
        
        # OWASP → PCI Mappings
        mappings = report.get("owasp_pci_mappings", [])
        if mappings:
            lines.append("-" * 72)
            lines.append("OWASP → PCI DSS REQUIREMENT MAPPINGS")
            lines.append("-" * 72)
            for m in mappings:
                lines.append(f"  [{m['severity']}] {m['owasp_finding']}")
                for pci_req in m.get("pci_requirements_violated", []):
                    lines.append(f"       → PCI DSS {pci_req['req']}: {pci_req['title']}")
            lines.append("")
        
        lines.append("=" * 72)
        lines.append("END OF REPORT")
        lines.append("=" * 72)
        
        return "\n".join(lines).encode("utf-8")
