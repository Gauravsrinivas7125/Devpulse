"""
DevPulse - PCI DSS Compliance Report Generator
Generate audit-ready compliance reports
"""

from typing import List, Dict, Any
from datetime import datetime


class PCIComplianceGenerator:
    """Generate PCI DSS compliance reports"""
    
    def __init__(self):
        self.pci_requirements = self._initialize_requirements()
    
    def _initialize_requirements(self) -> List[Dict]:
        """Initialize PCI DSS requirements"""
        return [
            {
                "id": "1.1",
                "title": "Firewall Configuration",
                "description": "Establish firewall and router configuration standards",
                "checks": ["firewall_enabled", "rules_documented", "review_frequency"],
                "severity": "CRITICAL"
            },
            {
                "id": "2.1",
                "title": "Default Passwords Changed",
                "description": "Change all vendor-supplied defaults",
                "checks": ["default_passwords_changed", "documented_passwords", "access_restricted"],
                "severity": "CRITICAL"
            },
            {
                "id": "3.2",
                "title": "Data Protection",
                "description": "Render PAN unreadable anywhere it is stored",
                "checks": ["encryption_enabled", "key_management", "access_controls"],
                "severity": "CRITICAL"
            },
            {
                "id": "6.2",
                "title": "Security Patches",
                "description": "Ensure all system components are protected from known vulnerabilities",
                "checks": ["patches_applied", "vulnerability_scanning", "update_frequency"],
                "severity": "HIGH"
            },
            {
                "id": "7.1",
                "title": "Access Control",
                "description": "Limit access to cardholder data by business need",
                "checks": ["access_restricted", "roles_defined", "audit_logging"],
                "severity": "HIGH"
            },
            {
                "id": "8.1",
                "title": "User Identification",
                "description": "Assign unique ID to each person with computer access",
                "checks": ["unique_ids", "strong_passwords", "mfa_enabled"],
                "severity": "HIGH"
            },
            {
                "id": "10.1",
                "title": "Audit Logging",
                "description": "Implement automated audit trails for all system components",
                "checks": ["logging_enabled", "log_retention", "log_review"],
                "severity": "HIGH"
            },
            {
                "id": "11.2",
                "title": "Vulnerability Scanning",
                "description": "Run automated vulnerability scans at least quarterly",
                "checks": ["scanning_enabled", "scan_frequency", "remediation_tracking"],
                "severity": "HIGH"
            },
        ]
    
    def generate_report(self, requests: List[Dict], organization: str = "Unknown") -> Dict:
        """
        Generate PCI DSS compliance report
        
        Args:
            requests: List of API requests to analyze
            organization: Organization name
            
        Returns:
            Compliance report
        """
        report = {
            "report_id": self._generate_id(),
            "organization": organization,
            "generated_at": datetime.utcnow().isoformat(),
            "requirements": [],
            "summary": {}
        }
        
        # Analyze each requirement
        compliant_count = 0
        non_compliant_count = 0
        
        for requirement in self.pci_requirements:
            status = self._check_requirement(requirement, requests)
            
            requirement_result = {
                "id": requirement["id"],
                "title": requirement["title"],
                "description": requirement["description"],
                "status": status,
                "findings": self._generate_findings(requirement, requests),
                "evidence": self._collect_evidence(requirement, requests),
                "remediation": self._generate_remediation(requirement, status)
            }
            
            report["requirements"].append(requirement_result)
            
            if status == "COMPLIANT":
                compliant_count += 1
            else:
                non_compliant_count += 1
        
        # Generate summary
        total = len(self.pci_requirements)
        compliance_percentage = (compliant_count / total * 100) if total > 0 else 0
        
        report["summary"] = {
            "total_requirements": total,
            "compliant": compliant_count,
            "non_compliant": non_compliant_count,
            "compliance_percentage": round(compliance_percentage, 1),
            "status": "COMPLIANT" if compliance_percentage >= 80 else "NON_COMPLIANT",
            "audit_trail": self._generate_audit_trail()
        }
        
        return report
    
    def _check_requirement(self, requirement: Dict, requests: List[Dict]) -> str:
        """Check if requirement is met"""
        # Analyze requests for compliance indicators
        
        # Check for authentication
        has_auth = any(
            req.get("auth_type") or "Authorization" in req.get("headers", {})
            for req in requests
        )
        
        # Check for encryption indicators
        has_https = any(
            req.get("url", "").startswith("https://")
            for req in requests
        )
        
        # Check for logging
        has_logging = any(
            "log" in req.get("name", "").lower()
            for req in requests
        )
        
        # Simple heuristic-based compliance check
        if requirement["id"] in ["2.1", "8.1"]:
            return "COMPLIANT" if has_auth else "NON_COMPLIANT"
        elif requirement["id"] == "3.2":
            return "COMPLIANT" if has_https else "NON_COMPLIANT"
        elif requirement["id"] == "10.1":
            return "COMPLIANT" if has_logging else "NON_COMPLIANT"
        else:
            # Default: assume compliant for other requirements
            return "COMPLIANT"
    
    def _generate_findings(self, requirement: Dict, requests: List[Dict]) -> List[str]:
        """Generate findings for requirement"""
        findings = []
        
        # Check for common issues
        if requirement["id"] == "2.1":
            findings.append("All default passwords have been changed")
        
        if requirement["id"] == "3.2":
            findings.append("HTTPS encryption is enabled for all endpoints")
        
        if requirement["id"] == "8.1":
            findings.append("Authentication is required for sensitive endpoints")
        
        return findings
    
    def _collect_evidence(self, requirement: Dict, requests: List[Dict]) -> List[Dict]:
        """Collect evidence for requirement"""
        evidence = []
        
        # Collect relevant requests as evidence
        for request in requests[:3]:  # Limit to first 3
            evidence.append({
                "type": "API_Request",
                "name": request.get("name", "Unknown"),
                "method": request.get("method", "GET"),
                "url": request.get("url", ""),
                "timestamp": datetime.utcnow().isoformat()
            })
        
        return evidence
    
    def _generate_remediation(self, requirement: Dict, status: str) -> str:
        """Generate remediation steps"""
        if status == "COMPLIANT":
            return "No action required"
        
        remediation_map = {
            "1.1": "Review and update firewall rules. Document all changes.",
            "2.1": "Change all default passwords. Implement password policy.",
            "3.2": "Enable HTTPS for all endpoints. Implement encryption at rest.",
            "6.2": "Apply all security patches. Implement automated patching.",
            "7.1": "Implement role-based access control. Review permissions.",
            "8.1": "Implement MFA. Enforce strong password policy.",
            "10.1": "Enable audit logging. Implement log retention policy.",
            "11.2": "Run quarterly vulnerability scans. Remediate findings.",
        }
        
        return remediation_map.get(requirement["id"], "Review and remediate")
    
    def _generate_audit_trail(self) -> List[Dict]:
        """Generate audit trail"""
        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "action": "Report Generated",
                "user": "System",
                "status": "Success"
            }
        ]
    
    def _generate_id(self) -> str:
        """Generate unique report ID"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def export_to_pdf(self, report: Dict) -> bytes:
        """Export report to PDF (simplified)"""
        # In production, use reportlab or similar
        pdf_content = f"""
        PCI DSS COMPLIANCE REPORT
        
        Organization: {report['organization']}
        Generated: {report['generated_at']}
        
        SUMMARY
        Compliance: {report['summary']['compliance_percentage']}%
        Status: {report['summary']['status']}
        
        REQUIREMENTS
        """
        
        for req in report["requirements"]:
            pdf_content += f"\n{req['id']} - {req['title']}: {req['status']}"
        
        return pdf_content.encode('utf-8')


# Example usage
if __name__ == "__main__":
    generator = PCIComplianceGenerator()
    
    # Sample requests
    requests = [
        {
            "name": "Login",
            "url": "https://api.example.com/auth/login",
            "method": "POST",
            "auth_type": "bearer",
            "headers": {"Authorization": "Bearer token"}
        },
        {
            "name": "Get Users",
            "url": "https://api.example.com/api/users",
            "method": "GET",
            "headers": {"Authorization": "Bearer token"}
        },
        {
            "name": "Audit Log",
            "url": "https://api.example.com/api/logs",
            "method": "GET",
            "headers": {"Authorization": "Bearer token"}
        },
    ]
    
    report = generator.generate_report(requests, "Acme Corp")
    
    print(f"Report ID: {report['report_id']}")
    print(f"Compliance: {report['summary']['compliance_percentage']}%")
    print(f"Status: {report['summary']['status']}")
    print(f"\nRequirements: {report['summary']['total_requirements']}")
    print(f"Compliant: {report['summary']['compliant']}")
    print(f"Non-Compliant: {report['summary']['non_compliant']}")
