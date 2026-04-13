"""
DevPulse - Unified Risk Score Engine
Aggregates security findings into a single 0-100 risk score
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = 4  # Weight 4x
    HIGH = 3      # Weight 3x
    MEDIUM = 2    # Weight 2x
    LOW = 1       # Weight 1x
    INFO = 0      # Weight 0x


@dataclass
class SecurityFinding:
    """Represents a security finding/vulnerability"""
    id: str
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str  # "OWASP", "Auth", "Encryption", etc.
    description: str
    remediation: str
    affected_endpoints: List[str]
    cve_id: Optional[str] = None
    
    def get_severity_weight(self) -> int:
        """Get numeric weight for severity"""
        severity_map = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0
        }
        return severity_map.get(self.severity.upper(), 0)


@dataclass
class RiskMetrics:
    """Risk assessment metrics"""
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float  # 0-100
    risk_level: str    # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    trends: Dict[str, Any]  # Historical trends


class RiskScoreEngine:
    """Calculate unified risk score from security findings"""
    
    # Scoring constants
    CRITICAL_WEIGHT = 25
    HIGH_WEIGHT = 10
    MEDIUM_WEIGHT = 3
    LOW_WEIGHT = 1
    INFO_WEIGHT = 0
    
    # Risk level thresholds
    CRITICAL_THRESHOLD = 80
    HIGH_THRESHOLD = 60
    MEDIUM_THRESHOLD = 40
    LOW_THRESHOLD = 20
    
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.historical_scores: List[float] = []
    
    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a security finding"""
        self.findings.append(finding)
    
    def add_findings(self, findings: List[SecurityFinding]) -> None:
        """Add multiple security findings"""
        self.findings.extend(findings)
    
    def calculate_score(self) -> float:
        """
        Calculate unified risk score (0-100)
        
        Algorithm:
        1. Count findings by severity
        2. Apply weights to each severity level
        3. Normalize to 0-100 scale
        4. Apply diminishing returns (logarithmic scaling)
        
        Returns:
            Risk score from 0-100
        """
        if not self.findings:
            return 0.0
        
        # Count findings by severity
        severity_counts = self._count_by_severity()
        
        # Calculate weighted score
        weighted_score = (
            severity_counts["CRITICAL"] * self.CRITICAL_WEIGHT +
            severity_counts["HIGH"] * self.HIGH_WEIGHT +
            severity_counts["MEDIUM"] * self.MEDIUM_WEIGHT +
            severity_counts["LOW"] * self.LOW_WEIGHT +
            severity_counts["INFO"] * self.INFO_WEIGHT
        )
        
        # Normalize to 0-100 scale with diminishing returns
        # Using logarithmic scaling to prevent score inflation
        max_possible_score = len(self.findings) * self.CRITICAL_WEIGHT
        normalized_score = (weighted_score / max_possible_score) * 100
        
        # Apply diminishing returns (logarithmic scaling)
        # This prevents a single critical issue from maxing out the score
        risk_score = min(100, normalized_score * (1 + 0.1 * len(self.findings) ** 0.5))
        
        # Store historical score
        self.historical_scores.append(risk_score)
        
        return round(risk_score, 1)
    
    def get_risk_level(self, score: float) -> str:
        """Convert numeric score to risk level"""
        if score >= self.CRITICAL_THRESHOLD:
            return "CRITICAL"
        elif score >= self.HIGH_THRESHOLD:
            return "HIGH"
        elif score >= self.MEDIUM_THRESHOLD:
            return "MEDIUM"
        elif score >= self.LOW_THRESHOLD:
            return "LOW"
        else:
            return "INFO"
    
    def get_metrics(self) -> RiskMetrics:
        """Get comprehensive risk metrics"""
        severity_counts = self._count_by_severity()
        risk_score = self.calculate_score()
        risk_level = self.get_risk_level(risk_score)
        
        trends = self._calculate_trends()
        
        return RiskMetrics(
            total_findings=len(self.findings),
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            low_count=severity_counts["LOW"],
            info_count=severity_counts["INFO"],
            risk_score=risk_score,
            risk_level=risk_level,
            trends=trends
        )
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity level"""
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for finding in self.findings:
            severity = finding.severity.upper()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _calculate_trends(self) -> Dict[str, Any]:
        """Calculate risk score trends"""
        if len(self.historical_scores) < 2:
            return {
                "trend": "stable",
                "change": 0,
                "direction": "none"
            }
        
        current_score = self.historical_scores[-1]
        previous_score = self.historical_scores[-2]
        change = current_score - previous_score
        
        if change > 5:
            trend = "increasing"
            direction = "up"
        elif change < -5:
            trend = "decreasing"
            direction = "down"
        else:
            trend = "stable"
            direction = "none"
        
        return {
            "trend": trend,
            "change": round(change, 1),
            "direction": direction,
            "historical_scores": self.historical_scores[-10:]  # Last 10 scores
        }
    
    def get_top_findings(self, limit: int = 5) -> List[SecurityFinding]:
        """Get top findings by severity"""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.get(f.severity.upper(), 5)
        )
        return sorted_findings[:limit]
    
    def get_findings_by_category(self) -> Dict[str, List[SecurityFinding]]:
        """Group findings by category"""
        categories = {}
        for finding in self.findings:
            if finding.category not in categories:
                categories[finding.category] = []
            categories[finding.category].append(finding)
        return categories
    
    def get_affected_endpoints(self) -> Dict[str, int]:
        """Get count of findings per endpoint"""
        endpoints = {}
        for finding in self.findings:
            for endpoint in finding.affected_endpoints:
                endpoints[endpoint] = endpoints.get(endpoint, 0) + 1
        return dict(sorted(endpoints.items(), key=lambda x: x[1], reverse=True))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        metrics = self.get_metrics()
        return {
            "total_findings": metrics.total_findings,
            "by_severity": {
                "critical": metrics.critical_count,
                "high": metrics.high_count,
                "medium": metrics.medium_count,
                "low": metrics.low_count,
                "info": metrics.info_count
            },
            "risk_score": metrics.risk_score,
            "risk_level": metrics.risk_level,
            "top_findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "affected_endpoints": f.affected_endpoints
                }
                for f in self.get_top_findings(5)
            ],
            "affected_endpoints": self.get_affected_endpoints(),
            "trends": metrics.trends
        }


# Example usage
if __name__ == "__main__":
    # Create engine
    engine = RiskScoreEngine()
    
    # Add sample findings
    findings = [
        SecurityFinding(
            id="vuln_001",
            title="SQL Injection in /api/users",
            severity="CRITICAL",
            category="OWASP",
            description="User input not sanitized in SQL query",
            remediation="Use parameterized queries",
            affected_endpoints=["/api/users", "/api/users/{id}"]
        ),
        SecurityFinding(
            id="vuln_002",
            title="Missing Authentication on /api/admin",
            severity="CRITICAL",
            category="Auth",
            description="Admin endpoint accessible without authentication",
            remediation="Add JWT authentication middleware",
            affected_endpoints=["/api/admin"]
        ),
        SecurityFinding(
            id="vuln_003",
            title="Weak Password Policy",
            severity="HIGH",
            category="Auth",
            description="Passwords not enforced to be strong",
            remediation="Implement password strength requirements",
            affected_endpoints=["/api/auth/register"]
        ),
        SecurityFinding(
            id="vuln_004",
            title="Missing HTTPS",
            severity="HIGH",
            category="Encryption",
            description="API endpoints not using HTTPS",
            remediation="Enable HTTPS on all endpoints",
            affected_endpoints=["*"]
        ),
        SecurityFinding(
            id="vuln_005",
            title="Verbose Error Messages",
            severity="MEDIUM",
            category="Information Disclosure",
            description="Error messages reveal internal system details",
            remediation="Use generic error messages in production",
            affected_endpoints=["*"]
        ),
    ]
    
    engine.add_findings(findings)
    
    # Get metrics
    metrics = engine.get_metrics()
    print(f"Risk Score: {metrics.risk_score}/100")
    print(f"Risk Level: {metrics.risk_level}")
    print(f"Total Findings: {metrics.total_findings}")
    print(f"  Critical: {metrics.critical_count}")
    print(f"  High: {metrics.high_count}")
    print(f"  Medium: {metrics.medium_count}")
    print(f"  Low: {metrics.low_count}")
    print(f"  Info: {metrics.info_count}")
    
    print("\nTop Findings:")
    for finding in engine.get_top_findings(3):
        print(f"  [{finding.severity}] {finding.title}")
    
    print("\nAffected Endpoints:")
    for endpoint, count in engine.get_affected_endpoints().items():
        print(f"  {endpoint}: {count} findings")
    
    print("\nFull Metrics:")
    import json
    print(json.dumps(engine.to_dict(), indent=2))
