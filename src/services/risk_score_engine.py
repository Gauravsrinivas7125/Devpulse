"""
DevPulse - Unified Risk Score Engine (Market-Ready, Patent 1 Core)
Combines security vulnerability severity WITH LLM cost anomaly data
into a single 0-100 unified risk score. This is the core innovation
of Patent 1: "Unified Security-Cost Risk Scoring for API Ecosystems."

The score formula: R = w_s * SecurityScore + w_c * CostAnomalyScore
where w_s and w_c are configurable weights (default 0.7 / 0.3).
"""

import math
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


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
class CostAnomaly:
    """Represents an LLM cost anomaly event (Patent 1 integration)"""
    anomaly_id: str
    anomaly_type: str  # "spike", "budget_breach", "runaway_loop", "model_drift"
    severity: str
    model: str
    expected_cost: float
    actual_cost: float
    deviation_percentage: float
    timestamp: str
    description: str


@dataclass
class RiskMetrics:
    """Risk assessment metrics including cost anomaly data"""
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float  # 0-100 unified score
    security_score: float  # 0-100 security-only component
    cost_anomaly_score: float  # 0-100 cost anomaly component
    risk_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    cost_anomalies: int
    trends: Dict[str, Any]


class RiskScoreEngine:
    """
    Patent 1 Core: Unified Security-Cost Risk Scoring Engine.
    
    Combines traditional security vulnerability scoring with LLM cost
    anomaly signals to produce a single actionable risk score.
    
    Formula: R = w_s * S + w_c * C
    where S = security score, C = cost anomaly score
    """
    
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
    
    # Patent 1: Security vs Cost weighting (configurable)
    SECURITY_WEIGHT = 0.7
    COST_WEIGHT = 0.3
    
    # Cost anomaly scoring
    COST_ANOMALY_WEIGHTS = {
        "spike": 15,
        "budget_breach": 25,
        "runaway_loop": 30,
        "model_drift": 10,
    }
    
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.cost_anomalies: List[CostAnomaly] = []
        self.historical_scores: List[float] = []
        self._security_score_cache: Optional[float] = None
        self._cost_score_cache: Optional[float] = None
    
    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a security finding"""
        self.findings.append(finding)
        self._security_score_cache = None
    
    def add_findings(self, findings: List[SecurityFinding]) -> None:
        """Add multiple security findings"""
        self.findings.extend(findings)
        self._security_score_cache = None
    
    def add_cost_anomaly(self, anomaly: CostAnomaly) -> None:
        """Add an LLM cost anomaly signal (Patent 1)"""
        self.cost_anomalies.append(anomaly)
        self._cost_score_cache = None
    
    def add_cost_anomalies(self, anomalies: List[CostAnomaly]) -> None:
        """Add multiple cost anomaly signals"""
        self.cost_anomalies.extend(anomalies)
        self._cost_score_cache = None
    
    def ingest_cost_anomaly(
        self,
        anomaly_id: str,
        anomaly_type: str,
        model: str,
        expected_cost: float,
        actual_cost: float,
        description: str = "",
    ) -> CostAnomaly:
        """Convenience method to create and ingest a cost anomaly"""
        deviation = ((actual_cost - expected_cost) / expected_cost * 100) if expected_cost > 0 else 0
        severity = "CRITICAL" if deviation > 500 else "HIGH" if deviation > 200 else "MEDIUM" if deviation > 100 else "LOW"
        
        anomaly = CostAnomaly(
            anomaly_id=anomaly_id,
            anomaly_type=anomaly_type,
            severity=severity,
            model=model,
            expected_cost=expected_cost,
            actual_cost=actual_cost,
            deviation_percentage=round(deviation, 1),
            timestamp=datetime.utcnow().isoformat(),
            description=description or f"{anomaly_type}: {model} cost ${actual_cost:.2f} vs expected ${expected_cost:.2f}",
        )
        self.add_cost_anomaly(anomaly)
        return anomaly
    
    def _calculate_security_score(self) -> float:
        """Calculate security-only score (0-100)"""
        if not self.findings:
            return 0.0
        
        severity_counts = self._count_by_severity()
        weighted_score = (
            severity_counts["CRITICAL"] * self.CRITICAL_WEIGHT +
            severity_counts["HIGH"] * self.HIGH_WEIGHT +
            severity_counts["MEDIUM"] * self.MEDIUM_WEIGHT +
            severity_counts["LOW"] * self.LOW_WEIGHT +
            severity_counts["INFO"] * self.INFO_WEIGHT
        )
        
        max_possible_score = len(self.findings) * self.CRITICAL_WEIGHT
        normalized_score = (weighted_score / max_possible_score) * 100
        score = min(100, normalized_score * (1 + 0.1 * len(self.findings) ** 0.5))
        return round(score, 1)
    
    def _calculate_cost_anomaly_score(self) -> float:
        """Calculate cost anomaly score (0-100) - Patent 1 innovation"""
        if not self.cost_anomalies:
            return 0.0
        
        weighted_score = 0.0
        for anomaly in self.cost_anomalies:
            base_weight = self.COST_ANOMALY_WEIGHTS.get(anomaly.anomaly_type, 10)
            # Scale by deviation magnitude (log scale to prevent extreme inflation)
            deviation_factor = 1 + math.log1p(abs(anomaly.deviation_percentage) / 100)
            weighted_score += base_weight * deviation_factor
        
        # Normalize with diminishing returns
        score = min(100, weighted_score * (1 + 0.05 * len(self.cost_anomalies) ** 0.5))
        return round(score, 1)
    
    def calculate_score(self) -> float:
        """
        Calculate UNIFIED risk score (0-100) - Patent 1 Core Algorithm
        
        R = w_s * SecurityScore + w_c * CostAnomalyScore
        
        This is the core patent innovation: a single score that combines
        security vulnerability severity with LLM cost anomaly data.
        """
        security_score = self._calculate_security_score()
        cost_score = self._calculate_cost_anomaly_score()
        
        # If we only have one signal type, that signal gets full weight
        if not self.findings and not self.cost_anomalies:
            return 0.0
        elif not self.findings:
            unified = cost_score
        elif not self.cost_anomalies:
            unified = security_score
        else:
            unified = (
                self.SECURITY_WEIGHT * security_score +
                self.COST_WEIGHT * cost_score
            )
        
        risk_score = round(min(100, unified), 1)
        self.historical_scores.append(risk_score)
        self._security_score_cache = security_score
        self._cost_score_cache = cost_score
        return risk_score
    
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
        """Get comprehensive risk metrics including cost anomaly data"""
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
            security_score=self._security_score_cache or 0.0,
            cost_anomaly_score=self._cost_score_cache or 0.0,
            risk_level=risk_level,
            cost_anomalies=len(self.cost_anomalies),
            trends=trends,
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
        """Convert metrics to dictionary (includes Patent 1 unified score)"""
        metrics = self.get_metrics()
        return {
            "total_findings": metrics.total_findings,
            "by_severity": {
                "critical": metrics.critical_count,
                "high": metrics.high_count,
                "medium": metrics.medium_count,
                "low": metrics.low_count,
                "info": metrics.info_count,
            },
            "risk_score": metrics.risk_score,
            "security_score": metrics.security_score,
            "cost_anomaly_score": metrics.cost_anomaly_score,
            "risk_level": metrics.risk_level,
            "cost_anomalies": metrics.cost_anomalies,
            "top_findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "affected_endpoints": f.affected_endpoints,
                }
                for f in self.get_top_findings(5)
            ],
            "cost_anomaly_details": [
                {
                    "anomaly_id": a.anomaly_id,
                    "type": a.anomaly_type,
                    "severity": a.severity,
                    "model": a.model,
                    "deviation": a.deviation_percentage,
                    "description": a.description,
                }
                for a in self.cost_anomalies[-10:]
            ],
            "affected_endpoints": self.get_affected_endpoints(),
            "trends": metrics.trends,
        }
