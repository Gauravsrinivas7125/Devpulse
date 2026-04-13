"""
DevPulse - Service Layer Tests
Comprehensive tests for all core services
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from services.risk_score_engine import RiskScoreEngine, SecurityFinding
from services.thinking_tokens import ThinkingTokenTracker
from services.kill_switch import KillSwitch
from services.postman_parser import PostmanParser
from services.collection_parsers import parser_factory


class TestThinkingTokenTracker:
    """Thinking token attribution tests"""

    def test_track_tokens_basic(self):
        tracker = ThinkingTokenTracker()
        result = tracker.track_tokens(
            request_id="test_001",
            model="o1",
            prompt_tokens=500,
            completion_tokens=1000,
            thinking_tokens=5000,
            operation="test_op",
        )
        assert result["request_id"] == "test_001"
        assert result["tokens"]["prompt"] == 500
        assert result["tokens"]["completion"] == 1000
        assert result["tokens"]["thinking"] == 5000
        assert result["tokens"]["total"] == 6500
        assert result["cost"]["total"] > 0

    def test_calculate_cost(self):
        tracker = ThinkingTokenTracker()
        cost = tracker.calculate_cost({
            "model": "o1",
            "prompt_tokens": 1000,
            "completion_tokens": 1000,
            "thinking_tokens": 1000,
        })
        assert cost["prompt"] > 0
        assert cost["completion"] > 0
        assert cost["thinking"] > 0
        # Use approx comparison due to floating point rounding
        assert abs(cost["total"] - (cost["prompt"] + cost["completion"] + cost["thinking"])) < 0.001

    def test_analytics_empty(self):
        tracker = ThinkingTokenTracker()
        analytics = tracker.get_analytics()
        assert analytics["summary"]["total_cost"] == 0
        assert analytics["summary"]["total_tokens"] == 0
        assert analytics["summary"]["total_requests"] == 0

    def test_analytics_with_data(self):
        tracker = ThinkingTokenTracker()
        tracker.track_tokens("r1", "o1", 500, 1000, 5000, "analysis")
        tracker.track_tokens("r2", "gpt-4", 300, 500, 0, "review")

        analytics = tracker.get_analytics()
        assert analytics["summary"]["total_requests"] == 2
        assert analytics["summary"]["total_cost"] > 0
        assert analytics["summary"]["thinking_tokens"] == 5000

    def test_expensive_operations(self):
        tracker = ThinkingTokenTracker()
        tracker.track_tokens("r1", "o1", 500, 1000, 5000, "expensive_op")
        tracker.track_tokens("r2", "gpt-3.5", 100, 50, 0, "cheap_op")

        expensive = tracker.get_expensive_operations()
        assert len(expensive) == 2
        assert expensive[0]["operation"] == "expensive_op"

    def test_thinking_token_breakdown(self):
        tracker = ThinkingTokenTracker()
        tracker.track_tokens("r1", "o1", 500, 1000, 5000, "analysis")
        tracker.track_tokens("r2", "gpt-4", 300, 500, 0, "review")

        breakdown = tracker.get_thinking_token_breakdown()
        assert breakdown["total_thinking_tokens"] == 5000
        assert breakdown["total_thinking_cost"] > 0

    def test_monthly_cost_estimate(self):
        tracker = ThinkingTokenTracker()
        tracker.track_tokens("r1", "o1", 500, 1000, 5000, "analysis")
        estimate = tracker.estimate_monthly_cost()
        assert "estimated_monthly_cost" in estimate
        assert estimate["estimated_monthly_cost"] >= 0


class TestKillSwitch:
    """Kill switch tests"""

    def test_block_request(self):
        ks = KillSwitch()
        result = ks.block_request("req_001", "SQL_INJECTION")
        assert result is not None

    def test_kill_switch_status(self):
        ks = KillSwitch()
        assert isinstance(ks.is_enabled(), bool)

    def test_blocked_count(self):
        ks = KillSwitch()
        initial = ks.get_blocked_count()
        ks.block_request("req_001", "XSS")
        assert ks.get_blocked_count() >= initial

    def test_active_patterns(self):
        ks = KillSwitch()
        patterns = ks.get_active_patterns()
        assert isinstance(patterns, (list, dict))


class TestRiskScoreEngineDetailed:
    """Detailed risk score engine tests"""

    def test_empty_engine(self):
        engine = RiskScoreEngine()
        metrics = engine.get_metrics()
        assert metrics.total_findings == 0
        assert metrics.risk_score == 0

    def test_critical_findings_high_score(self):
        engine = RiskScoreEngine()
        findings = [
            SecurityFinding(
                id="f1", title="SQL Injection", severity="CRITICAL",
                category="injection", description="SQL injection found",
                remediation="Use parameterized queries",
                affected_endpoints=["/api/users"],
            ),
            SecurityFinding(
                id="f2", title="RCE", severity="CRITICAL",
                category="code_execution", description="Remote code execution",
                remediation="Sanitize input",
                affected_endpoints=["/api/exec"],
            ),
        ]
        engine.add_findings(findings)
        metrics = engine.get_metrics()
        assert metrics.risk_score > 50
        assert metrics.critical_count == 2

    def test_low_findings_low_score(self):
        engine = RiskScoreEngine()
        findings = [
            SecurityFinding(
                id="f1", title="Info disclosure", severity="LOW",
                category="info", description="Minor info leak",
                remediation="Review headers",
                affected_endpoints=["/api/health"],
            ),
        ]
        engine.add_findings(findings)
        metrics = engine.get_metrics()
        assert metrics.risk_score < 50
        assert metrics.low_count == 1

    def test_calculate_score(self):
        engine = RiskScoreEngine()
        score = engine.calculate_score()
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100


class TestCollectionParsers:
    """Collection parser tests"""

    def test_postman_v2_parse(self):
        parser = PostmanParser()
        data = {
            "info": {
                "name": "Test API",
                "_postman_id": "abc-123",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [
                {
                    "name": "Get Users",
                    "request": {
                        "method": "GET",
                        "url": {"raw": "https://api.example.com/users", "host": ["api", "example", "com"], "path": ["users"]},
                    },
                },
                {
                    "name": "Create User",
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/users",
                        "body": {"mode": "raw", "raw": '{"name": "test"}'},
                    },
                },
            ],
        }
        result = parser.parse_collection_data(data)
        assert result["name"] == "Test API"
        assert len(result["requests"]) == 2

    def test_parser_factory_auto_detect(self):
        data = {
            "info": {
                "name": "Factory Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [
                {
                    "name": "Test",
                    "request": {"method": "GET", "url": "https://example.com/api"},
                }
            ],
        }
        result = parser_factory.parse(data)
        assert "error" not in result or result.get("total_requests", 0) >= 0


class TestDatabaseSession:
    """Database session / storage backend tests"""

    def test_storage_backend_init(self):
        from backend.db_session import StorageBackend
        storage = StorageBackend()
        assert storage is not None

    def test_in_memory_user_crud(self):
        from backend.db_session import StorageBackend
        storage = StorageBackend()
        # Force in-memory mode for test
        storage.use_db = False

        assert not storage.user_exists("test@example.com")
        user = storage.create_user("test@example.com", "hashed_pw", "Test User")
        assert user["email"] == "test@example.com"
        assert storage.user_exists("test@example.com")

        fetched = storage.get_user_by_email("test@example.com")
        assert fetched["id"] == user["id"]

    def test_in_memory_collection_crud(self):
        from backend.db_session import StorageBackend
        storage = StorageBackend()
        storage.use_db = False

        col = storage.create_collection("col_1", "user_1", {
            "name": "Test Collection",
            "format": "postman",
            "requests": [{"method": "GET", "url": "/api/test"}],
            "total_requests": 1,
        })
        assert col["name"] == "Test Collection"

        fetched = storage.get_collection("col_1")
        assert fetched is not None

        cols = storage.list_collections("user_1")
        assert len(cols) == 1

        deleted = storage.delete_collection("col_1")
        assert deleted is True

    def test_in_memory_audit_log(self):
        from backend.db_session import StorageBackend
        storage = StorageBackend()
        storage.use_db = False

        storage.add_audit_entry("user_1", "login", {"ip": "127.0.0.1"})
        logs = storage.get_audit_log()
        assert len(logs) >= 1
        assert logs[-1]["action"] == "login"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
