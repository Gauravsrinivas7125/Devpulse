"""
DevPulse - API Endpoint Integration Tests
Tests for all major API endpoints with authentication
"""

import pytest
from fastapi.testclient import TestClient
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers(client):
    """Register a user and return auth headers"""
    import uuid
    email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    resp = client.post("/api/auth/register", params={"email": email, "password": "SecureP@ss123"})
    token = resp.json().get("token", "")
    return {"Authorization": f"Bearer {token}"}


class TestHealthEndpoints:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_status(self, client):
        r = client.get("/api/status")
        assert r.status_code == 200
        data = r.json()
        assert "collections" in data


class TestAuthEndpoints:
    def test_register(self, client):
        import uuid
        email = f"reg_{uuid.uuid4().hex[:8]}@test.com"
        r = client.post("/api/auth/register", params={"email": email, "password": "Pass123!"})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert "token" in data
        assert "user_id" in data

    def test_register_duplicate(self, client):
        import uuid
        email = f"dup_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/api/auth/register", params={"email": email, "password": "Pass123!"})
        r = client.post("/api/auth/register", params={"email": email, "password": "Pass123!"})
        assert r.status_code == 400

    def test_login_success(self, client):
        import uuid
        email = f"login_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/api/auth/register", params={"email": email, "password": "Pass123!"})
        r = client.post("/api/auth/login", params={"email": email, "password": "Pass123!"})
        assert r.status_code == 200
        assert r.json()["success"] is True

    def test_login_wrong_password(self, client):
        import uuid
        email = f"wrong_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/api/auth/register", params={"email": email, "password": "Pass123!"})
        r = client.post("/api/auth/login", params={"email": email, "password": "WrongPass!"})
        assert r.status_code == 401

    def test_login_nonexistent(self, client):
        r = client.post("/api/auth/login", params={"email": "nobody@test.com", "password": "Pass123!"})
        assert r.status_code == 401


class TestProtectedEndpoints:
    def test_scan_requires_auth(self, client):
        r = client.post("/api/scan/code", params={"code": "x=1", "language": "python"})
        assert r.status_code in [401, 403, 422]

    def test_risk_score_requires_auth(self, client):
        r = client.get("/api/risk-score")
        assert r.status_code in [401, 403]

    def test_findings_requires_auth(self, client):
        r = client.get("/api/findings")
        assert r.status_code in [401, 403]

    def test_kill_switch_requires_auth(self, client):
        r = client.get("/api/kill-switch/status")
        assert r.status_code in [401, 403]

    def test_collections_requires_auth(self, client):
        r = client.get("/api/collections")
        assert r.status_code in [401, 403]


class TestScanEndpoints:
    def test_scan_code_clean(self, client, auth_headers):
        r = client.post(
            "/api/scan/code",
            params={"code": "x = 1 + 2", "language": "python"},
            headers=auth_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert "scan_id" in data
        assert data["total_findings"] == 0

    def test_scan_code_with_vulnerability(self, client, auth_headers):
        r = client.post(
            "/api/scan/code",
            params={"code": "eval(user_input)", "language": "python"},
            headers=auth_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["total_findings"] > 0
        assert data["risk_score"] > 0


class TestRiskScoreEndpoints:
    def test_get_risk_score(self, client, auth_headers):
        r = client.get("/api/risk-score", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "risk_score" in data
        assert "risk_level" in data
        assert "by_severity" in data


class TestKillSwitchEndpoints:
    def test_get_status(self, client, auth_headers):
        r = client.get("/api/kill-switch/status", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "enabled" in data
        assert "blocked_count" in data

    def test_block_request(self, client, auth_headers):
        r = client.post(
            "/api/kill-switch/block",
            params={"request_id": "test_req", "reason": "SQL_INJECTION"},
            headers=auth_headers,
        )
        assert r.status_code == 200
        assert r.json()["success"] is True


class TestTokenEndpoints:
    def test_track_tokens(self, client, auth_headers):
        r = client.post(
            "/api/tokens/track",
            params={
                "request_id": "tok_test",
                "model": "o1",
                "prompt_tokens": 500,
                "completion_tokens": 1000,
                "thinking_tokens": 5000,
            },
            headers=auth_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["request_id"] == "tok_test"
        assert "cost" in data

    def test_token_analytics(self, client, auth_headers):
        r = client.get("/api/tokens/analytics", headers=auth_headers)
        assert r.status_code == 200
        assert "summary" in r.json()


class TestPlanEndpoints:
    def test_plan_limits(self, client, auth_headers):
        r = client.get("/api/plan/limits", headers=auth_headers)
        assert r.status_code == 200


class TestCollectionEndpoints:
    def test_list_collections_empty(self, client, auth_headers):
        r = client.get("/api/collections", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "collections" in data

    def test_import_collection(self, client, auth_headers):
        collection = {
            "info": {"name": "Test API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": [
                {"name": "Get Users", "request": {"method": "GET", "url": "https://api.example.com/users"}}
            ],
        }
        r = client.post(
            "/api/collections/import",
            files={"file": ("test.json", json.dumps(collection), "application/json")},
            headers=auth_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert "collection_id" in data


class TestOnboardingEndpoints:
    def test_onboarding_steps(self, client, auth_headers):
        r = client.get("/api/onboarding/steps", headers=auth_headers)
        assert r.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
