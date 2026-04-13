"""
DevPulse - Backend Tests
Unit and integration tests for backend services
"""

import pytest
from fastapi.testclient import TestClient
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from backend.main import app
from services.risk_score_engine import RiskScoreEngine
from services.postman_parser import PostmanParser


@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)


class TestHealthCheck:
    """Health check endpoint tests"""
    
    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["success"] is True
    
    def test_status_endpoint(self, client):
        """Test status endpoint"""
        response = client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "status" in data


class TestAuthentication:
    """Authentication tests"""
    
    def test_register_user(self, client):
        """Test user registration"""
        response = client.post(
            "/api/auth/register",
            json={"email": "test@example.com", "password": "TestPass123"}
        )
        assert response.status_code == 200
        assert response.json()["success"] is True
    
    def test_login_user(self, client):
        """Test user login"""
        # Register first
        client.post(
            "/api/auth/register",
            json={"email": "test@example.com", "password": "TestPass123"}
        )
        
        # Then login
        response = client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "TestPass123"}
        )
        assert response.status_code == 200
        assert response.json()["success"] is True
        assert "token" in response.json()


class TestRiskScoreEngine:
    """Risk score engine tests"""
    
    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        engine = RiskScoreEngine()
        
        # Add some findings
        findings = [
            {"severity": "critical", "type": "sql_injection"},
            {"severity": "high", "type": "xss"},
            {"severity": "medium", "type": "csrf"},
        ]
        
        for finding in findings:
            engine.add_finding(finding)
        
        # Get metrics
        metrics = engine.get_metrics()
        assert metrics.total_findings == 3
        assert metrics.risk_score > 0
    
    def test_risk_level_determination(self):
        """Test risk level determination"""
        engine = RiskScoreEngine()
        
        # Low risk
        engine.add_finding({"severity": "low"})
        metrics = engine.get_metrics()
        assert metrics.risk_level in ["LOW", "MEDIUM"]
        
        # High risk
        engine2 = RiskScoreEngine()
        for _ in range(5):
            engine2.add_finding({"severity": "critical"})
        metrics2 = engine2.get_metrics()
        assert metrics2.risk_level == "CRITICAL"


class TestPostmanParser:
    """Postman parser tests"""
    
    def test_parse_simple_collection(self):
        """Test parsing simple Postman collection"""
        parser = PostmanParser()
        
        collection_data = {
            "info": {"name": "Test Collection"},
            "item": [
                {
                    "name": "Test Request",
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/users"
                    }
                }
            ]
        }
        
        result = parser.parse_collection(collection_data)
        assert result["name"] == "Test Collection"
        assert len(result["requests"]) == 1
        assert result["requests"][0]["method"] == "GET"
    
    def test_parse_nested_collection(self):
        """Test parsing nested Postman collection"""
        parser = PostmanParser()
        
        collection_data = {
            "info": {"name": "Nested Collection"},
            "item": [
                {
                    "name": "Folder",
                    "item": [
                        {
                            "name": "Request 1",
                            "request": {
                                "method": "POST",
                                "url": "https://api.example.com/users"
                            }
                        }
                    ]
                }
            ]
        }
        
        result = parser.parse_collection(collection_data)
        assert result["name"] == "Nested Collection"
        assert len(result["requests"]) >= 1


class TestScanEndpoint:
    """Scan endpoint tests"""
    
    def test_scan_code_requires_auth(self, client):
        """Test that scan endpoint requires authentication"""
        response = client.post(
            "/api/scan/code",
            json={"code": "print('hello')", "language": "python"}
        )
        # Should fail without auth token
        assert response.status_code in [401, 422]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
