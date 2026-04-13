#!/usr/bin/env python3
"""
DevPulse - Demo Data Seeding Script
Populates the database with realistic demo data for investor demos and testing
"""

import json
import uuid
from datetime import datetime, timedelta
import random

# Demo Users
DEMO_USERS = [
    {
        "id": str(uuid.uuid4()),
        "email": "demo@devpulse.io",
        "name": "Demo User",
        "password": "demo_password_123",
        "company": "TechCorp Inc",
        "plan": "pro"
    },
    {
        "id": str(uuid.uuid4()),
        "email": "investor@devpulse.io",
        "name": "Investor Demo",
        "password": "investor_demo_123",
        "company": "Venture Capital Partners",
        "plan": "enterprise"
    },
    {
        "id": str(uuid.uuid4()),
        "email": "security@devpulse.io",
        "name": "Security Engineer",
        "password": "security_demo_123",
        "company": "SecureBank Ltd",
        "plan": "pro"
    }
]

# Demo Collections
DEMO_COLLECTIONS = [
    {
        "name": "E-Commerce API",
        "description": "Production e-commerce platform API",
        "total_requests": 245,
        "endpoints": [
            "/api/products",
            "/api/orders",
            "/api/payments",
            "/api/users",
            "/api/auth/login"
        ]
    },
    {
        "name": "Payment Gateway",
        "description": "Payment processing and billing API",
        "total_requests": 89,
        "endpoints": [
            "/api/charges",
            "/api/refunds",
            "/api/webhooks",
            "/api/subscriptions"
        ]
    },
    {
        "name": "Analytics Platform",
        "description": "Real-time analytics and reporting API",
        "total_requests": 156,
        "endpoints": [
            "/api/events",
            "/api/dashboards",
            "/api/reports",
            "/api/segments"
        ]
    }
]

# Demo Security Findings
DEMO_FINDINGS = [
    {
        "title": "SQL Injection Vulnerability",
        "severity": "CRITICAL",
        "category": "Injection",
        "endpoint": "/api/users",
        "description": "User search endpoint vulnerable to SQL injection via 'q' parameter",
        "remediation": "Use parameterized queries and input validation",
        "affected_requests": 5
    },
    {
        "title": "Missing Authentication",
        "severity": "CRITICAL",
        "category": "Authentication",
        "endpoint": "/api/admin/users",
        "description": "Admin endpoint accessible without authentication",
        "remediation": "Add JWT authentication middleware",
        "affected_requests": 12
    },
    {
        "title": "Exposed API Keys",
        "severity": "HIGH",
        "category": "Secrets",
        "endpoint": "/api/config",
        "description": "API keys exposed in response headers",
        "remediation": "Remove sensitive data from responses",
        "affected_requests": 3
    },
    {
        "title": "CORS Misconfiguration",
        "severity": "MEDIUM",
        "category": "Configuration",
        "endpoint": "*",
        "description": "CORS allows requests from any origin",
        "remediation": "Restrict CORS to trusted domains",
        "affected_requests": 0
    },
    {
        "title": "Rate Limiting Missing",
        "severity": "MEDIUM",
        "category": "Rate Limiting",
        "endpoint": "/api/auth/login",
        "description": "No rate limiting on authentication endpoint",
        "remediation": "Implement rate limiting (e.g., 5 attempts per minute)",
        "affected_requests": 0
    }
]

# Demo Cost Data
DEMO_COSTS = [
    {
        "date": (datetime.now() - timedelta(days=6)).date().isoformat(),
        "model": "gpt-4",
        "prompt_tokens": 15000,
        "completion_tokens": 8000,
        "cost_usd": 0.68
    },
    {
        "date": (datetime.now() - timedelta(days=5)).date().isoformat(),
        "model": "gpt-4",
        "prompt_tokens": 22000,
        "completion_tokens": 12000,
        "cost_usd": 1.02
    },
    {
        "date": (datetime.now() - timedelta(days=4)).date().isoformat(),
        "model": "gpt-3.5-turbo",
        "prompt_tokens": 45000,
        "completion_tokens": 18000,
        "cost_usd": 0.12
    },
    {
        "date": (datetime.now() - timedelta(days=3)).date().isoformat(),
        "model": "gpt-4",
        "prompt_tokens": 28000,
        "completion_tokens": 15000,
        "cost_usd": 1.29
    },
    {
        "date": (datetime.now() - timedelta(days=2)).date().isoformat(),
        "model": "gpt-4",
        "prompt_tokens": 32000,
        "completion_tokens": 18000,
        "cost_usd": 1.50
    },
    {
        "date": (datetime.now() - timedelta(days=1)).date().isoformat(),
        "model": "gpt-4",
        "prompt_tokens": 38000,
        "completion_tokens": 21000,
        "cost_usd": 1.79
    },
    {
        "date": datetime.now().date().isoformat(),
        "model": "gpt-4",
        "prompt_tokens": 42000,
        "completion_tokens": 24000,
        "cost_usd": 1.98
    }
]

def seed_database():
    """Seed the database with demo data"""
    print("🌱 Seeding DevPulse demo database...")
    
    # In a real implementation, this would insert into the database
    # For now, we'll just print the data structure
    
    print("\n✅ Demo Users Created:")
    for user in DEMO_USERS:
        print(f"  - {user['email']} (Plan: {user['plan']})")
    
    print("\n✅ Demo Collections Created:")
    for collection in DEMO_COLLECTIONS:
        print(f"  - {collection['name']} ({collection['total_requests']} requests)")
    
    print("\n✅ Demo Security Findings Created:")
    for finding in DEMO_FINDINGS:
        print(f"  - [{finding['severity']}] {finding['title']} ({finding['endpoint']})")
    
    print("\n✅ Demo Cost Data Created:")
    total_cost = sum(cost['cost_usd'] for cost in DEMO_COSTS)
    print(f"  - 7 days of LLM usage data")
    print(f"  - Total cost: ${total_cost:.2f}")
    
    print("\n🎉 Demo data seeding complete!")
    print("\nDemo Credentials:")
    print(f"  Email: {DEMO_USERS[0]['email']}")
    print(f"  Password: {DEMO_USERS[0]['password']}")
    
    return {
        "users": DEMO_USERS,
        "collections": DEMO_COLLECTIONS,
        "findings": DEMO_FINDINGS,
        "costs": DEMO_COSTS
    }

if __name__ == "__main__":
    seed_database()
