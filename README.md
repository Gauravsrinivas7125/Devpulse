# DevPulse - Production-Ready API Security & LLM Cost Intelligence

[![CI](https://github.com/anugownori/pulse-dashboard/actions/workflows/ci.yml/badge.svg)](https://github.com/anugownori/pulse-dashboard/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688.svg)](https://fastapi.tiangolo.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**Version:** 1.0.0  
**Status:** Production-Ready  
**Last Updated:** April 11, 2026

---

## Overview

DevPulse is a comprehensive API security and LLM cost intelligence platform that helps developers:

- 🔒 **Detect Security Vulnerabilities** - OWASP Top 10, injection attacks, authentication issues
- 💰 **Track LLM Costs** - Attribution for OpenAI o1 thinking tokens and other models
- 🛡️ **Block Dangerous Requests** - Autonomous kill switch for real-time threat blocking
- 🔍 **Find Shadow APIs** - Detect undocumented endpoints
- 📋 **Generate Compliance Reports** - PCI DSS and other standards
- 📊 **Unified Risk Scoring** - Aggregate security findings into actionable metrics

---

## Quick Start

### Prerequisites

- Python 3.9+
- pip or poetry
- PostgreSQL (optional, uses in-memory storage by default)
- Redis (optional, for caching)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/devpulse/devpulse.git
cd devpulse_production
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Run the server**
```bash
python src/backend/main.py
```

The API will be available at `http://localhost:8000`

---

## Architecture

```
devpulse_production/
├── src/
│   ├── backend/
│   │   └── main.py              # FastAPI application
│   ├── frontend/                # React UI (optional)
│   └── services/
│       ├── postman_parser.py    # Parse Postman collections
│       ├── risk_score_engine.py # Calculate unified risk score
│       ├── kill_switch.py       # Real-time threat blocking
│       ├── shadow_api_scanner.py # Detect undocumented APIs
│       ├── pci_compliance.py    # Generate compliance reports
│       └── thinking_tokens.py   # Track LLM costs
├── docs/                        # Documentation
├── config/                      # Configuration files
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

---

## Core Features

### 1. Postman Collection Parser

Import Postman collections and extract API endpoints, headers, authentication, and request bodies.

**Endpoint:** `POST /api/collections/import`

```bash
curl -X POST http://localhost:8000/api/collections/import \
  -F "file=@collection.json"
```

**Response:**
```json
{
  "success": true,
  "collection_id": "uuid",
  "total_requests": 42,
  "statistics": {
    "by_method": {"GET": 20, "POST": 15, "PUT": 5, "DELETE": 2},
    "with_auth": 35,
    "with_body": 20
  }
}
```

### 2. Unified Risk Score Engine

Aggregate security findings into a single 0-100 risk score with severity weighting.

**Endpoint:** `GET /api/risk-score`

```bash
curl http://localhost:8000/api/risk-score
```

**Response:**
```json
{
  "risk_score": 72.5,
  "risk_level": "HIGH",
  "total_findings": 12,
  "by_severity": {
    "critical": 2,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 0
  },
  "trends": {
    "trend": "increasing",
    "change": 5.2
  }
}
```

### 3. Autonomous Kill Switch

Real-time detection and blocking of dangerous API calls.

**Endpoint:** `POST /api/kill-switch/block`

```bash
curl -X POST http://localhost:8000/api/kill-switch/block \
  -H "Content-Type: application/json" \
  -d '{"request_id": "req_123", "reason": "SQL_INJECTION"}'
```

**Features:**
- SQL injection detection
- Command injection detection
- Path traversal detection
- XXE injection detection
- XSS detection
- Rate limiting
- Authentication enforcement

### 4. Shadow API Scanner

Detect undocumented API endpoints.

**Endpoint:** `POST /api/shadow-apis/scan`

```bash
curl -X POST http://localhost:8000/api/shadow-apis/scan \
  -H "Content-Type: application/json" \
  -d '{"collection_id": "uuid"}'
```

**Response:**
```json
{
  "collection_id": "uuid",
  "shadow_apis": [
    {
      "endpoint": "/api/admin",
      "risk_level": "CRITICAL",
      "reason": "Admin endpoint may allow unauthorized access",
      "recommendation": "Review and secure or remove this endpoint"
    }
  ],
  "total_shadow_apis": 3,
  "risk_impact": 15
}
```

### 5. PCI DSS Compliance Report Generator

Generate audit-ready compliance reports.

**Endpoint:** `POST /api/compliance/pci-dss`

```bash
curl -X POST http://localhost:8000/api/compliance/pci-dss \
  -H "Content-Type: application/json" \
  -d '{"collection_id": "uuid"}'
```

**Response:**
```json
{
  "report_id": "abc123",
  "collection_id": "uuid",
  "compliance_status": "COMPLIANT",
  "compliance_percentage": 83.3,
  "requirements": [...],
  "generated_at": "2024-04-09T10:30:00Z"
}
```

### 6. Thinking Token Attribution

Track and attribute LLM reasoning costs.

**Endpoint:** `POST /api/tokens/track`

```bash
curl -X POST http://localhost:8000/api/tokens/track \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "req_123",
    "model": "o1",
    "prompt_tokens": 500,
    "completion_tokens": 1000,
    "thinking_tokens": 5000
  }'
```

**Response:**
```json
{
  "request_id": "req_123",
  "tokens": {
    "prompt": 500,
    "completion": 1000,
    "thinking": 5000,
    "total": 6500
  },
  "cost": {
    "prompt": 0.0075,
    "completion": 0.06,
    "thinking": 0.75,
    "total": 0.8175
  }
}
```

### 7. Reasoning Efficiency Score (RES)

Measures how efficiently an LLM uses thinking tokens relative to output quality.

```python
from thinking_tokens_lib import ReasoningEfficiencyScore

res = ReasoningEfficiencyScore.calculate(
    thinking_tokens=5000,
    output_tokens=1000,
    quality_score=0.85,
)
# => {"score": 72.3, "grade": "A", "description": "Good efficiency", ...}
```

**Scale:**
| Score | Grade | Description |
|-------|-------|-------------|
| 90-100 | A+ | Exceptional - Minimal thinking for high-quality output |
| 70-89 | A | Good - Reasonable thinking-to-output ratio |
| 50-69 | B | Average - Some optimization possible |
| 30-49 | C | Below Average - Excessive reasoning detected |
| 0-29 | D | Poor - Possible infinite loop or waste |

---

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user

### Collections
- `POST /api/collections/import` - Import Postman collection
- `GET /api/collections` - List all collections
- `GET /api/collections/{id}` - Get collection details

### Security Scanning
- `POST /api/scan/code` - Scan code for vulnerabilities
- `GET /api/findings` - Get all findings
- `GET /api/risk-score` - Get unified risk score

### Kill Switch
- `POST /api/kill-switch/block` - Block a request
- `GET /api/kill-switch/status` - Get kill switch status

### Shadow APIs
- `POST /api/shadow-apis/scan` - Scan for shadow APIs

### Compliance
- `POST /api/compliance/pci-dss` - Generate PCI DSS report

### Tokens
- `POST /api/tokens/track` - Track thinking tokens
- `GET /api/tokens/analytics` - Get token analytics

### System
- `GET /api/health` - Health check
- `GET /api/status` - System status

---

## Configuration

Create a `.env` file in the project root:

```env
# Server
PORT=8000
DEBUG=False
ENVIRONMENT=production

# Database
DATABASE_URL=postgresql://user:password@localhost/devpulse
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600

# OpenAI
OPENAI_API_KEY=sk-...

# Stripe
STRIPE_API_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Supabase
SUPABASE_URL=https://...
SUPABASE_KEY=...
```

---

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Quality

```bash
# Format code
black src/

# Lint
flake8 src/

# Type checking
mypy src/
```

### Database Migrations

```bash
# Create migration
alembic revision --autogenerate -m "Add new table"

# Apply migrations
alembic upgrade head
```

---

## Production Deployment

### Docker

```bash
# Build image
docker build -t devpulse:latest .

# Run container
docker run -p 8000:8000 devpulse:latest
```

### Docker Compose

```bash
docker-compose up -d
```

### Kubernetes

```bash
kubectl apply -f k8s/deployment.yaml
```

---

## Performance Optimization

- **Caching:** Redis caching for frequent queries
- **Database Indexing:** Optimized queries with proper indexes
- **Async Processing:** Background jobs for heavy operations
- **Rate Limiting:** Protect API from abuse

---

## Security

- **Authentication:** JWT-based authentication
- **Authorization:** Role-based access control
- **Input Validation:** Pydantic models for validation
- **HTTPS:** Always use HTTPS in production
- **CORS:** Configured for specific origins

---

## Monitoring & Logging

- **Application Logs:** Structured logging with timestamps
- **Performance Metrics:** Track response times and throughput
- **Error Tracking:** Centralized error logging
- **Audit Trail:** Track all user actions

---

## Troubleshooting

### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000

# Kill process
kill -9 <PID>
```

### Database Connection Error
```bash
# Check database is running
psql -U user -h localhost -d devpulse

# Check connection string in .env
```

### Module Not Found
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

---

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## License

MIT License - see LICENSE file for details

---

## Support

- 📧 Email: support@devpulse.io
- 🐛 Issues: GitHub Issues
- 💬 Discord: [Join our community](https://discord.gg/devpulse)
- 📚 Docs: [Full documentation](https://docs.devpulse.io)

---

## Roadmap

- [ ] Machine learning-based threat detection
- [ ] Real-time dashboard with WebSocket updates
- [ ] GitHub/GitLab integration
- [ ] Slack notifications
- [ ] Mobile app
- [ ] Enterprise features (SSO, advanced reporting)

---

**Built with ❤️ by the DevPulse team**
