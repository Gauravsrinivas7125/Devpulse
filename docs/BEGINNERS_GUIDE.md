# DevPulse Beginner's Guide

Welcome to DevPulse! This guide will help you understand the codebase architecture, key components, and how to get started with development.

## Project Structure

```
devpulse_production/
├── src/
│   ├── backend/          # FastAPI backend services
│   ├── services/         # Core security engines
│   ├── frontend/         # React TypeScript UI
│   ├── vscode_extension/ # VS Code extension
│   └── admin/            # Admin dashboard service
├── cli/                  # Command-line interface
├── docs/                 # Documentation
├── config/               # Configuration files
├── tests/                # Test suite
├── Dockerfile            # Docker container definition
├── docker-compose.yml    # Local development setup
├── requirements.txt      # Python dependencies
└── README.md             # Project overview
```

## Core Components

### 1. Backend (`src/backend/`)

**main.py** - FastAPI application entry point
- Initializes the REST API
- Defines all HTTP endpoints
- Mounts TRPC router for type-safe RPC calls
- Integrates WebSocket connections

**auth_service.py** - Authentication & Authorization
- User signup and login
- JWT token management
- Workspace access control (`check_workspace_access`)
- Session management

**trpc_router.py** - Type-safe RPC routing
- Collections management (import, list)
- Security scanning
- Usage tracking
- Workspace-level security middleware

**types.py** - Pydantic type definitions
- API request/response models
- Enums for severity levels, plan types, scan status
- Type validation and serialization

**usage_counter.py** - Usage tracking
- Atomic increment operations (Redis-style)
- Thread-safe counters with locking
- Plan limit enforcement
- Monthly reset logic

**db_transactions.py** - Database operations
- SQLAlchemy transaction wrappers
- Atomic multi-table writes
- Connection pooling

**csrf_protection.py** - CSRF token management
- Token generation and validation
- Request verification

**dead_letter_queue.py** - Failed job handling
- BullMQ job queue simulation
- Retry logic with exponential backoff
- Next retry timestamp tracking

### 2. Services (`src/services/`)

**risk_score_engine.py** - Unified risk scoring
- Aggregates security findings into 0-100 score
- Severity-weighted calculation
- Trend analysis and historical tracking

**postman_parser.py** - Postman collection parsing
- Supports v2.1 collections
- Recursive folder parsing
- Request extraction and validation

**shadow_api_scanner.py** - Shadow API detection
- Identifies undocumented endpoints
- SSRF protection with IP validation
- Internal/metadata scan blocking

**kill_switch.py** - AgentGuard™ autonomous kill switch
- Loop detection
- Emergency agent termination
- Autonomous safety mechanisms

**pci_compliance.py** - PCI DSS v4.0.1 mapping
- Automated evidence generation
- Compliance percentage calculation
- Requirement mapping

**thinking_tokens.py** - O1-model cost attribution
- Thinking token isolation
- Cost calculation per model
- Monthly estimation

**pdf_generator.py** - PDF report generation
- Security findings reports
- Compliance reports
- Professional formatting with fpdf2

### 3. Frontend (`src/frontend/`)

**App.tsx** - Main application shell
- Central routing with React Router
- Authentication state management
- Onboarding wizard integration
- Responsive layout

**dashboards.tsx** - Dashboard pages
- 16 responsive dashboard components
- Tailwind CSS grid layouts
- Mobile-first design

**mobile_responsive.tsx** - Responsive utilities
- `useResponsive` hook for breakpoints
- Responsive navigation component
- Container with adaptive padding

**onboarding_notifications.tsx** - User onboarding
- Multi-step wizard
- Notification system
- Backend API wiring

### 4. VS Code Extension (`src/vscode_extension/`)

**security_panel.ts** - IDE security panel
- WebviewViewProvider implementation
- Real-time finding display
- Export and report functionality

**SecurityWebview.tsx** - Webview component
- Finding visualization
- Risk score display
- Severity badges

### 5. Admin Dashboard (`src/admin/`)

**admin_dashboard.py** - Analytics service
- Signup tracking
- Download analytics
- Revenue tracking
- MRR calculation

### 6. CLI Tool (`cli/`)

**devpulse_cli.py** - Command-line interface
- Collection import
- Security scanning
- Compliance reporting
- Server status checks

## Key Workflows

### 1. Importing a Collection

```
User → CLI/UI → /api/collections/import
  → PostmanParser.parse_collection_data()
  → Validate requests
  → Store in collections_db
  → Return collection_id
```

### 2. Running a Security Scan

```
User → /api/security/scan
  → RiskScoreEngine.calculate_score()
  → ShadowAPIScanner.scan()
  → KillSwitch.check_loops()
  → Return findings + risk_score
```

### 3. Generating Compliance Report

```
User → /api/compliance/pci-dss
  → PCIComplianceEngine.generate_report()
  → PDFReportGenerator.generate_compliance_report()
  → Return report + PDF URL
```

### 4. Tracking Usage

```
API Call → UsageCounter.increment()
  → Acquire lock (thread-safe)
  → Redis-style INCR
  → Check against plan limits
  → Return usage status
```

## Security Features

### IDOR Protection
- `check_workspace_access()` middleware on all tRPC procedures
- Validates user has access to requested workspace
- Prevents unauthorized data access

### SSRF Protection
- IP validation in `ShadowAPIScanner`
- Blocks internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Blocks metadata service endpoints

### Atomic Operations
- Thread-safe usage counters with locks
- SQLAlchemy transaction wrappers
- Prevents race conditions

### Authentication
- JWT token-based auth
- Bearer token in Authorization header
- Token verification on protected endpoints

## Development Setup

### 1. Local Development

```bash
# Clone the repository
git clone <repo-url>
cd devpulse_production

# Install dependencies
pip install -r requirements.txt

# Start services
docker-compose up -d

# Run backend
uvicorn src.backend.main:app --reload

# Run frontend (in separate terminal)
cd src/frontend
npm install
npm start
```

### 2. Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src

# Run specific test file
pytest tests/test_auth.py -v
```

### 3. Using the CLI

```bash
# Login
devpulse login --api-url http://localhost:8000

# Import collection
devpulse import-collection collection.json

# Run scan
devpulse scan --collection-id col_abc123

# Generate compliance report
devpulse compliance --collection-id col_abc123
```

## Common Tasks

### Adding a New Endpoint

1. Define request/response models in `types.py`
2. Add endpoint function in `main.py` with `@app.get()` or `@app.post()`
3. Add security checks (IDOR, auth)
4. Add tests in `tests/`

### Adding a New Service

1. Create new file in `src/services/`
2. Implement service class with public methods
3. Import and use in `main.py`
4. Add tests

### Adding Frontend Page

1. Create component in `src/frontend/`
2. Add route in `App.tsx`
3. Add navigation item in `ResponsiveNav`
4. Style with Tailwind CSS

## Deployment

### Docker Deployment

```bash
# Build image
docker build -t devpulse:latest .

# Run container
docker run -p 8000:8000 \
  -e DATABASE_URL=postgresql://... \
  -e REDIS_URL=redis://... \
  devpulse:latest
```

### Kubernetes Deployment

```bash
# Apply manifests
kubectl apply -f k8s/

# Check status
kubectl get pods
kubectl logs <pod-name>
```

## Troubleshooting

### Database Connection Issues
- Check `DATABASE_URL` in `.env`
- Verify PostgreSQL is running: `docker-compose logs postgres`
- Run migrations: `alembic upgrade head`

### Redis Connection Issues
- Check `REDIS_URL` in `.env`
- Verify Redis is running: `docker-compose logs redis`
- Test connection: `redis-cli ping`

### API Not Responding
- Check backend logs: `docker-compose logs api`
- Verify port 8000 is not in use
- Check firewall settings

### Frontend Build Issues
- Clear node_modules: `rm -rf node_modules && npm install`
- Clear cache: `npm cache clean --force`
- Check Node version: `node --version` (should be 16+)

## Performance Optimization

### Database
- Use connection pooling (SQLAlchemy)
- Add indexes on frequently queried columns
- Use pagination for large result sets

### Caching
- Redis for session storage
- Cache security findings for 1 hour
- Cache compliance reports for 24 hours

### API
- Implement rate limiting
- Use compression (gzip)
- Implement pagination

## Contributing

1. Create feature branch: `git checkout -b feature/my-feature`
2. Make changes and add tests
3. Run tests: `pytest tests/ -v`
4. Format code: `black src/`
5. Lint: `flake8 src/`
6. Commit: `git commit -am "Add my feature"`
7. Push: `git push origin feature/my-feature`
8. Create Pull Request

## Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://react.dev/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Tailwind CSS Documentation](https://tailwindcss.com/)

## Support

For questions or issues:
1. Check existing issues on GitHub
2. Review documentation in `/docs`
3. Ask in team Slack channel
4. Create new GitHub issue with details

Happy coding! 🚀
