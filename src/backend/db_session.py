"""
DevPulse - Database Session Integration
Provides database-backed storage that falls back to in-memory for quick start.
Wire this into main.py to replace raw dicts with persistent storage.
"""

import os
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

# Determine if we should use the database
USE_DATABASE = os.getenv("USE_DATABASE", "true").lower() == "true"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./devpulse.db")

if USE_DATABASE:
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker, Session
        from sqlalchemy.pool import StaticPool
        from .models import Base, User, Collection, Scan, Finding, TeamMember, TokenUsage, AuditLog

        if "sqlite" in DATABASE_URL:
            engine = create_engine(
                DATABASE_URL,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        else:
            engine = create_engine(
                DATABASE_URL,
                echo=os.getenv("SQL_ECHO", "false").lower() == "true",
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20,
            )

        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        def init_db():
            """Create all tables"""
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables created successfully")

        def get_db():
            """Get a database session (FastAPI dependency)"""
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        DB_AVAILABLE = True
        logger.info(f"Database configured: {DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL}")

    except Exception as e:
        logger.warning(f"Database not available, using in-memory storage: {e}")
        DB_AVAILABLE = False
else:
    DB_AVAILABLE = False
    logger.info("Database disabled via USE_DATABASE=false, using in-memory storage")


class StorageBackend:
    """
    Unified storage backend that supports both in-memory and database storage.
    Falls back to in-memory dicts when database is not available.
    """

    def __init__(self):
        self.use_db = USE_DATABASE and DB_AVAILABLE
        # In-memory fallback
        self._users: Dict[str, Dict] = {}
        self._collections: Dict[str, Dict] = {}
        self._scans: Dict[str, Dict] = {}
        self._findings: Dict[str, Dict] = {}
        self._workspaces: Dict[str, Dict] = {}
        self._audit_log: List[Dict] = []

        if self.use_db:
            try:
                init_db()
                logger.info("Using database storage backend")
            except Exception as e:
                logger.warning(f"Failed to init DB, falling back to in-memory: {e}")
                self.use_db = False

    # --- User operations ---

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        if self.use_db:
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.email == email).first()
                if user:
                    return {
                        "id": user.id,
                        "email": user.email,
                        "name": user.name,
                        "password": user.password_hash,
                        "plan": user.plan,
                        "stripe_customer_id": user.stripe_customer_id,
                        "created_at": user.created_at.isoformat() if user.created_at else None,
                    }
                return None
            finally:
                db.close()
        return self._users.get(email)

    def create_user(self, email: str, password_hash: str, name: str = "") -> Dict:
        user_id = str(uuid.uuid4())
        if self.use_db:
            db = SessionLocal()
            try:
                user = User(
                    id=user_id,
                    email=email,
                    name=name or email.split("@")[0],
                    password_hash=password_hash,
                    plan="free",
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                return {
                    "id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "password": user.password_hash,
                    "plan": user.plan,
                    "stripe_customer_id": user.stripe_customer_id,
                    "created_at": user.created_at.isoformat(),
                }
            finally:
                db.close()
        else:
            user_data = {
                "id": user_id,
                "email": email,
                "name": name or email.split("@")[0],
                "password": password_hash,
                "plan": "free",
                "stripe_customer_id": None,
                "created_at": datetime.utcnow().isoformat(),
            }
            self._users[email] = user_data
            return user_data

    def user_exists(self, email: str) -> bool:
        return self.get_user_by_email(email) is not None

    def update_user(self, email: str, updates: Dict) -> None:
        if self.use_db:
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.email == email).first()
                if user:
                    for key, value in updates.items():
                        if key == "password":
                            setattr(user, "password_hash", value)
                        elif hasattr(user, key):
                            setattr(user, key, value)
                    db.commit()
            finally:
                db.close()
        elif email in self._users:
            self._users[email].update(updates)

    # --- Collection operations ---

    def create_collection(self, collection_id: str, owner_id: str, data: Dict) -> Dict:
        if self.use_db:
            db = SessionLocal()
            try:
                collection = Collection(
                    id=collection_id,
                    user_id=owner_id,
                    name=data.get("name", "Imported Collection"),
                    format=data.get("format", "unknown"),
                    total_requests=data.get("total_requests", 0),
                    data=data,
                )
                db.add(collection)
                db.commit()
                return {
                    "id": collection_id,
                    "owner_id": owner_id,
                    "name": data.get("name", "Imported Collection"),
                    "format": data.get("format", "unknown"),
                    "requests": data.get("requests", []),
                    "total_requests": data.get("total_requests", 0),
                    "created_at": datetime.utcnow().isoformat(),
                }
            finally:
                db.close()
        else:
            record = {
                "id": collection_id,
                "owner_id": owner_id,
                **data,
                "created_at": datetime.utcnow().isoformat(),
            }
            self._collections[collection_id] = record
            return record

    def get_collection(self, collection_id: str) -> Optional[Dict]:
        if self.use_db:
            db = SessionLocal()
            try:
                c = db.query(Collection).filter(Collection.id == collection_id).first()
                if c:
                    return {
                        "id": c.id,
                        "owner_id": c.user_id,
                        "name": c.name,
                        "format": c.format,
                        "requests": c.data.get("requests", []) if c.data else [],
                        "total_requests": c.total_requests,
                        "created_at": c.created_at.isoformat() if c.created_at else None,
                    }
                return None
            finally:
                db.close()
        return self._collections.get(collection_id)

    def list_collections(self, owner_id: str) -> List[Dict]:
        if self.use_db:
            db = SessionLocal()
            try:
                cols = db.query(Collection).filter(Collection.user_id == owner_id).all()
                return [
                    {
                        "id": c.id,
                        "owner_id": c.user_id,
                        "name": c.name,
                        "format": c.format,
                        "total_requests": c.total_requests,
                        "created_at": c.created_at.isoformat() if c.created_at else None,
                    }
                    for c in cols
                ]
            finally:
                db.close()
        return [c for c in self._collections.values() if c.get("owner_id") == owner_id]

    def delete_collection(self, collection_id: str) -> bool:
        if self.use_db:
            db = SessionLocal()
            try:
                c = db.query(Collection).filter(Collection.id == collection_id).first()
                if c:
                    db.delete(c)
                    db.commit()
                    return True
                return False
            finally:
                db.close()
        return self._collections.pop(collection_id, None) is not None

    # --- Scan / Findings operations ---

    def store_scan(self, scan_id: str, user_id: str, scan_data: Dict) -> None:
        if self.use_db:
            db = SessionLocal()
            try:
                scan = Scan(
                    id=scan_id,
                    user_id=user_id,
                    collection_id=scan_data.get("collection_id", ""),
                    risk_score=scan_data.get("risk_score", 0),
                    risk_level=scan_data.get("risk_level", "LOW"),
                    total_findings=len(scan_data.get("findings", [])),
                    findings_data=scan_data.get("findings", []),
                )
                db.add(scan)
                db.commit()
            finally:
                db.close()
        else:
            self._findings[scan_id] = {
                "id": scan_id,
                "user_id": user_id,
                **scan_data,
            }

    def get_findings_for_user(self, user_id: str) -> List[Dict]:
        if self.use_db:
            db = SessionLocal()
            try:
                scans = db.query(Scan).filter(Scan.user_id == user_id).all()
                all_findings = []
                for s in scans:
                    if s.findings_data:
                        all_findings.extend(s.findings_data)
                return all_findings
            finally:
                db.close()
        all_findings = []
        for scan in self._findings.values():
            if scan.get("user_id") == user_id:
                all_findings.extend(scan.get("findings", []))
        return all_findings

    # --- Audit log ---

    def add_audit_entry(self, user_id: str, action: str, details: Dict = None) -> None:
        entry = {
            "user_id": user_id,
            "action": action,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat(),
        }
        if self.use_db:
            db = SessionLocal()
            try:
                log = AuditLog(
                    user_id=user_id,
                    action=action,
                    resource_type=details.get("resource_type", "system") if details else "system",
                    resource_id=details.get("resource_id") if details else None,
                    details=details,
                )
                db.add(log)
                db.commit()
            finally:
                db.close()
        else:
            self._audit_log.append(entry)

    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        if self.use_db:
            db = SessionLocal()
            try:
                logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
                return [
                    {
                        "user_id": l.user_id,
                        "action": l.action,
                        "resource_type": l.resource_type,
                        "details": l.details,
                        "timestamp": l.created_at.isoformat() if l.created_at else None,
                    }
                    for l in logs
                ]
            finally:
                db.close()
        return self._audit_log[-limit:]

    @property
    def users_db(self) -> Dict:
        """Compatibility: return in-memory users dict for legacy code"""
        return self._users

    @property
    def collections_db(self) -> Dict:
        """Compatibility: return in-memory collections dict for legacy code"""
        return self._collections

    @property
    def findings_db(self) -> Dict:
        """Compatibility: return in-memory findings dict for legacy code"""
        return self._findings

    @property
    def workspaces_db(self) -> Dict:
        """Compatibility: return in-memory workspaces dict for legacy code"""
        return self._workspaces

    @property
    def scans_db(self) -> Dict:
        """Compatibility: return in-memory scans dict for legacy code"""
        return self._scans


# Singleton storage backend
storage = StorageBackend()
