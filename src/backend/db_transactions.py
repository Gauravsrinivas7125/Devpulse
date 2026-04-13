"""
DevPulse - Database Transaction Wrappers
Atomic multi-table operations using Dizzle/SQLAlchemy
"""

from typing import Any, Callable, Dict, List, Optional
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, String, Integer, DateTime, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
import logging

logger = logging.getLogger(__name__)

Base = declarative_base()


# ============================================================================
# DATABASE MODELS
# ============================================================================

class Team(Base):
    """Team model"""
    __tablename__ = "teams"
    
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    owner_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    extra_metadata = Column(JSON, default={})  # renamed from 'metadata' (reserved by SQLAlchemy)


class UsageWindow(Base):
    """Usage window model"""
    __tablename__ = "usage_windows"
    
    id = Column(String, primary_key=True)
    team_id = Column(String, nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    requests_count = Column(Integer, default=0)
    api_calls_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class UsageLog(Base):
    """Usage log model"""
    __tablename__ = "usage_logs"
    
    id = Column(String, primary_key=True)
    team_id = Column(String, nullable=False)
    window_id = Column(String, nullable=False)
    metric = Column(String, nullable=False)
    amount = Column(Integer, default=1)
    timestamp = Column(DateTime, default=datetime.utcnow)
    extra_metadata = Column(JSON, default={})  # renamed from 'metadata' (reserved by SQLAlchemy)


# ============================================================================
# TRANSACTION WRAPPERS
# ============================================================================

class DatabaseTransaction:
    """Atomic database transaction wrapper"""
    
    def __init__(self, session: Session):
        self.session = session
        self.operations: List[Dict[str, Any]] = []
        self.committed = False
        self.failed = False
    
    def add_operation(self, operation_type: str, data: Dict[str, Any]):
        """Add operation to transaction"""
        self.operations.append({
            "type": operation_type,
            "data": data,
            "timestamp": datetime.utcnow()
        })
    
    def create_team(self, team_id: str, name: str, owner_id: str) -> Team:
        """Create team"""
        team = Team(id=team_id, name=name, owner_id=owner_id)
        self.session.add(team)
        self.add_operation("create_team", {"team_id": team_id, "name": name})
        return team
    
    def create_usage_window(
        self,
        window_id: str,
        team_id: str,
        period_start: datetime,
        period_end: datetime
    ) -> UsageWindow:
        """Create usage window"""
        window = UsageWindow(
            id=window_id,
            team_id=team_id,
            period_start=period_start,
            period_end=period_end
        )
        self.session.add(window)
        self.add_operation("create_usage_window", {"window_id": window_id, "team_id": team_id})
        return window
    
    def log_usage(
        self,
        log_id: str,
        team_id: str,
        window_id: str,
        metric: str,
        amount: int = 1
    ) -> UsageLog:
        """Log usage"""
        log = UsageLog(
            id=log_id,
            team_id=team_id,
            window_id=window_id,
            metric=metric,
            amount=amount
        )
        self.session.add(log)
        self.add_operation("log_usage", {"metric": metric, "amount": amount})
        return log
    
    def increment_usage_window(self, window_id: str, metric: str, amount: int = 1):
        """Increment usage in window"""
        window = self.session.query(UsageWindow).filter(UsageWindow.id == window_id).first()
        if window:
            if metric == "requests":
                window.requests_count += amount
            elif metric == "api_calls":
                window.api_calls_count += amount
            self.add_operation("increment_usage", {"window_id": window_id, "metric": metric})
    
    def commit(self) -> bool:
        """Commit transaction"""
        try:
            self.session.commit()
            self.committed = True
            logger.info(f"Transaction committed with {len(self.operations)} operations")
            return True
        except SQLAlchemyError as e:
            self.session.rollback()
            self.failed = True
            logger.error(f"Transaction failed: {str(e)}")
            return False
    
    def rollback(self):
        """Rollback transaction"""
        self.session.rollback()
        self.failed = True
        logger.info("Transaction rolled back")
    
    def get_status(self) -> Dict[str, Any]:
        """Get transaction status"""
        return {
            "operations": len(self.operations),
            "committed": self.committed,
            "failed": self.failed,
            "operations_list": self.operations
        }


class TransactionManager:
    """Manage database transactions"""
    
    def __init__(self, database_url: str = "sqlite:///:memory:"):
        self.engine = create_engine(database_url)
        self.SessionLocal = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
    
    def create_transaction(self) -> DatabaseTransaction:
        """Create new transaction"""
        session = self.SessionLocal()
        return DatabaseTransaction(session)
    
    def execute_transaction(self, callback: Callable[[DatabaseTransaction], Any]) -> bool:
        """
        Execute transaction with callback
        
        Args:
            callback: Function that takes transaction and performs operations
            
        Returns:
            True if successful, False otherwise
        """
        transaction = self.create_transaction()
        try:
            callback(transaction)
            return transaction.commit()
        except Exception as e:
            logger.error(f"Transaction execution failed: {str(e)}")
            transaction.rollback()
            return False
        finally:
            transaction.session.close()


# ============================================================================
# MULTI-TABLE OPERATIONS
# ============================================================================

class MultiTableOperations:
    """Multi-table atomic operations"""
    
    def __init__(self, transaction_manager: TransactionManager):
        self.tm = transaction_manager
    
    def create_team_with_usage_window(
        self,
        team_id: str,
        name: str,
        owner_id: str,
        window_id: str,
        period_start: datetime,
        period_end: datetime
    ) -> bool:
        """
        Create team and initialize usage window atomically
        
        If either operation fails, both are rolled back
        """
        def operation(tx: DatabaseTransaction):
            tx.create_team(team_id, name, owner_id)
            tx.create_usage_window(window_id, team_id, period_start, period_end)
        
        return self.tm.execute_transaction(operation)
    
    def log_and_increment_usage(
        self,
        log_id: str,
        team_id: str,
        window_id: str,
        metric: str,
        amount: int = 1
    ) -> bool:
        """
        Log usage and increment window atomically
        
        Both operations must succeed or both are rolled back
        """
        def operation(tx: DatabaseTransaction):
            tx.log_usage(log_id, team_id, window_id, metric, amount)
            tx.increment_usage_window(window_id, metric, amount)
        
        return self.tm.execute_transaction(operation)
    
    def batch_log_usage(
        self,
        team_id: str,
        window_id: str,
        logs: List[Dict[str, Any]]
    ) -> bool:
        """
        Log multiple usage entries atomically
        
        All logs must be created or none are created
        """
        def operation(tx: DatabaseTransaction):
            for log in logs:
                tx.log_usage(
                    log_id=log["id"],
                    team_id=team_id,
                    window_id=window_id,
                    metric=log["metric"],
                    amount=log.get("amount", 1)
                )
                tx.increment_usage_window(window_id, log["metric"], log.get("amount", 1))
        
        return self.tm.execute_transaction(operation)


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Create transaction manager
    tm = TransactionManager()
    ops = MultiTableOperations(tm)
    
    # Test 1: Create team with usage window
    print("Test 1: Create team with usage window")
    success = ops.create_team_with_usage_window(
        team_id="team_001",
        name="Acme Corp",
        owner_id="user_123",
        window_id="window_001",
        period_start=datetime.utcnow(),
        period_end=datetime.utcnow() + timedelta(days=30)
    )
    print(f"  Result: {'✓ Success' if success else '✗ Failed'}")
    
    # Test 2: Log and increment usage
    print("\nTest 2: Log and increment usage")
    success = ops.log_and_increment_usage(
        log_id="log_001",
        team_id="team_001",
        window_id="window_001",
        metric="requests",
        amount=5
    )
    print(f"  Result: {'✓ Success' if success else '✗ Failed'}")
    
    # Test 3: Batch log usage
    print("\nTest 3: Batch log usage")
    success = ops.batch_log_usage(
        team_id="team_001",
        window_id="window_001",
        logs=[
            {"id": "log_002", "metric": "requests", "amount": 10},
            {"id": "log_003", "metric": "api_calls", "amount": 50},
            {"id": "log_004", "metric": "requests", "amount": 5},
        ]
    )
    print(f"  Result: {'✓ Success' if success else '✗ Failed'}")
    
    print("\n✓ All transaction tests completed")
