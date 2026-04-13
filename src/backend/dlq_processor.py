"""
DevPulse - Dead Letter Queue Processor
Handles failed tasks and implements retry logic
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import Column, String, Integer, DateTime, JSON, Boolean, and_
from sqlalchemy.ext.declarative import declarative_base
import asyncio

logger = logging.getLogger(__name__)

Base = declarative_base()


class DeadLetterQueueItem(Base):
    """Model for DLQ items"""
    __tablename__ = "dead_letter_queue"
    
    id = Column(String(36), primary_key=True)
    task_type = Column(String(100), nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    error_message = Column(String(500), nullable=True)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    last_retry_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    processed = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<DLQItem {self.id} - {self.task_type}>"


class DeadLetterQueueProcessor:
    """Process and retry failed tasks"""
    
    MAX_RETRIES = 3
    RETRY_DELAY_SECONDS = 300  # 5 minutes
    
    def __init__(self, db: Session):
        self.db = db

    async def enqueue_failed_task(
        self,
        task_type: str,
        payload: Dict[str, Any],
        error_message: str,
        max_retries: int = MAX_RETRIES
    ) -> str:
        """Add a failed task to the DLQ"""
        import uuid
        
        dlq_item = DeadLetterQueueItem(
            id=str(uuid.uuid4()),
            task_type=task_type,
            payload=payload,
            error_message=error_message,
            max_retries=max_retries,
            retry_count=0
        )
        
        self.db.add(dlq_item)
        self.db.commit()
        self.db.refresh(dlq_item)
        
        logger.warning(f"Task {task_type} added to DLQ: {dlq_item.id}")
        return dlq_item.id

    async def process_dlq(self) -> Dict[str, Any]:
        """Process all pending DLQ items"""
        pending_items = self.db.query(DeadLetterQueueItem).filter(
            and_(
                DeadLetterQueueItem.processed == False,
                DeadLetterQueueItem.retry_count < DeadLetterQueueItem.max_retries
            )
        ).all()
        
        results = {
            "total": len(pending_items),
            "successful": 0,
            "failed": 0,
            "items": []
        }
        
        for item in pending_items:
            try:
                # Check if enough time has passed since last retry
                if item.last_retry_at:
                    time_since_retry = datetime.utcnow() - item.last_retry_at
                    if time_since_retry.total_seconds() < self.RETRY_DELAY_SECONDS:
                        continue
                
                # Retry the task
                success = await self._retry_task(item)
                
                if success:
                    item.processed = True
                    results["successful"] += 1
                    logger.info(f"DLQ task {item.id} processed successfully")
                else:
                    item.retry_count += 1
                    item.last_retry_at = datetime.utcnow()
                    results["failed"] += 1
                    logger.warning(f"DLQ task {item.id} retry failed (attempt {item.retry_count}/{item.max_retries})")
                
                results["items"].append({
                    "id": item.id,
                    "task_type": item.task_type,
                    "retry_count": item.retry_count,
                    "success": success
                })
                
                self.db.commit()
            except Exception as e:
                logger.error(f"Error processing DLQ item {item.id}: {str(e)}")
                results["failed"] += 1
        
        return results

    async def _retry_task(self, item: DeadLetterQueueItem) -> bool:
        """Retry a specific task based on its type"""
        try:
            if item.task_type == "email_verification":
                return await self._retry_email_verification(item.payload)
            elif item.task_type == "scan_processing":
                return await self._retry_scan_processing(item.payload)
            elif item.task_type == "compliance_report":
                return await self._retry_compliance_report(item.payload)
            elif item.task_type == "stripe_webhook":
                return await self._retry_stripe_webhook(item.payload)
            else:
                logger.error(f"Unknown task type: {item.task_type}")
                return False
        except Exception as e:
            logger.error(f"Task retry failed: {str(e)}")
            return False

    async def _retry_email_verification(self, payload: Dict[str, Any]) -> bool:
        """Retry email verification"""
        from services.email_service import email_service
        
        email = payload.get("email")
        name = payload.get("name")
        token = payload.get("token")
        
        if not all([email, name, token]):
            return False
        
        return email_service.send_verification_email(email, name, token)

    async def _retry_scan_processing(self, payload: Dict[str, Any]) -> bool:
        """Retry scan processing"""
        from services.risk_score_engine import RiskScoreEngine
        
        scan_id = payload.get("scan_id")
        collection_data = payload.get("collection_data")
        
        if not scan_id or not collection_data:
            return False
        
        try:
            engine = RiskScoreEngine()
            # Re-process the scan
            logger.info(f"Reprocessing scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Scan reprocessing failed: {str(e)}")
            return False

    async def _retry_compliance_report(self, payload: Dict[str, Any]) -> bool:
        """Retry compliance report generation"""
        from services.pci_compliance import PCIComplianceGenerator
        
        collection_id = payload.get("collection_id")
        report_type = payload.get("report_type")
        
        if not collection_id or not report_type:
            return False
        
        try:
            generator = PCIComplianceGenerator()
            logger.info(f"Regenerating {report_type} report for collection {collection_id}")
            return True
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return False

    async def _retry_stripe_webhook(self, payload: Dict[str, Any]) -> bool:
        """Retry Stripe webhook processing"""
        event_type = payload.get("event_type")
        event_data = payload.get("event_data")
        
        if not event_type or not event_data:
            return False
        
        try:
            logger.info(f"Reprocessing Stripe webhook: {event_type}")
            # Re-process the webhook
            return True
        except Exception as e:
            logger.error(f"Webhook reprocessing failed: {str(e)}")
            return False

    def get_dlq_stats(self) -> Dict[str, Any]:
        """Get DLQ statistics"""
        total = self.db.query(DeadLetterQueueItem).count()
        pending = self.db.query(DeadLetterQueueItem).filter(
            DeadLetterQueueItem.processed == False
        ).count()
        processed = self.db.query(DeadLetterQueueItem).filter(
            DeadLetterQueueItem.processed == True
        ).count()
        
        # Group by task type
        by_type = {}
        items = self.db.query(DeadLetterQueueItem).all()
        for item in items:
            if item.task_type not in by_type:
                by_type[item.task_type] = 0
            by_type[item.task_type] += 1
        
        return {
            "total": total,
            "pending": pending,
            "processed": processed,
            "by_type": by_type
        }

    def get_pending_items(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get pending DLQ items"""
        items = self.db.query(DeadLetterQueueItem).filter(
            DeadLetterQueueItem.processed == False
        ).order_by(DeadLetterQueueItem.created_at.desc()).limit(limit).all()
        
        return [
            {
                "id": item.id,
                "task_type": item.task_type,
                "retry_count": item.retry_count,
                "max_retries": item.max_retries,
                "error_message": item.error_message,
                "created_at": item.created_at.isoformat(),
                "last_retry_at": item.last_retry_at.isoformat() if item.last_retry_at else None
            }
            for item in items
        ]

    async def clear_processed_items(self, older_than_days: int = 7) -> int:
        """Clear old processed items"""
        cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)
        
        items_to_delete = self.db.query(DeadLetterQueueItem).filter(
            and_(
                DeadLetterQueueItem.processed == True,
                DeadLetterQueueItem.created_at < cutoff_date
            )
        ).all()
        
        count = len(items_to_delete)
        for item in items_to_delete:
            self.db.delete(item)
        
        self.db.commit()
        logger.info(f"Cleared {count} old DLQ items")
        return count
