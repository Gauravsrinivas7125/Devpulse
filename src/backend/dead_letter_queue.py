"""
DevPulse - Dead Letter Queue (DLQ)
Handle failed jobs with retry logic
"""

from typing import Any, Callable, Dict, List, Optional
from datetime import datetime, timedelta
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    """Job status"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"
    RETRYING = "retrying"


class Job:
    """Job in queue"""
    
    def __init__(
        self,
        job_id: str,
        job_type: str,
        payload: Dict[str, Any],
        max_retries: int = 3,
        timeout_seconds: int = 300
    ):
        self.job_id = job_id
        self.job_type = job_type
        self.payload = payload
        self.status = JobStatus.PENDING
        self.max_retries = max_retries
        self.retry_count = 0
        self.timeout_seconds = timeout_seconds
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None
        self.error_stack: Optional[str] = None
        self.next_retry_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict"""
        return {
            "job_id": self.job_id,
            "job_type": self.job_type,
            "payload": self.payload,
            "status": self.status.value,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "next_retry_at": self.next_retry_at.isoformat() if self.next_retry_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Job':
        """Deserialize from dict"""
        job = cls(
            job_id=data["job_id"],
            job_type=data["job_type"],
            payload=data["payload"],
            max_retries=data.get("max_retries", 3)
        )
        job.status = JobStatus(data.get("status", "pending"))
        job.retry_count = data.get("retry_count", 0)
        return job


class DeadLetterQueue:
    """Dead Letter Queue for failed jobs"""
    
    def __init__(self):
        self.jobs: Dict[str, Job] = {}  # job_id -> Job
        self.queue: List[str] = []  # job_ids in order
        self.dlq: List[str] = []  # dead letter job_ids
        self.handlers: Dict[str, Callable] = {}  # job_type -> handler
    
    def register_handler(self, job_type: str, handler: Callable):
        """Register handler for job type"""
        self.handlers[job_type] = handler
        logger.info(f"Registered handler for job type: {job_type}")
    
    def enqueue(self, job: Job):
        """Add job to queue"""
        self.jobs[job.job_id] = job
        self.queue.append(job.job_id)
        logger.info(f"Enqueued job {job.job_id} (type: {job.job_type})")
    
    def dequeue(self) -> Optional[Job]:
        """Get next job from queue (respects retry backoff with next_retry_at)"""
        if not self.queue:
            return None
        
        # SECURITY: Find next job that is ready to process
        # Only dequeue if:
        # 1. Job has no retry scheduled (next_retry_at is None), OR
        # 2. The current time >= next_retry_at (retry time has passed)
        now = datetime.utcnow()
        for i, job_id in enumerate(self.queue):
            job = self.jobs[job_id]
            
            # Check if job is ready to process
            if job.next_retry_at is None or job.next_retry_at <= now:
                self.queue.pop(i)
                job.status = JobStatus.PROCESSING
                job.started_at = datetime.utcnow()
                logger.info(f"Dequeued job {job_id}")
                return job
        
        # No jobs ready yet (all have future retry times)
        return None
    
    async def process_job(self, job: Job) -> bool:
        """
        Process job with retry logic
        
        Returns:
            True if successful, False if moved to DLQ
        """
        try:
            # Get handler
            handler = self.handlers.get(job.job_type)
            if not handler:
                raise ValueError(f"No handler for job type: {job.job_type}")
            
            # Execute handler
            logger.info(f"Processing job {job.job_id}")
            await handler(job.payload)
            
            # Mark as completed
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            logger.info(f"Job {job.job_id} completed successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Job {job.job_id} failed: {str(e)}")
            return await self._handle_failure(job, str(e))
    
    async def _handle_failure(self, job: Job, error_message: str) -> bool:
        """Handle job failure with retry logic"""
        job.error_message = error_message
        job.retry_count += 1
        
        # Check if should retry
        if job.retry_count <= job.max_retries:
            # Calculate exponential backoff
            backoff_seconds = 2 ** job.retry_count  # 2, 4, 8, 16, 32 seconds
            job.next_retry_at = datetime.utcnow() + timedelta(seconds=backoff_seconds)
            job.status = JobStatus.RETRYING
            
            # Re-enqueue for retry
            self.queue.append(job.job_id)
            logger.info(
                f"Job {job.job_id} will retry at {job.next_retry_at} "
                f"(attempt {job.retry_count}/{job.max_retries})"
            )
            
            return False
        
        else:
            # Move to DLQ
            job.status = JobStatus.DEAD_LETTER
            self.dlq.append(job.job_id)
            logger.error(
                f"Job {job.job_id} moved to DLQ after {job.retry_count} failed attempts"
            )
            
            return False
    
    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID"""
        return self.jobs.get(job_id)
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get queue status"""
        pending = sum(1 for jid in self.queue if self.jobs[jid].status == JobStatus.PENDING)
        processing = sum(1 for jid in self.queue if self.jobs[jid].status == JobStatus.PROCESSING)
        retrying = sum(1 for jid in self.queue if self.jobs[jid].status == JobStatus.RETRYING)
        
        return {
            "total_jobs": len(self.jobs),
            "queue_size": len(self.queue),
            "dlq_size": len(self.dlq),
            "pending": pending,
            "processing": processing,
            "retrying": retrying,
            "completed": sum(1 for j in self.jobs.values() if j.status == JobStatus.COMPLETED),
            "failed": sum(1 for j in self.jobs.values() if j.status == JobStatus.DEAD_LETTER),
        }
    
    def get_dlq_jobs(self) -> List[Dict[str, Any]]:
        """Get all dead letter jobs"""
        return [self.jobs[job_id].to_dict() for job_id in self.dlq]
    
    def retry_dlq_job(self, job_id: str) -> bool:
        """Retry a dead letter job"""
        if job_id not in self.dlq:
            return False
        
        job = self.jobs[job_id]
        job.retry_count = 0
        job.status = JobStatus.PENDING
        job.next_retry_at = None
        
        self.dlq.remove(job_id)
        self.queue.append(job_id)
        
        logger.info(f"Retrying DLQ job {job_id}")
        return True
    
    def purge_dlq(self):
        """Remove all dead letter jobs"""
        for job_id in self.dlq:
            del self.jobs[job_id]
        self.dlq.clear()
        logger.info("DLQ purged")


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    import asyncio
    
    # Create DLQ
    dlq = DeadLetterQueue()
    
    # Register handlers
    async def scan_handler(payload: Dict[str, Any]):
        """Handler for scan jobs"""
        collection_id = payload.get("collection_id")
        print(f"  Scanning collection {collection_id}...")
        
        # Simulate occasional failures
        import random
        if random.random() < 0.3:  # 30% failure rate
            raise Exception("Scan failed: timeout")
        
        print(f"  Scan completed for {collection_id}")
    
    async def report_handler(payload: Dict[str, Any]):
        """Handler for report jobs"""
        report_id = payload.get("report_id")
        print(f"  Generating report {report_id}...")
        print(f"  Report completed for {report_id}")
    
    dlq.register_handler("scan", scan_handler)
    dlq.register_handler("report", report_handler)
    
    # Create jobs
    print("Creating jobs...")
    for i in range(5):
        job = Job(
            job_id=f"job_{i}",
            job_type="scan",
            payload={"collection_id": f"col_{i}"}
        )
        dlq.enqueue(job)
    
    # Process jobs
    async def process_all():
        print("\nProcessing jobs...")
        while True:
            job = dlq.dequeue()
            if not job:
                break
            
            success = await dlq.process_job(job)
            print(f"  Job {job.job_id}: {'✓' if success else '✗'}")
    
    asyncio.run(process_all())
    
    # Show status
    print("\nQueue status:")
    status = dlq.get_queue_status()
    for key, value in status.items():
        print(f"  {key}: {value}")
    
    # Show DLQ jobs
    print("\nDead letter jobs:")
    dlq_jobs = dlq.get_dlq_jobs()
    for job_data in dlq_jobs:
        print(f"  {job_data['job_id']}: {job_data['error_message']}")
