"""
DevPulse Scan Session History Service
Inspired by Claude Code's SessionMemory patterns.
Per-scan context tracking, automatic scan notes/summaries,
and scan comparison (diff between scan runs).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import defaultdict
import threading
import hashlib


@dataclass
class ScanSession:
    session_id: str
    scan_id: str
    user_id: str
    collection_id: str
    collection_name: str
    started_at: str
    completed_at: Optional[str] = None
    status: str = "running"  # running, completed, failed
    risk_score: float = 0
    total_findings: int = 0
    findings: List[Dict] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    summary: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[int] = None


@dataclass
class ScanComparison:
    baseline_session_id: str
    compare_session_id: str
    risk_score_delta: float
    new_findings: List[Dict]
    resolved_findings: List[Dict]
    unchanged_findings: List[Dict]
    summary: str


class ScanSessionHistoryService:
    """
    Track scan sessions with context, notes, and comparison capabilities.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[str, ScanSession] = {}
        self._user_sessions: Dict[str, List[str]] = defaultdict(list)  # user_id -> session_ids

    # -----------------------------------------------------------------------
    # Session Lifecycle
    # -----------------------------------------------------------------------

    def start_session(
        self,
        scan_id: str,
        user_id: str,
        collection_id: str,
        collection_name: str,
        metadata: Optional[Dict] = None,
    ) -> ScanSession:
        """Start a new scan session."""
        with self._lock:
            session_id = f"ss_{scan_id}_{int(datetime.utcnow().timestamp())}"
            session = ScanSession(
                session_id=session_id,
                scan_id=scan_id,
                user_id=user_id,
                collection_id=collection_id,
                collection_name=collection_name,
                started_at=datetime.utcnow().isoformat(),
                metadata=metadata or {},
            )
            self._sessions[session_id] = session
            self._user_sessions[user_id].append(session_id)
            return session

    def complete_session(
        self,
        session_id: str,
        risk_score: float,
        findings: List[Dict],
        summary: Optional[str] = None,
    ) -> Optional[ScanSession]:
        """Mark a session as completed with results."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None

            session.status = "completed"
            session.completed_at = datetime.utcnow().isoformat()
            session.risk_score = risk_score
            session.total_findings = len(findings)
            session.findings = findings

            # Calculate duration
            started = datetime.fromisoformat(session.started_at)
            duration = datetime.utcnow() - started
            session.duration_ms = int(duration.total_seconds() * 1000)

            # Auto-generate summary if not provided
            if not summary:
                session.summary = self._generate_summary(session)
            else:
                session.summary = summary

            return session

    def fail_session(self, session_id: str, error: str) -> Optional[ScanSession]:
        """Mark a session as failed."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            session.status = "failed"
            session.completed_at = datetime.utcnow().isoformat()
            session.summary = f"Scan failed: {error}"
            session.metadata["error"] = error
            return session

    def add_note(self, session_id: str, note: str) -> bool:
        """Add a note to a scan session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            session.notes.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {note}")
            return True

    # -----------------------------------------------------------------------
    # Auto Summary Generation
    # -----------------------------------------------------------------------

    def _generate_summary(self, session: ScanSession) -> str:
        """Auto-generate a human-readable scan summary."""
        sev_counts: Dict[str, int] = defaultdict(int)
        categories: set = set()
        for f in session.findings:
            sev = f.get("severity", "INFO").upper()
            sev_counts[sev] += 1
            categories.add(f.get("category", "Unknown"))

        parts = [f"Scanned '{session.collection_name}' — Risk Score: {session.risk_score}/100"]

        if session.total_findings == 0:
            parts.append("No security findings detected.")
        else:
            finding_parts = []
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = sev_counts.get(sev, 0)
                if count > 0:
                    finding_parts.append(f"{count} {sev.lower()}")
            parts.append(f"Found {session.total_findings} issues: {', '.join(finding_parts)}.")

        if categories:
            parts.append(f"Categories: {', '.join(sorted(categories))}.")

        if session.duration_ms:
            duration_s = session.duration_ms / 1000
            parts.append(f"Completed in {duration_s:.1f}s.")

        return " ".join(parts)

    # -----------------------------------------------------------------------
    # Query & History
    # -----------------------------------------------------------------------

    def get_session(self, session_id: str, user_id: str) -> Optional[Dict]:
        """Get a single session (with ownership check)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session or session.user_id != user_id:
                return None
            return self._session_to_dict(session)

    def get_user_history(
        self,
        user_id: str,
        limit: int = 50,
        collection_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict]:
        """Get scan session history for a user."""
        with self._lock:
            session_ids = self._user_sessions.get(user_id, [])
            sessions = [self._sessions[sid] for sid in session_ids if sid in self._sessions]

            if collection_id:
                sessions = [s for s in sessions if s.collection_id == collection_id]
            if status:
                sessions = [s for s in sessions if s.status == status]

            # Sort by most recent first
            sessions.sort(key=lambda s: s.started_at, reverse=True)

            return [self._session_to_dict(s) for s in sessions[:limit]]

    def _session_to_dict(self, session: ScanSession) -> Dict:
        """Convert a session to a serializable dict."""
        return {
            "session_id": session.session_id,
            "scan_id": session.scan_id,
            "collection_id": session.collection_id,
            "collection_name": session.collection_name,
            "status": session.status,
            "risk_score": session.risk_score,
            "total_findings": session.total_findings,
            "findings": session.findings,
            "notes": session.notes,
            "summary": session.summary,
            "started_at": session.started_at,
            "completed_at": session.completed_at,
            "duration_ms": session.duration_ms,
            "metadata": session.metadata,
        }

    # -----------------------------------------------------------------------
    # Scan Comparison (Diff)
    # -----------------------------------------------------------------------

    def compare_sessions(
        self,
        baseline_session_id: str,
        compare_session_id: str,
        user_id: str,
    ) -> Optional[Dict]:
        """
        Compare two scan sessions to show what changed.
        Returns new findings, resolved findings, and risk score delta.
        """
        with self._lock:
            baseline = self._sessions.get(baseline_session_id)
            compare = self._sessions.get(compare_session_id)

            if not baseline or not compare:
                return None
            if baseline.user_id != user_id or compare.user_id != user_id:
                return None

            # Create fingerprints for findings
            baseline_fps = {self._finding_fingerprint(f): f for f in baseline.findings}
            compare_fps = {self._finding_fingerprint(f): f for f in compare.findings}

            baseline_keys = set(baseline_fps.keys())
            compare_keys = set(compare_fps.keys())

            new_keys = compare_keys - baseline_keys
            resolved_keys = baseline_keys - compare_keys
            unchanged_keys = baseline_keys & compare_keys

            risk_delta = compare.risk_score - baseline.risk_score
            direction = "improved" if risk_delta < 0 else "degraded" if risk_delta > 0 else "unchanged"

            summary_parts = [
                f"Risk score {direction}: {baseline.risk_score} → {compare.risk_score} ({risk_delta:+.1f})",
                f"{len(new_keys)} new finding(s)",
                f"{len(resolved_keys)} resolved finding(s)",
                f"{len(unchanged_keys)} unchanged finding(s)",
            ]

            return {
                "baseline": {
                    "session_id": baseline_session_id,
                    "risk_score": baseline.risk_score,
                    "total_findings": baseline.total_findings,
                    "scanned_at": baseline.started_at,
                },
                "compare": {
                    "session_id": compare_session_id,
                    "risk_score": compare.risk_score,
                    "total_findings": compare.total_findings,
                    "scanned_at": compare.started_at,
                },
                "risk_score_delta": risk_delta,
                "direction": direction,
                "new_findings": [compare_fps[k] for k in new_keys],
                "resolved_findings": [baseline_fps[k] for k in resolved_keys],
                "unchanged_findings_count": len(unchanged_keys),
                "summary": " | ".join(summary_parts),
            }

    def _finding_fingerprint(self, finding: Dict) -> str:
        """Create a stable fingerprint for a finding to enable diffing."""
        key_parts = [
            finding.get("title", ""),
            finding.get("category", ""),
            finding.get("severity", ""),
            str(sorted(finding.get("affected_endpoints", []))),
        ]
        raw = "|".join(key_parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # -----------------------------------------------------------------------
    # Statistics
    # -----------------------------------------------------------------------

    def get_user_stats(self, user_id: str) -> Dict:
        """Get overall scan statistics for a user."""
        with self._lock:
            session_ids = self._user_sessions.get(user_id, [])
            sessions = [self._sessions[sid] for sid in session_ids if sid in self._sessions]
            completed = [s for s in sessions if s.status == "completed"]

            if not completed:
                return {
                    "total_scans": 0,
                    "completed_scans": 0,
                    "failed_scans": len([s for s in sessions if s.status == "failed"]),
                    "avg_risk_score": 0,
                    "total_findings": 0,
                    "avg_scan_duration_ms": 0,
                }

            return {
                "total_scans": len(sessions),
                "completed_scans": len(completed),
                "failed_scans": len([s for s in sessions if s.status == "failed"]),
                "avg_risk_score": round(sum(s.risk_score for s in completed) / len(completed), 1),
                "total_findings": sum(s.total_findings for s in completed),
                "avg_scan_duration_ms": int(
                    sum(s.duration_ms or 0 for s in completed) / len(completed)
                ),
                "latest_risk_score": completed[0].risk_score if completed else 0,
                "risk_trend": self._calculate_trend(completed),
            }

    def _calculate_trend(self, sessions: List[ScanSession]) -> str:
        """Calculate risk trend direction from completed sessions."""
        if len(sessions) < 2:
            return "insufficient_data"
        recent = sorted(sessions, key=lambda s: s.started_at, reverse=True)
        latest = recent[0].risk_score
        previous = recent[1].risk_score
        if latest < previous:
            return "improving"
        if latest > previous:
            return "degrading"
        return "stable"


# Global instance
scan_session_history = ScanSessionHistoryService()
