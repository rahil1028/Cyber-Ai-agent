"""
CyberLens AI scan job management.

Provides a small, clean job model for tracking authorized
security assessment requests.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


SCAN_STATUSES = {
    "queued",
    "scanning",
    "completed",
    "failed",
}


@dataclass
class ScanJob:
    """Represents one security assessment job."""

    target_url: str
    profile: str = "passive"
    scan_id: str = field(
        default_factory=lambda: f"CL-{uuid4().hex[:10].upper()}"
    )
    status: str = "queued"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    findings_count: int = 0
    error: str | None = None

    def set_status(self, status: str) -> None:
        """Update the job status safely."""

        if status not in SCAN_STATUSES:
            raise ValueError(f"Invalid scan status: {status}")

        self.status = status

    def to_dict(self) -> dict:
        """Return a JSON-friendly representation of the job."""

        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "profile": self.profile,
            "status": self.status,
            "created_at": self.created_at,
            "findings_count": self.findings_count,
            "error": self.error,
        }
