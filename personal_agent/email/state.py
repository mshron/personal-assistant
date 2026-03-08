"""Subscription state persistence backed by a JSON file."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class SenderRecord:
    """Tracks a single sender's subscription state."""

    sender: str
    status: str  # "active" | "unsubscribed" | "pending" | "skipped"
    email_count: int
    first_seen: str  # ISO date
    last_seen: str  # ISO date
    unsubscribe_method: str | None = None
    unsubscribe_detail: str | None = None
    provider: str = ""  # Which email provider this sender was found via
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.updated_at:
            self.updated_at = _now_iso()


@dataclass
class ScanRecord:
    """Records a completed scan of a date range."""

    after: str  # ISO date
    before: str  # ISO date
    scanned_at: str  # ISO datetime
    candidates_found: int


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_iso() -> str:
    return date.today().isoformat()


_DEFAULT_PATH = Path(
    os.environ.get("EMAIL_SUBSCRIPTIONS_FILE", "/data/email_subscriptions.json")
)


@dataclass
class _State:
    """Internal container for the full persisted state."""

    senders: dict[str, dict[str, Any]] = field(default_factory=dict)
    scans: list[dict[str, Any]] = field(default_factory=list)


class SubscriptionStore:
    """Manages subscription state in a JSON file.

    Parameters
    ----------
    path:
        Location of the JSON state file.  Defaults to the value of the
        ``EMAIL_SUBSCRIPTIONS_FILE`` environment variable, falling back
        to ``/data/email_subscriptions.json``.
    """

    def __init__(self, path: Path = _DEFAULT_PATH) -> None:
        self._path = path
        self._state = _State()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load state from disk.  Creates empty state if the file is missing."""
        if not self._path.exists():
            self._state = _State()
            return
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        self._state = _State(
            senders=raw.get("senders", {}),
            scans=raw.get("scans", []),
        )

    def save(self) -> None:
        """Atomically write state to disk (creates parent dirs if needed)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(
            {"senders": self._state.senders, "scans": self._state.scans},
            indent=2,
            sort_keys=True,
        )
        # Atomic write: write to a temp file in the same directory, then rename.
        fd, tmp = tempfile.mkstemp(
            dir=str(self._path.parent), suffix=".tmp"
        )
        try:
            os.write(fd, data.encode("utf-8"))
            os.fsync(fd)
            os.close(fd)
            os.replace(tmp, str(self._path))
        except BaseException:
            os.close(fd) if not _fd_closed(fd) else None
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # ------------------------------------------------------------------
    # Sender helpers
    # ------------------------------------------------------------------

    def get_sender(self, sender: str) -> SenderRecord | None:
        """Return a SenderRecord for *sender*, or ``None`` if unknown."""
        raw = self._state.senders.get(sender)
        if raw is None:
            return None
        return SenderRecord(**raw)

    def upsert_sender(self, sender: str, **kwargs: Any) -> SenderRecord:
        """Create or update a sender record.  Auto-saves after mutation."""
        now = _now_iso()
        existing = self._state.senders.get(sender)
        if existing is None:
            record: dict[str, Any] = {
                "sender": sender,
                "status": kwargs.get("status", "active"),
                "email_count": kwargs.get("email_count", 0),
                "first_seen": kwargs.get("first_seen", _today_iso()),
                "last_seen": kwargs.get("last_seen", _today_iso()),
                "unsubscribe_method": kwargs.get("unsubscribe_method"),
                "unsubscribe_detail": kwargs.get("unsubscribe_detail"),
                "provider": kwargs.get("provider", ""),
                "updated_at": now,
            }
        else:
            record = {**existing, **kwargs, "sender": sender, "updated_at": now}
        self._state.senders[sender] = record
        self.save()
        return SenderRecord(**record)

    def list_senders(self, status: str | None = None) -> list[SenderRecord]:
        """Return sender records, optionally filtered by *status*."""
        results: list[SenderRecord] = []
        for raw in self._state.senders.values():
            if status is not None and raw.get("status") != status:
                continue
            results.append(SenderRecord(**raw))
        return results

    # ------------------------------------------------------------------
    # Scan helpers
    # ------------------------------------------------------------------

    def add_scan(self, after: date, before: date, candidates_found: int) -> None:
        """Record a completed scan of a date range.  Auto-saves."""
        self._state.scans.append(
            {
                "after": after.isoformat(),
                "before": before.isoformat(),
                "scanned_at": _now_iso(),
                "candidates_found": candidates_found,
            }
        )
        self.save()

    def get_scans(self) -> list[ScanRecord]:
        """Return the full scan history."""
        return [ScanRecord(**s) for s in self._state.scans]

    def is_scanned(self, after: date, before: date) -> bool:
        """Return ``True`` if the exact date range has already been scanned."""
        a_str = after.isoformat()
        b_str = before.isoformat()
        return any(
            s["after"] == a_str and s["before"] == b_str for s in self._state.scans
        )


def _fd_closed(fd: int) -> bool:
    """Check whether a file descriptor is already closed."""
    try:
        os.fstat(fd)
        return False
    except OSError:
        return True
