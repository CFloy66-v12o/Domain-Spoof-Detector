from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


ALLOWED_STATUSES = {
    "listed",
    "not_found",
    "unavailable",
    "user_reported",
}

ALLOWED_MATCH_TYPES = {
    "exact_url",
    "hostname",
    "none",
}


def utc_timestamp() -> str:
    """Return a timezone-aware UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ThreatIntelligenceFinding:
    """
    Represent one result from a threat-intelligence source.

    This structure records what an intelligence source reported. It does not
    independently determine that a domain, URL, sender, or person is malicious.
    """

    source: str
    status: str
    classification: str
    match_type: str
    verified: bool
    detail: str
    lookup_timestamp: str = field(default_factory=utc_timestamp)
    source_timestamp: str | None = None
    reference: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("Threat-intelligence source cannot be empty")

        if self.status not in ALLOWED_STATUSES:
            raise ValueError(
                f"Unsupported threat-intelligence status: {self.status}"
            )

        if self.match_type not in ALLOWED_MATCH_TYPES:
            raise ValueError(
                f"Unsupported threat-intelligence match type: "
                f"{self.match_type}"
            )

        if self.status == "listed" and self.match_type == "none":
            raise ValueError(
                "A listed finding must identify an exact URL or hostname match"
            )

        if self.status != "listed" and self.verified:
            raise ValueError(
                "Only a listed intelligence finding may be marked verified"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a template-friendly dictionary representation."""
        return asdict(self)
