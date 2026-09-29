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


def _record_to_finding(
    record: PhishTankRecord,
    *,
    match_type: str,
) -> ThreatIntelligenceFinding:
    """Convert one local feed record into a shared result object."""

    if match_type == "exact_url":
        detail = (
            "The normalized submitted URL exactly matches a verified, "
            "online PhishTank feed record."
        )
    elif match_type == "hostname":
        detail = (
            "The submitted hostname is associated with at least one "
            "verified, online PhishTank URL. This is not an exact match "
            "for the submitted URL."
        )
    else:
        raise ValueError(
            f"Unsupported PhishTank match type: {match_type}"
        )

    if record.target:
        detail += f" Reported impersonation target: {record.target}."

    return ThreatIntelligenceFinding(
        source="PhishTank",
        status="listed",
        classification="phishing",
        match_type=match_type,
        verified=True,
        detail=detail,
        source_timestamp=(
            record.verification_time or None
        ),
        reference=record.detail_url or None,
    )


def lookup_phishtank_index(
    index: PhishTankIndex,
    submitted_value: str,
) -> tuple[ThreatIntelligenceFinding, ...]:
    """Check a submitted value against a previously loaded local index."""

    exact_matches = index.exact_url_matches(submitted_value)

    if exact_matches:
        return tuple(
            _record_to_finding(
                record,
                match_type="exact_url",
            )
            for record in exact_matches
        )

    hostname_matches = index.hostname_matches(submitted_value)

    if hostname_matches:
        return tuple(
            _record_to_finding(
                record,
                match_type="hostname",
            )
            for record in hostname_matches
        )

    return (
        ThreatIntelligenceFinding(
            source="PhishTank",
            status="not_found",
            classification="phishing",
            match_type="none",
            verified=False,
            detail=(
                "No match was found in the loaded PhishTank feed. "
                "This does not mean the submitted URL or hostname is safe."
            ),
        ),
    )
