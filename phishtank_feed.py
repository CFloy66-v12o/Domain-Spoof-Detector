"""Offline parsing and normalization for PhishTank feed records.

This module does not download data, resolve hostnames, visit URLs, or make
network connections. Network retrieval, if later approved, will remain a
separate component.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping

from local_threat_lookup import (
    canonicalize_url,
    extract_intelligence_hostname,
)


@dataclass(frozen=True)
class PhishTankRecord:
    """A validated, normalized record imported from a PhishTank data file."""

    phish_id: str
    url: str
    hostname: str
    detail_url: str
    submission_time: str
    verification_time: str
    target: str


def _clean_text(value: object) -> str:
    """Return a stripped string for supported scalar feed values."""

    if isinstance(value, (str, int)):
        return str(value).strip()

    return ""


def parse_phishtank_record(
    raw_record: Mapping[str, object],
) -> PhishTankRecord | None:
    """Validate and normalize one record without contacting its URL.

    Records that are not both verified and currently online are ignored.
    Malformed active records raise ValueError so callers can treat the feed
    import as incomplete rather than silently trusting damaged data.
    """

    verified = _clean_text(raw_record.get("verified")).casefold()
    online = _clean_text(raw_record.get("online")).casefold()

    if verified != "yes" or online != "yes":
        return None

    phish_id = _clean_text(raw_record.get("phish_id"))
    submitted_url = _clean_text(raw_record.get("url"))

    if not phish_id:
        raise ValueError("PhishTank record is missing phish_id")

    if not submitted_url:
        raise ValueError(
            f"PhishTank record {phish_id} is missing its URL"
        )

    try:
        normalized_url = canonicalize_url(submitted_url)
        hostname = extract_intelligence_hostname(submitted_url)
    except (UnicodeError, ValueError) as exc:
        raise ValueError(
            f"PhishTank record {phish_id} contains an invalid URL"
        ) from exc

    return PhishTankRecord(
        phish_id=phish_id,
        url=normalized_url,
        hostname=hostname,
        detail_url=_clean_text(
            raw_record.get("phish_detail_url")
        ),
        submission_time=_clean_text(
            raw_record.get("submission_time")
        ),
        verification_time=_clean_text(
            raw_record.get("verification_time")
        ),
        target=_clean_text(raw_record.get("target")),
    )
