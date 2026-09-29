"""Offline parsing and normalization for PhishTank feed records.

This module does not download data, resolve hostnames, visit URLs, or make
network connections. Network retrieval, if later approved, will remain a
separate component.
"""

from __future__ import annotations
import json
from pathlib import Path
from dataclasses import dataclass
from collections.abc import Mapping
from types import MappingProxyType
from local_threat_lookup import (
    canonicalize_url,
    extract_intelligence_hostname,
)
from threat_intelligence import ThreatIntelligenceFinding

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


def load_phishtank_json(
    feed_path: str | Path,
    *,
    max_bytes: int = 100_000_000,
) -> tuple[PhishTankRecord, ...]:
    """Load a bounded local JSON feed without making network connections.

    The complete import fails if the file is oversized, malformed, or
    contains an invalid active record. This prevents a damaged partial feed
    from silently replacing a previously valid local data set.
    """

    if max_bytes <= 0:
        raise ValueError("max_bytes must be greater than zero")

    path = Path(feed_path)

    try:
        with path.open("rb") as feed_file:
            payload = feed_file.read(max_bytes + 1)
    except OSError as exc:
        raise ValueError(
            f"PhishTank feed could not be read: {path}"
        ) from exc

    if len(payload) > max_bytes:
        raise ValueError(
            f"PhishTank feed exceeds the {max_bytes}-byte limit"
        )

    try:
        raw_feed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("PhishTank feed is not valid JSON") from exc

    if not isinstance(raw_feed, list):
        raise ValueError(
            "PhishTank feed must contain a top-level JSON array"
        )

    records: list[PhishTankRecord] = []

    for position, raw_record in enumerate(raw_feed):
        if not isinstance(raw_record, Mapping):
            raise ValueError(
                "PhishTank feed entry "
                f"{position} is not a JSON object"
            )

        try:
            record = parse_phishtank_record(raw_record)
        except ValueError as exc:
            raise ValueError(
                "Invalid active PhishTank feed entry "
                f"at position {position}: {exc}"
            ) from exc

        if record is not None:
            records.append(record)

    return tuple(records)


@dataclass(frozen=True)
class PhishTankIndex:
    """Immutable local indexes for exact-URL and hostname lookups."""

    by_url: Mapping[str, tuple[PhishTankRecord, ...]]
    by_hostname: Mapping[str, tuple[PhishTankRecord, ...]]

    def exact_url_matches(
        self,
        submitted_value: str,
    ) -> tuple[PhishTankRecord, ...]:
        """Return records matching the normalized submitted URL."""

        normalized_url = canonicalize_url(submitted_value)
        return self.by_url.get(normalized_url, ())

    def hostname_matches(
        self,
        submitted_value: str,
    ) -> tuple[PhishTankRecord, ...]:
        """Return records associated with the submitted hostname."""

        hostname = extract_intelligence_hostname(submitted_value)
        return self.by_hostname.get(hostname, ())


def build_phishtank_index(
    records: tuple[PhishTankRecord, ...],
) -> PhishTankIndex:
    """Build immutable local indexes without resolving or visiting URLs."""

    url_entries: dict[str, list[PhishTankRecord]] = {}
    hostname_entries: dict[str, list[PhishTankRecord]] = {}
    seen_ids: set[str] = set()

    for record in records:
        if record.phish_id in seen_ids:
            raise ValueError(
                f"Duplicate PhishTank ID: {record.phish_id}"
            )

        seen_ids.add(record.phish_id)

        url_entries.setdefault(record.url, []).append(record)
        hostname_entries.setdefault(
            record.hostname,
            [],
        ).append(record)

    immutable_urls = MappingProxyType(
        {
            key: tuple(value)
            for key, value in url_entries.items()
        }
    )
    immutable_hostnames = MappingProxyType(
        {
            key: tuple(value)
            for key, value in hostname_entries.items()
        }
    )

    return PhishTankIndex(
        by_url=immutable_urls,
        by_hostname=immutable_hostnames,
    )


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
        source_timestamp=record.verification_time or None,
        reference=record.detail_url or None,
    )


def lookup_phishtank_index(
    index: PhishTankIndex,
    submitted_value: str,
) -> tuple[ThreatIntelligenceFinding, ...]:
    """Check a submitted value against a loaded local index."""

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
