from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from threat_intelligence import ThreatIntelligenceFinding

DEFAULT_FEED_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "fabricated_threat_feed.json"
)


def normalize_intelligence_hostname(hostname: str) -> str:
    """
    Normalize a hostname for intelligence-feed comparison.

    Unicode labels are converted to their ASCII/Punycode representation so
    visually equivalent Unicode and Punycode submissions can use one index.
    """
    normalized_labels = []

    for label in hostname.rstrip(".").split("."):
        if not label:
            raise ValueError("Hostname contains an empty label")

        try:
            normalized_label = label.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Hostname contains an invalid IDN label") from exc

        normalized_labels.append(normalized_label.casefold())

    return ".".join(normalized_labels)


def canonicalize_url(value: str) -> str:
    """
    Canonicalize a URL for exact local-feed comparison without connecting
    to the destination.

    Embedded credentials and fragments are excluded. The query string is
    retained because it may be significant to an exact intelligence match.
    """
    candidate = value.strip()

    if not candidate:
        raise ValueError("Input is empty")

    has_explicit_scheme = "://" in candidate
    parsed = urlsplit(
        candidate if has_explicit_scheme else f"//{candidate}"
    )

    if not parsed.hostname:
        raise ValueError("Could not extract hostname")

    hostname = normalize_intelligence_hostname(parsed.hostname)

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc

    host_and_port = hostname

    if port is not None:
        default_port = (
            parsed.scheme.casefold() == "http" and port == 80
        ) or (
            parsed.scheme.casefold() == "https" and port == 443
        )

        if not default_port:
            host_and_port = f"{hostname}:{port}"

    path = parsed.path or "/"
    scheme = parsed.scheme.casefold() if has_explicit_scheme else ""

    if not scheme:
        return urlunsplit(
            ("", host_and_port, path, parsed.query, "")
        )

    return urlunsplit(
        (scheme, host_and_port, path, parsed.query, "")
    )


def extract_intelligence_hostname(value: str) -> str:
    """Extract and normalize a hostname without making a network request."""
    candidate = value.strip()

    if not candidate:
        raise ValueError("Input is empty")

    parsed = urlsplit(
        candidate if "://" in candidate else f"//{candidate}"
    )

    if not parsed.hostname:
        raise ValueError("Could not extract hostname")

    return normalize_intelligence_hostname(parsed.hostname)


def load_local_feed(feed_path: Path = DEFAULT_FEED_PATH) -> dict:
    """Load and minimally validate a local JSON intelligence feed."""
    with feed_path.open("r", encoding="utf-8") as feed_file:
        feed = json.load(feed_file)

    if (
        not isinstance(feed.get("source"), str)
        or not feed["source"].strip()
    ):
        raise ValueError("Feed source is missing or invalid")

    if not isinstance(feed.get("records"), list):
        raise ValueError("Feed records are missing or invalid")

    return feed


def lookup_local_feed(
    value: str,
    feed_path: Path = DEFAULT_FEED_PATH,
) -> list[ThreatIntelligenceFinding]:
    """
    Compare untrusted input with a local intelligence feed.

    The function performs string parsing and local file reads only. It does
    not resolve or connect to the submitted destination.
    """
    submitted_hostname = extract_intelligence_hostname(value)
    submitted_canonical_url = canonicalize_url(value)
    submitted_has_scheme = "://" in value.strip()

    try:
        feed = load_local_feed(feed_path)
        source = feed["source"]
        findings = []

        for record in feed["records"]:
            if not isinstance(record, dict):
                raise ValueError("Feed contains an invalid record")

            record_url = record.get("url")
            classification = record.get("classification")

            if (
                not isinstance(record_url, str)
                or not record_url.strip()
            ):
                raise ValueError(
                    "Feed record URL is missing or invalid"
                )

            if (
                not isinstance(classification, str)
                or not classification.strip()
            ):
                raise ValueError(
                    "Feed record classification is missing or invalid"
                )

            record_hostname = extract_intelligence_hostname(
                record_url
            )

            if submitted_hostname != record_hostname:
                continue

            exact_match = (
                submitted_has_scheme
                and submitted_canonical_url
                == canonicalize_url(record_url)
            )

            match_type = (
                "exact_url" if exact_match else "hostname"
            )

            detail = (
                "The submitted URL exactly matches a local "
                "intelligence record."
                if exact_match
                else (
                    "The submitted hostname appears in one or more "
                    "URLs in the local intelligence feed."
                )
            )

            findings.append(
                ThreatIntelligenceFinding(
                    source=source,
                    status="listed",
                    classification=classification,
                    match_type=match_type,
                    verified=bool(
                        record.get("verified", False)
                    ),
                    detail=detail,
                    source_timestamp=record.get(
                        "source_timestamp"
                    ),
                    reference=record.get("reference"),
                )
            )

        if findings:
            return findings

        return [
            ThreatIntelligenceFinding(
                source=source,
                status="not_found",
                classification="none",
                match_type="none",
                verified=False,
                detail=(
                    "No matching record was located in the local "
                    "intelligence feed. This does not establish "
                    "that the domain or URL is safe."
                ),
                source_timestamp=feed.get("generated_at"),
            )
        ]

    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        return [
            ThreatIntelligenceFinding(
                source="Local threat intelligence feed",
                status="unavailable",
                classification="unknown",
                match_type="none",
                verified=False,
                detail=(
                    "The local intelligence source could not be "
                    "checked. No conclusion should be drawn from "
                    "the missing lookup."
                ),
                reference=type(exc).__name__,
            )
        ]
