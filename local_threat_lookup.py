from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


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
