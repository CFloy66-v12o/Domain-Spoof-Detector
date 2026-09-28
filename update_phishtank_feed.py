"""Safely retrieve and replace a local PhishTank JSON feed.

This updater contacts only the fixed PhishTank data host. It never contacts
URLs contained inside the downloaded feed.
"""

from __future__ import annotations

import bz2
import io
import os
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from phishtank_feed import load_phishtank_json


PHISHTANK_FEED_URL = (
    "https://data.phishtank.com/data/online-valid.json.bz2"
)
ALLOWED_FEED_HOST = "data.phishtank.com"
DEFAULT_DESTINATION = Path("data/phishtank-online-valid.json")
MAX_COMPRESSED_BYTES = 25_000_000
MAX_DECOMPRESSED_BYTES = 100_000_000
DOWNLOAD_TIMEOUT_SECONDS = 30
USER_AGENT = (
    "FrederickDataForensics-DomainChecker/1.0 "
    "(https://frederickdataforensics.net)"
)


def _validate_feed_url(url: str) -> None:
    """Allow HTTPS retrieval only from the fixed PhishTank data host."""

    parsed = urlsplit(url)

    if parsed.scheme != "https":
        raise ValueError("PhishTank feed URL must use HTTPS")

    if parsed.hostname != ALLOWED_FEED_HOST:
        raise ValueError(
            "PhishTank feed URL uses an unapproved host"
        )

    if parsed.username or parsed.password:
        raise ValueError(
            "PhishTank feed URL must not contain credentials"
        )


class RestrictedRedirectHandler(HTTPRedirectHandler):
    """Reject redirects away from the approved HTTPS feed host."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        _validate_feed_url(newurl)
        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl,
        )


def download_compressed_feed(
    url: str = PHISHTANK_FEED_URL,
) -> bytes:
    """Download a bounded compressed feed from the approved host."""

    _validate_feed_url(url)

    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/octet-stream",
        },
        method="GET",
    )
    opener = build_opener(RestrictedRedirectHandler())

    try:
        with opener.open(
            request,
            timeout=DOWNLOAD_TIMEOUT_SECONDS,
        ) as response:
            _validate_feed_url(response.geturl())

            content_length = response.headers.get(
                "Content-Length"
            )
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError as exc:
                    raise ValueError(
                        "Feed response has an invalid Content-Length"
                    ) from exc

                if declared_size > MAX_COMPRESSED_BYTES:
                    raise ValueError(
                        "Compressed feed exceeds the size limit"
                    )

            payload = response.read(
                MAX_COMPRESSED_BYTES + 1
            )
    except (HTTPError, URLError, TimeoutError) as exc:
        raise ValueError(
            "PhishTank feed download failed"
        ) from exc

    if len(payload) > MAX_COMPRESSED_BYTES:
        raise ValueError(
            "Compressed feed exceeds the size limit"
        )

    if not payload:
        raise ValueError("Downloaded PhishTank feed is empty")

    return payload


def decompress_feed(payload: bytes) -> bytes:
    """Decompress a bounded BZ2 payload and reject decompression bombs."""

    try:
        with bz2.open(io.BytesIO(payload), "rb") as archive:
            decompressed = archive.read(
                MAX_DECOMPRESSED_BYTES + 1
            )
    except (OSError, EOFError) as exc:
        raise ValueError(
            "Downloaded PhishTank feed is not valid BZ2 data"
        ) from exc

    if len(decompressed) > MAX_DECOMPRESSED_BYTES:
        raise ValueError(
            "Decompressed feed exceeds the size limit"
        )

    if not decompressed:
        raise ValueError(
            "Decompressed PhishTank feed is empty"
        )

    return decompressed


def update_local_feed(
    destination: str | Path = DEFAULT_DESTINATION,
) -> int:
    """Download, validate, and atomically replace the local feed."""

    destination_path = Path(destination)
    destination_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    compressed = download_compressed_feed()
    decompressed = decompress_feed(compressed)

    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination_path.parent,
            prefix=".phishtank-",
            suffix=".json.tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(decompressed)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)

        temporary_path.chmod(0o600)

        records = load_phishtank_json(
            temporary_path,
            max_bytes=MAX_DECOMPRESSED_BYTES,
        )

        if not records:
            raise ValueError(
                "Validated PhishTank feed contains no active records"
            )

        os.replace(
            temporary_path,
            destination_path,
        )
        temporary_path = None

        return len(records)
    finally:
        if (
            temporary_path is not None
            and temporary_path.exists()
        ):
            temporary_path.unlink()


def main() -> None:
    """Run one controlled feed update."""

    record_count = update_local_feed()
    print(
        "PhishTank feed updated successfully: "
        f"{record_count} active records"
    )


if __name__ == "__main__":
    main()
