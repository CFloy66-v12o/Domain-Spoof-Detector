import bz2
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phishtank_feed import load_phishtank_json
from update_phishtank_feed import (
    _validate_feed_url,
    update_local_feed,
)


VALID_FEED = b"""
[
  {
    "phish_id": 400001,
    "url": "https://feed-test.example.test/login",
    "phish_detail_url": "https://phishtank.example.test/phish/400001",
    "submission_time": "2026-09-28T13:00:00+00:00",
    "verified": "yes",
    "verification_time": "2026-09-28T13:05:00+00:00",
    "online": "yes",
    "target": "Example Service"
  }
]
"""


class PhishTankUpdaterTests(unittest.TestCase):
    def test_rejects_unapproved_feed_urls(self):
        rejected_urls = (
            "http://data.phishtank.com/data/feed.json.bz2",
            "https://example.test/data/feed.json.bz2",
            (
                "https://user:secret@data.phishtank.com/"
                "data/feed.json.bz2"
            ),
        )

        for url in rejected_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    _validate_feed_url(url)

    def test_valid_feed_atomically_replaces_destination(self):
        compressed_feed = bz2.compress(VALID_FEED)

        with tempfile.TemporaryDirectory() as temp_directory:
            destination = (
                Path(temp_directory)
                / "phishtank-online-valid.json"
            )
            destination.write_text(
                "old feed",
                encoding="utf-8",
            )

            with patch(
                "update_phishtank_feed.download_compressed_feed",
                return_value=compressed_feed,
            ):
                record_count = update_local_feed(destination)

            self.assertEqual(record_count, 1)

            records = load_phishtank_json(destination)
            self.assertEqual(len(records), 1)
            self.assertEqual(
                records[0].hostname,
                "feed-test.example.test",
            )

    def test_invalid_new_feed_preserves_existing_destination(self):
        empty_feed = bz2.compress(b"[]")

        with tempfile.TemporaryDirectory() as temp_directory:
            destination = (
                Path(temp_directory)
                / "phishtank-online-valid.json"
            )
            original_content = b"existing validated feed"
            destination.write_bytes(original_content)

            with patch(
                "update_phishtank_feed.download_compressed_feed",
                return_value=empty_feed,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "contains no active records",
                ):
                    update_local_feed(destination)

            self.assertEqual(
                destination.read_bytes(),
                original_content,
            )


if __name__ == "__main__":
    unittest.main()
