import unittest

from pathlib import Path

from phishtank_feed import (
    load_phishtank_json,
    parse_phishtank_record,
)

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "phishtank_sample.json"
)


class PhishTankFeedTests(unittest.TestCase):
    def test_parses_verified_online_record(self):
        record = parse_phishtank_record(
            {
                "phish_id": 123456,
                "url": (
                    "https://login-alert.example.test/"
                    "account?source=email"
                ),
                "phish_detail_url": (
                    "https://phishtank.example.test/phish/123456"
                ),
                "submission_time": "2026-09-28T12:00:00+00:00",
                "verified": "yes",
                "verification_time": "2026-09-28T12:05:00+00:00",
                "online": "yes",
                "target": "Example Payment Service",
            }
        )

        self.assertIsNotNone(record)
        self.assertEqual(record.phish_id, "123456")
        self.assertEqual(
            record.hostname,
            "login-alert.example.test",
        )
        self.assertEqual(
            record.url,
            (
                "https://login-alert.example.test/"
                "account?source=email"
            ),
        )
        self.assertEqual(
            record.target,
            "Example Payment Service",
        )

    def test_ignores_record_that_is_not_verified(self):
        record = parse_phishtank_record(
            {
                "phish_id": "200001",
                "url": "https://unverified.example.test/",
                "verified": "no",
                "online": "yes",
            }
        )

        self.assertIsNone(record)

    def test_ignores_record_that_is_not_online(self):
        record = parse_phishtank_record(
            {
                "phish_id": "200002",
                "url": "https://offline.example.test/",
                "verified": "yes",
                "online": "no",
            }
        )

        self.assertIsNone(record)

    def test_rejects_active_record_with_missing_url(self):
        with self.assertRaisesRegex(
            ValueError,
            "missing its URL",
        ):
            parse_phishtank_record(
                {
                    "phish_id": "200003",
                    "url": "",
                    "verified": "yes",
                    "online": "yes",
                }
            )

    def test_removes_credentials_and_fragment_from_stored_url(self):
        record = parse_phishtank_record(
            {
                "phish_id": "200004",
                "url": (
                    "https://user:secret@login-alert.example.test/"
                    "private?token=value#account"
                ),
                "verified": "yes",
                "online": "yes",
            }
        )

        self.assertIsNotNone(record)
        self.assertEqual(
            record.url,
            (
                "https://login-alert.example.test/"
                "private?token=value"
            ),
        )
        self.assertNotIn("user:secret", record.url)
        self.assertNotIn("#account", record.url)


if __name__ == "__main__":
    unittest.main()
