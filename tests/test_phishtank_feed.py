import unittest

from pathlib import Path

from phishtank_feed import (
    build_phishtank_index,
    load_phishtank_json,
    lookup_phishtank_index,
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


    def test_index_returns_exact_normalized_url_match(self):
        records = load_phishtank_json(FIXTURE_PATH)
        index = build_phishtank_index(records)

        matches = index.exact_url_matches(
            "https://login-alert.example.test/"
            "account?source=email#ignored-fragment"
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].phish_id, "300001")

    def test_index_returns_hostname_association(self):
        records = load_phishtank_json(FIXTURE_PATH)
        index = build_phishtank_index(records)

        matches = index.hostname_matches(
            "https://login-alert.example.test/"
            "a-different-path"
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].phish_id, "300001")

    def test_exact_url_no_match_does_not_claim_hostname_match(self):
        records = load_phishtank_json(FIXTURE_PATH)
        index = build_phishtank_index(records)

        exact_matches = index.exact_url_matches(
            "https://login-alert.example.test/"
            "a-different-path"
        )
        hostname_matches = index.hostname_matches(
            "https://login-alert.example.test/"
            "a-different-path"
        )

        self.assertEqual(exact_matches, ())
        self.assertEqual(len(hostname_matches), 1)


    def test_exact_match_becomes_verified_intelligence_finding(self):
        records = load_phishtank_json(FIXTURE_PATH)
        index = build_phishtank_index(records)

        findings = lookup_phishtank_index(
            index,
            (
                "https://login-alert.example.test/"
                "account?source=email#fragment"
            ),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "PhishTank")
        self.assertEqual(findings[0].status, "listed")
        self.assertEqual(findings[0].match_type, "exact_url")
        self.assertTrue(findings[0].verified)
        self.assertEqual(
            findings[0].classification,
            "phishing",
        )

    def test_hostname_association_is_not_labeled_exact_match(self):
        records = load_phishtank_json(FIXTURE_PATH)
        index = build_phishtank_index(records)

        findings = lookup_phishtank_index(
            index,
            (
                "https://login-alert.example.test/"
                "unlisted-path"
            ),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "listed")
        self.assertEqual(findings[0].match_type, "hostname")
        self.assertNotIn(
            "exactly matches",
            findings[0].detail,
        )
        self.assertIn(
            "not an exact match",
            findings[0].detail,
        )

    def test_no_match_explicitly_does_not_claim_safety(self):
        records = load_phishtank_json(FIXTURE_PATH)
        index = build_phishtank_index(records)

        findings = lookup_phishtank_index(
            index,
            "https://no-match.example.test/",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "not_found")
        self.assertEqual(findings[0].match_type, "none")
        self.assertFalse(findings[0].verified)
        self.assertIn(
            "does not mean",
            findings[0].detail,
        )
        self.assertIn(
            "safe",
            findings[0].detail,
        )

if __name__ == "__main__":
    unittest.main()
