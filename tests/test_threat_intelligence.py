import unittest
from datetime import datetime

from threat_intelligence import ThreatIntelligenceFinding


class ThreatIntelligenceFindingTests(unittest.TestCase):

    def test_verified_hostname_listing(self):
        finding = ThreatIntelligenceFinding(
            source="Test Phishing Feed",
            status="listed",
            classification="phishing",
            match_type="hostname",
            verified=True,
            detail="The hostname appeared in a verified phishing record.",
            source_timestamp="2026-09-28T12:00:00+00:00",
            reference="test-record-1001",
        )

        result = finding.to_dict()

        self.assertEqual(result["source"], "Test Phishing Feed")
        self.assertEqual(result["status"], "listed")
        self.assertEqual(result["classification"], "phishing")
        self.assertEqual(result["match_type"], "hostname")
        self.assertTrue(result["verified"])
        self.assertEqual(result["reference"], "test-record-1001")

    def test_not_found_result(self):
        finding = ThreatIntelligenceFinding(
            source="Test Phishing Feed",
            status="not_found",
            classification="none",
            match_type="none",
            verified=False,
            detail="No matching record was located.",
        )

        self.assertEqual(finding.status, "not_found")
        self.assertFalse(finding.verified)
        self.assertEqual(finding.match_type, "none")

    def test_lookup_timestamp_is_timezone_aware(self):
        finding = ThreatIntelligenceFinding(
            source="Test Phishing Feed",
            status="not_found",
            classification="none",
            match_type="none",
            verified=False,
            detail="No matching record was located.",
        )

        timestamp = datetime.fromisoformat(finding.lookup_timestamp)

        self.assertIsNotNone(timestamp.tzinfo)

    def test_empty_source_is_rejected(self):
        with self.assertRaises(ValueError):
            ThreatIntelligenceFinding(
                source="",
                status="listed",
                classification="phishing",
                match_type="hostname",
                verified=True,
                detail="Invalid test record.",
            )

    def test_unknown_status_is_rejected(self):
        with self.assertRaises(ValueError):
            ThreatIntelligenceFinding(
                source="Test Phishing Feed",
                status="confirmed_safe",
                classification="none",
                match_type="none",
                verified=False,
                detail="Invalid test record.",
            )

    def test_listed_finding_requires_a_match_type(self):
        with self.assertRaises(ValueError):
            ThreatIntelligenceFinding(
                source="Test Phishing Feed",
                status="listed",
                classification="phishing",
                match_type="none",
                verified=True,
                detail="Invalid test record.",
            )

    def test_nonlisted_finding_cannot_be_verified(self):
        with self.assertRaises(ValueError):
            ThreatIntelligenceFinding(
                source="Test Phishing Feed",
                status="not_found",
                classification="none",
                match_type="none",
                verified=True,
                detail="Invalid test record.",
            )


if __name__ == "__main__":
    unittest.main()
