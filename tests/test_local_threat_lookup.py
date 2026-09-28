import unittest
from pathlib import Path

from local_threat_lookup import (
    canonicalize_url,
    lookup_local_feed,
    normalize_intelligence_hostname,
)


class LocalThreatLookupNormalizationTests(unittest.TestCase):

    def test_hostname_is_lowercase_and_trailing_dot_is_removed(self):
        result = normalize_intelligence_hostname("Login.Example.TEST.")

        self.assertEqual(result, "login.example.test")

    def test_unicode_hostname_is_converted_to_punycode(self):
        result = normalize_intelligence_hostname("еxample.com")

        self.assertEqual(result, "xn--xample-2of.com")

    def test_url_credentials_and_fragment_are_removed(self):
        result = canonicalize_url(
            "HTTPS://user:password@Example.COM:443/"
            "account?case=123#section"
        )

        self.assertEqual(
            result,
            "https://example.com/account?case=123",
        )
        self.assertNotIn("user", result)
        self.assertNotIn("password", result)
        self.assertNotIn("section", result)

    def test_default_ports_are_removed(self):
        http_result = canonicalize_url(
            "http://example.com:80/login"
        )
        https_result = canonicalize_url(
            "https://example.com:443/login"
        )

        self.assertEqual(
            http_result,
            "http://example.com/login",
        )
        self.assertEqual(
            https_result,
            "https://example.com/login",
        )

    def test_nondefault_port_is_retained(self):
        result = canonicalize_url(
            "https://example.com:8443/login"
        )

        self.assertEqual(
            result,
            "https://example.com:8443/login",
        )

    def test_bare_domain_is_canonicalized_without_assuming_scheme(self):
        result = canonicalize_url("Example.COM")

        self.assertEqual(result, "//example.com/")

    def test_empty_input_is_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize_url("")

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize_url(
                "https://example.com:not-a-port/login"
            )

    def test_exact_url_match(self):
        findings = lookup_local_feed(
            "https://login-alert.example.test/account/verify"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "listed")
        self.assertEqual(findings[0].match_type, "exact_url")
        self.assertEqual(findings[0].classification, "phishing")
        self.assertTrue(findings[0].verified)
        self.assertEqual(
            findings[0].reference,
            "test-phish-1001",
        )

    def test_hostname_match_when_path_is_different(self):
        findings = lookup_local_feed(
            "https://login-alert.example.test/different-page"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "listed")
        self.assertEqual(findings[0].match_type, "hostname")
        self.assertEqual(findings[0].classification, "phishing")

    def test_bare_hostname_match(self):
        findings = lookup_local_feed(
            "login-alert.example.test"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "listed")
        self.assertEqual(findings[0].match_type, "hostname")

    def test_malware_classification_remains_separate(self):
        findings = lookup_local_feed(
            "https://download.example.test/payload"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "listed")
        self.assertEqual(
            findings[0].classification,
            "malware_distribution",
        )
        self.assertNotEqual(
            findings[0].classification,
            "phishing",
        )

    def test_no_match_does_not_claim_domain_is_safe(self):
        findings = lookup_local_feed(
            "https://clean.example.test/"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "not_found")
        self.assertEqual(findings[0].match_type, "none")
        self.assertFalse(findings[0].verified)
        self.assertIn(
            "does not establish",
            findings[0].detail,
        )

    def test_missing_feed_returns_unavailable(self):
        findings = lookup_local_feed(
            "example.com",
            Path("data/feed-that-does-not-exist.json"),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "unavailable")
        self.assertEqual(findings[0].match_type, "none")
        self.assertFalse(findings[0].verified)
        self.assertIn(
            "No conclusion should be drawn",
            findings[0].detail,
        )


if __name__ == "__main__":
    unittest.main()
