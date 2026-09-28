import unittest

from local_threat_lookup import (
    canonicalize_url,
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


if __name__ == "__main__":
    unittest.main()
