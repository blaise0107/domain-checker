import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.normalize import (  # noqa: E402
    candidate_hosts, domain_matches, is_ip, normalize_domain, registrable_domain,
)


class NormalizeTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(normalize_domain("EXAMPLE.com"), "example.com")

    def test_url_with_port_and_path(self):
        self.assertEqual(normalize_domain("https://API.Example.com:443/path?q=1"), "api.example.com")

    def test_ip_and_port(self):
        self.assertEqual(normalize_domain("192.168.1.1:8080"), "192.168.1.1")
        self.assertTrue(is_ip("149.154.166.110"))

    def test_invalid(self):
        self.assertIsNone(normalize_domain("not a domain"))
        self.assertIsNone(normalize_domain("-bad.com"))
        self.assertIsNone(normalize_domain(""))

    def test_registrable(self):
        self.assertEqual(registrable_domain("api.mistral.ai"), "mistral.ai")
        self.assertEqual(registrable_domain("www.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(registrable_domain("149.154.166.110"), "149.154.166.110")

    def test_candidates_contains_parent_and_root(self):
        hosts = candidate_hosts("api.example.co.uk", "cursor.com")
        self.assertIn("api.example.co.uk", hosts)
        self.assertIn("example.co.uk", hosts)
        self.assertIn("www.example.co.uk", hosts)
        self.assertIn("cursor.com", hosts)

    def test_domain_matches_subdomains(self):
        self.assertTrue(domain_matches("mistral.ai", "api.mistral.ai"))
        self.assertFalse(domain_matches("mistral.ai", "notmistral.ai"))
        self.assertFalse(domain_matches("^dns.google", "www.dns.google"))


if __name__ == "__main__":
    unittest.main()
