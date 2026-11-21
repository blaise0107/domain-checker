import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.router import classify_list_status  # noqa: E402


def place(short, line="mistral.ai", doh_only=False):
    return {"short": short, "line": line, "host": "mistral.ai", "doh_only": doh_only}


class ListConflictTests(unittest.TestCase):
    def test_none(self):
        r = classify_list_status([])
        self.assertEqual(r["status"], "none")

    def test_ok_general(self):
        r = classify_list_status([place("list_general")])
        self.assertEqual(r["status"], "ok")

    def test_conflict_include_and_exclude(self):
        r = classify_list_status([
            place("list_general"),
            place("list_exclude"),
        ])
        self.assertEqual(r["status"], "conflict")
        self.assertIn("удалите оттуда", r["message"])

    def test_wrong_exclude(self):
        r = classify_list_status([place("list_exclude_user", "^mistral.ai", doh_only=True)])
        self.assertEqual(r["status"], "wrong_exclude")

    def test_wrong_google(self):
        r = classify_list_status([place("list_google")])
        self.assertEqual(r["status"], "wrong_google")

    def test_wrong_doh(self):
        r = classify_list_status([place("list_general_user", "^dns.google", doh_only=True)])
        self.assertEqual(r["status"], "wrong_doh")

    def test_doh_in_user_list_does_not_turn_ok(self):
        # ^-запись в list_general_user — это не обычный SNI-обход
        r = classify_list_status([place("list_general_user", "^dns.google", doh_only=True)])
        self.assertEqual(r["status"], "wrong_doh")


if __name__ == "__main__":
    unittest.main()
