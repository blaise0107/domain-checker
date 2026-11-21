import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.decision import Verdict  # noqa: E402
from src.ui.hints import action_note, normalize_mode, verdict_text  # noqa: E402


def make_verdict(level="SNI", raw=None):
    return Verdict(
        domain="example.com", candidates=["example.com"], level=level,
        title="t", summary="s", confidence="высокая", raw=raw or {},
    )


class HintTests(unittest.TestCase):
    def test_normalize_mode(self):
        self.assertEqual(normalize_mode("pro"), "pro")
        self.assertEqual(normalize_mode("bogus"), "novice")
        self.assertEqual(normalize_mode(None), "novice")

    def test_novice_keeps_original_note(self):
        v = make_verdict()
        note = action_note("ВАЖНО:-domен уже в списке", v, "novice", has_commands=True)
        self.assertIn("ВАЖНО:-domен уже в списке", note)
        self.assertIn("1. Нажмите", note)

    def test_novice_shows_list_status(self):
        v = make_verdict("DNS", raw={"lists": {"status": "conflict", "message": "КОНФЛИКТ в списках"}})
        _, _, summary = verdict_text(v, "novice")
        self.assertIn("КОНФЛИКТ в списках", summary)

    def test_ok_exclude_message_is_rewritten(self):
        v = make_verdict("OK", raw={"lists": {"status": "wrong_exclude", "message": "уберите оттуда"}})
        _, _, summary = verdict_text(v, "novice")
        self.assertIn("это правильно", summary)

    def test_pro_handles_null_matches(self):
        v = make_verdict("SNI", raw={
            "lists": {"ok": True, "matches": None},
            "dnsserver": {"matches": None},
        })
        _, _, summary = verdict_text(v, "pro")
        self.assertIn("lists_ok", summary)


if __name__ == "__main__":
    unittest.main()
