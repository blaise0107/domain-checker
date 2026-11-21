import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.decision import Verdict  # noqa: E402
from src.core.knowledge import DomainEntry, Pitfall  # noqa: E402
from src.ui.detail_dialogs import evidence_as_text, knowledge_as_text, pitfalls_as_text  # noqa: E402


def make_verdict():
    return Verdict(
        domain="example.com", candidates=["example.com"], level="SNI",
        title="t", summary="s", confidence="высокая",
        evidence=[("BlockCheck: example.com", "blocked=true", "bad"),
                  ("DNS A: example.com", "1.2.3.4", "ok")],
        warnings=["⚠️ WARP обесценивает тесты"],
        pitfalls=[Pitfall("warp", ("*",), "WARP", "Подробности про WARP")],
    )


class DetailDialogTests(unittest.TestCase):
    def test_evidence_as_text(self):
        text = evidence_as_text(make_verdict())
        self.assertIn("BlockCheck: example.com", text)
        self.assertIn("❌ проблема", text)
        self.assertIn("✅ хорошо", text)

    def test_pitfalls_as_text(self):
        text = pitfalls_as_text(make_verdict())
        self.assertIn("WARP обесценивает тесты", text)
        self.assertIn("Подробности про WARP", text)

    def test_empty_pitfalls(self):
        v = make_verdict()
        v.warnings = []
        v.pitfalls = []
        self.assertIn("Нет специальных предупреждений", pitfalls_as_text(v))

    def test_knowledge_as_text(self):
        v = make_verdict()
        v.knowledge = [DomainEntry("chatgpt.com", "DNS", "Только DNS-правило", "Геоблок OpenAI")]
        text = knowledge_as_text(v)
        self.assertIn("chatgpt.com", text)
        self.assertIn("Геоблок OpenAI", text)

    def test_knowledge_empty(self):
        self.assertIn("не найден", knowledge_as_text(make_verdict()))


if __name__ == "__main__":
    unittest.main()
