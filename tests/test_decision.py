import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config import Config  # noqa: E402
from src.core.decision import analyze  # noqa: E402
from src.core.knowledge import Knowledge  # noqa: E402


def base_data(**overrides):
    data = {
        "panel_ok": True,
        "panel_message": "панель отвечает",
        "hosts": ["example.com", "www.example.com"],
        "redirect_target": None,
        "blockcheck": {"ok": True, "error": None, "targets": {
            "example.com": {"blocked": False, "verdict": "ok", "code": 200, "ttfb_ms": 40, "connect_ms": 10}}},
        "dns": {"example.com": {"ok": True, "ips": ["1.1.1.1"]}},
        "ip_addresses": ["1.1.1.1"],
        "connections": {"ok": True, "items": []},
        "lists": {"ok": True, "contents": {}, "matches": []},
        "dnsserver": {"ok": True, "error": None, "rules_count": 0, "matches": []},
        "tunnel": {"ok": True, "error": None, "lines": [], "matches": []},
    }
    data.update(overrides)
    return data


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.knowledge = Knowledge()
        self.cfg = Config()

    def test_ok_when_not_blocked(self):
        v = analyze("example.com", base_data(), self.knowledge, self.cfg)
        self.assertEqual(v.level, "OK")
        self.assertTrue(any(a.kind == "none" for a in v.actions))

    def test_sni_when_blocked_with_tls_timeout(self):
        data = base_data(blockcheck={"ok": True, "targets": {
            "example.com": {"blocked": True, "verdict": "timeout", "code": None, "ttfb_ms": 0, "connect_ms": 12}}})
        v = analyze("example.com", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "SNI")
        self.assertTrue(any(a.kind == "nfqws2" for a in v.actions))

    def test_ip_when_conntrack_proves_syn_drop(self):
        data = base_data(
            blockcheck={"ok": True, "targets": {
                "example.com": {"blocked": True, "verdict": "timeout", "code": None, "ttfb_ms": 0, "connect_ms": 0}}},
            connections={"ok": True, "items": [{"dst": "1.1.1.1", "dport": "443", "state": "SYN_SENT",
                                                "unreplied": True, "reply_bytes": 0}]},
        )
        v = analyze("example.com", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "IP")
        self.assertTrue(any(a.kind == "tunnel" for a in v.actions))

    def test_knowledge_override_for_telegram(self):
        data = base_data(hosts=["api.telegram.org"],
                         blockcheck={"ok": True, "targets": {
                             "api.telegram.org": {"blocked": False, "verdict": "ok", "ttfb_ms": 20}}},
                         dns={"api.telegram.org": {"ok": True, "ips": ["149.154.166.110"]}},
                         ip_addresses=["149.154.166.110"])
        v = analyze("api.telegram.org", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "IP")
        self.assertTrue(v.knowledge)

    def test_panel_down_falls_back_to_knowledge(self):
        data = base_data(panel_ok=False, panel_message="недоступна", hosts=["mistral.ai"])
        v = analyze("mistral.ai", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "SNI")  # вердикт из базы знаний при недоступной панели
        self.assertEqual(v.confidence, "низкая")
        self.assertTrue(any("недоступна" in w for w in v.warnings))

    def test_chatgpt_dns_relay_not_ip(self):
        """BlockCheck без блока + SYN_SENT на IP DNS-релея — это НЕ блок провайдера."""
        data = base_data(
            hosts=["chatgpt.com", "www.chatgpt.com"],
            blockcheck={"ok": True, "targets": {
                "chatgpt.com": {"blocked": False, "verdict": "ok", "code": 200, "ttfb_ms": 3636}}},
            dns={"chatgpt.com": {"ok": True, "ips": ["206.223.242.221"],
                                 "upstream": "https://sync.bezmezhau.com/dns-query"}},
            ip_addresses=["206.223.242.221"],
            connections={"ok": True, "items": [
                {"dst": "206.223.250.253", "dport": "443", "state": "SYN_SENT",
                 "unreplied": True, "reply_bytes": 0}]},
            dnsserver={"ok": True, "rules_count": 96, "matches": [
                {"host": "chatgpt.com", "rule": {"domain": "chatgpt.com"}}]},
        )
        v = analyze("chatgpt.com", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "DNS")
        self.assertFalse(any(a.kind in {"tunnel", "client"} for a in v.actions))
        self.assertTrue(any("VPN-туннель не нужен" in w for w in v.warnings))

    def test_nonexistent_domain_is_nxdomain(self):
        """'no such host' от BlockCheck — это NXDOMAIN, а не подмена DNS."""
        data = base_data(
            hosts=["www.1tvrrr.ru"],
            blockcheck={"ok": True, "targets": {
                "www.1tvrrr.ru": {"blocked": True, "verdict": "dns", "code": 0,
                                  "err": 'Get "https://www.1tvrrr.ru/": dial tcp4: '
                                         'lookup www.1tvrrr.ru on 8.8.8.8:53: no such host'}}},
            dns={"www.1tvrrr.ru": {"ok": True, "ips": [], "route": "nfqws"}},
            ip_addresses=[],
        )
        v = analyze("www.1tvrrr.ru", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "NXDOMAIN")
        self.assertFalse(any(a.kind in {"dns", "nfqws2", "tunnel"} for a in v.actions))
        self.assertTrue(any("опечат" in w for w in v.warnings))

    def test_ozon_redirect_loop_not_block(self):
        """'stopped after 10 redirects' у Ozon — ошибка BlockCheck, не блок провайдера."""
        data = base_data(
            hosts=["ozon.ru", "www.ozon.ru"],
            blockcheck={"ok": True, "targets": {
                "ozon.ru": {"blocked": True, "verdict": "error", "code": 0,
                            "err": 'Get "https://ozon.ru/?__rr=1": stopped after 10 redirects'}}},
            dns={"ozon.ru": {"ok": True, "ips": ["185.73.193.68"]}},
            ip_addresses=["185.73.193.68"],
        )
        v = analyze("ozon.ru", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "OK")
        self.assertTrue(any(a.kind == "none" for a in v.actions))
        self.assertTrue(any("циклического редиректа" in w for w in v.warnings))

    def test_forum_is_not_nxdomain(self):
        """'no such host' через 1.1.1.1, но DNS роутера дал IP — не NXDOMAIN."""
        data = base_data(
            hosts=["forum.ru-board.com", "www.forum.ru-board.com", "ru-board.com"],
            blockcheck={"ok": True, "targets": {
                "forum.ru-board.com": {"blocked": True, "verdict": "dns", "code": 0,
                                       "err": 'lookup forum.ru-board.com on 1.1.1.1:53: no such host'},
                "ru-board.com": {"blocked": False, "verdict": "ok", "code": 200}}},
            dns={"forum.ru-board.com": {"ok": True, "ips": ["94.156.128.52"]}},
            ip_addresses=["94.156.128.52"],
            lists={"ok": True, "contents": {}, "matches": [
                {"file": "/opt/etc/nfqws2/lists/list-general.list",
                 "line": "forum.ru-board.com", "host": "forum.ru-board.com", "short": "list_general"}]},
        )
        v = analyze("forum.ru-board.com", data, self.knowledge, self.cfg)
        self.assertNotEqual(v.level, "NXDOMAIN")
        self.assertEqual(v.level, "DNS")
        self.assertFalse(any(a.kind == "info" and "не существует" in a.title for a in v.actions))
        self.assertTrue(any("домен существует" in w for w in v.warnings))

    def test_no_foreign_blockcheck_fallback(self):
        """Результат BlockCheck другого кандидата не должен определять вердикт основного домена."""
        data = base_data(
            hosts=["example.com", "www.example.com"],
            blockcheck={"ok": True, "targets": {
                "www.example.com": {"blocked": True, "verdict": "timeout", "ttfb_ms": 0}}},
        )
        v = analyze("example.com", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "OK")

    def test_ip_proof_uses_only_target_host_ips(self):
        """SYN_SENT на IP другого кандидата не должен давать IP-вердикт целевому хосту."""
        data = base_data(
            hosts=["example.com", "www.example.com"],
            blockcheck={"ok": True, "targets": {
                "example.com": {"blocked": True, "verdict": "timeout", "ttfb_ms": 0, "connect_ms": 12}}},
            dns={"example.com": {"ok": True, "ips": ["1.1.1.1"]},
                 "www.example.com": {"ok": True, "ips": ["9.9.9.9"]}},
            ip_addresses=["1.1.1.1", "9.9.9.9"],
            connections={"ok": True, "items": [
                {"dst": "9.9.9.9", "dport": "443", "state": "SYN_SENT",
                 "unreplied": True, "reply_bytes": 0}]},
        )
        v = analyze("example.com", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "SNI")  # не IP: proof относится к www

    def test_known_level_no_foreign_inheritance(self):
        """Без точного совпадения в базе знаний не наследуем чужой вердикт."""
        from src.core.decision import _known_level
        entries = self.knowledge.lookup(["api.telegram.org"])
        self.assertIsNone(_known_level(entries, "unknown.example.com"))

    def test_dns_of_other_candidate_not_used(self):
        """DNS/IP другого кандидата не должен давать доказательства целевому хосту."""
        data = base_data(
            hosts=["example.com", "www.example.com"],
            blockcheck={"ok": True, "targets": {
                "example.com": {"blocked": True, "verdict": "timeout", "ttfb_ms": 0, "connect_ms": 12}}},
            dns={"www.example.com": {"ok": True, "ips": ["9.9.9.9"]}},
            ip_addresses=["9.9.9.9"],
            connections={"ok": True, "items": [
                {"dst": "9.9.9.9", "dport": "443", "state": "SYN_SENT",
                 "unreplied": True, "reply_bytes": 0}]},
        )
        v = analyze("example.com", data, self.knowledge, self.cfg)
        self.assertEqual(v.level, "SNI")

    def test_foreign_avo_route_not_marked_existing(self):
        """Маршрут другого домена в VPN-туннель не значит, что целевой адрес уже добавлен."""
        data = base_data(
            hosts=["example.com", "www.example.com"],
            blockcheck={"ok": True, "targets": {
                "example.com": {"blocked": True, "verdict": "timeout", "ttfb_ms": 0,
                                "connect_ms": 0}}},
            dns={"example.com": {"ok": True, "ips": ["1.1.1.1"]}},
            ip_addresses=["1.1.1.1"],
            connections={"ok": True, "items": [
                {"dst": "1.1.1.1", "dport": "443", "state": "SYN_SENT",
                 "unreplied": True, "reply_bytes": 0}]},
            tunnel={"ok": True, "lines": ["9.9.9.9:443"], "matches": [
                {"line": "9.9.9.9:443", "target": "www.example.com"}]},
        )
        v = analyze("example.com", data, self.knowledge, self.cfg)
        action = next(a for a in v.actions if a.kind == "tunnel")
        self.assertNotIn("уже есть", action.note)

    def test_report_contains_actions(self):
        data = base_data(blockcheck={"ok": True, "targets": {
            "example.com": {"blocked": True, "verdict": "timeout", "ttfb_ms": 0, "connect_ms": 12}}})
        v = analyze("example.com", data, self.knowledge, self.cfg)
        from src.core.report import build_markdown
        md = build_markdown(v)
        self.assertIn("list-general.list", md)
        self.assertIn("Доказательства", md)


if __name__ == "__main__":
    unittest.main()
