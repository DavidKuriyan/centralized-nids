import unittest
from unittest.mock import patch

from core.detection_engine import DetectionEngine
from core.rule_management import (RuleValidationError, decode_content, parse_port_expression,
                                  parse_rule_text, set_port_variables, validate_rule)


class PortExpressionTests(unittest.TestCase):
    def setUp(self):
        from core.rule_management import load_port_variables
        load_port_variables()

    def test_canonical_matrix(self):
        cases = [
            ("80", 80),
            ("443", 443),
            ("80,443", "80,443"),
            ("[80,443]", "80,443"),
            ("1:1024", "1:1024"),
            ("$HTTP_PORTS", "80,8000,8008,8080,8888"),
            ("$HTTPS_PORTS", "443,8443"),
            ("$HTTP_PORTS,$HTTPS_PORTS", "80,443,8000,8008,8080,8443,8888"),
            ("$DNS_PORTS", 53),
            ("$SSH_PORTS", 22),
            ("$FTP_PORTS", "20:21"),
            ("any", "any"),
        ]
        for expression, expected in cases:
            with self.subTest(expression=expression):
                self.assertEqual(parse_port_expression(expression), expected)

    def test_custom_variable_table(self):
        set_port_variables({"HTTP_PORTS": [81, 82]})
        # Adjacent ports collapse to a range in the canonical form; the
        # matcher expands ranges, so 81:82 is the canonical equivalent of
        # 81,82.
        self.assertEqual(parse_port_expression("$HTTP_PORTS"), "81:82")

    def test_unknown_variable_is_user_friendly(self):
        with self.assertRaises(RuleValidationError) as context:
            parse_port_expression("$XYZ_PORTS")
        message = str(context.exception.format())
        self.assertIn("Unknown port variable '$XYZ_PORTS'", message)
        self.assertIn("Available variables:", message)
        self.assertIn("HTTP_PORTS", message)

    def test_invalid_expression_is_user_friendly(self):
        with self.assertRaises(RuleValidationError) as context:
            parse_port_expression("not-a-port")
        rendered = context.exception.format()
        self.assertIn("Rule validation failed", rendered)
        self.assertIn("Destination Port", rendered)
        for expected in ("80", "80,443", "[80,443]", "1:1024", "$HTTP_PORTS"):
            self.assertIn(expected, rendered)

    def test_out_of_range_port_rejected(self):
        with self.assertRaises(RuleValidationError):
            parse_port_expression("70000")

    def test_invalid_range_rejected(self):
        with self.assertRaises(RuleValidationError):
            parse_port_expression("1024:1")

    def test_json_rule_validation_normalizes_ports(self):
        rule = validate_rule({"sid": 1, "rev": 1, "protocol": "TCP", "dst_port": "[80,443]",
                              "content": "x", "message": "m"})
        self.assertEqual(rule["dst_port"], "80,443")

    def test_content_hex_escape_decoding(self):
        self.assertEqual(decode_content("User-Agent|3a| Nmap"), b"User-Agent: Nmap")
        self.assertEqual(decode_content("|3a|"), b":")
        self.assertEqual(decode_content("GET /x"), b"GET /x")
        self.assertEqual(decode_content(["User-Agent|3a| ", "Nmap"]), b"User-Agent: Nmap")


class RuleTextParsingTests(unittest.TestCase):
    def setUp(self):
        from core.rule_management import load_port_variables
        load_port_variables()

    def test_rule_with_variable_port(self):
        rule = parse_rule_text("alert tcp 192.168.68.110 any -> any $HTTP_PORTS "
                               '(msg:"Nmap detected from windows"; content:"User-Agent|3a| Nmap"; sid:100023; rev:123;)')
        self.assertEqual(rule["sid"], 100023)
        self.assertEqual(rule["rev"], 123)
        self.assertEqual(rule["dst_port"], "80,8000,8008,8080,8888")
        self.assertEqual(rule["src_ip"], "192.168.68.110")

    def test_rule_with_bracketed_port_list(self):
        rule = parse_rule_text("alert tcp 192.168.68.110 any -> any [80,443] "
                               '(msg:"Nmap ports"; content:"GET /"; sid:100024; rev:1;)')
        self.assertEqual(rule["dst_port"], "80,443")

    def test_rule_with_range(self):
        rule = parse_rule_text("alert tcp any any -> any 1:1024 (msg:\"x\"; sid:1; rev:1;)")
        self.assertEqual(rule["dst_port"], "1:1024")

    def test_rule_header_and_options_round_trip(self):
        rule = parse_rule_text("alert tcp 192.168.68.0/24 any -> any $HTTPS_PORTS "
                               '(msg:"tls"; content:"|16 03|"; nocase; sid:42; rev:2; priority:2;)')
        self.assertEqual(rule["src_ip"], "192.168.68.0/24")
        self.assertEqual(rule["dst_port"], "443,8443")
        self.assertTrue(rule["nocase"])
        self.assertEqual(rule["priority"], 2)

    def test_parse_source_and_destination_are_preserved(self):
        rule = parse_rule_text("alert tcp 10.0.0.1 any -> 10.0.0.2 any (msg:\"pair\"; sid:7; rev:1;)")
        self.assertEqual(rule["src_ip"], "10.0.0.1")
        self.assertEqual(rule["dst_ip"], "10.0.0.2")


class RuleMatchingTests(unittest.TestCase):
    def setUp(self):
        from core.rule_management import load_port_variables
        load_port_variables()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine._compiled_rules = []
        engine.unsupported_rules = 0
        engine._alert_cache = {}
        engine._lock = __import__("threading").RLock()
        engine.rules = []
        self.engine = engine

    def _load(self, rules):
        self.engine.rules = rules
        self.engine._compiled_rules = self.engine._compile_rules(rules)

    def _sids(self, packet):
        return sorted(alert["sid"] for alert in self.engine.analyze_packet(packet))

    def test_variable_port_rule_matches_http_destinations(self):
        rule = parse_rule_text("alert tcp 192.168.68.110 any -> any $HTTP_PORTS "
                               '(msg:"Nmap detected from windows"; content:"User-Agent|3a| Nmap"; sid:100023; rev:123;)')
        self._load([rule])
        base = {"src_ip": "192.168.68.110", "dst_ip": "198.51.100.9", "protocol": "TCP", "src_port": 50000}
        self.assertEqual(self._sids({**base, "dst_port": 80, "payload": b"User-Agent: Nmap"}), [100023])
        self.assertEqual(self._sids({**base, "dst_port": 8080, "payload": b"User-Agent: Nmap"}), [100023])
        self.assertEqual(self._sids({**base, "dst_port": 8888, "payload": b"User-Agent: Nmap"}), [100023])
        # unrelated ports must not match
        self.assertEqual(self._sids({**base, "dst_port": 8445, "payload": b"User-Agent: Nmap"}), [])
        self.assertEqual(self._sids({**base, "dst_port": 22, "payload": b"User-Agent: Nmap"}), [])
        # payload without content must not match
        self.assertEqual(self._sids({**base, "dst_port": 80, "payload": b"GET /index HTTP/1.1"}), [])

    def test_bracketed_port_list_rule_matches_80_and_443(self):
        rule = parse_rule_text("alert tcp 192.168.68.110 any -> any [80,443] "
                               '(msg:"web ports"; content:"GET /"; sid:100024; rev:1;)')
        self._load([rule])
        base = {"src_ip": "192.168.68.110", "dst_ip": "198.51.100.9", "protocol": "TCP", "src_port": 50000}
        self.assertEqual(self._sids({**base, "dst_port": 80, "payload": b"GET /index"}), [100024])
        self.assertEqual(self._sids({**base, "dst_port": 443, "payload": b"GET /index"}), [100024])
        self.assertEqual(self._sids({**base, "dst_port": 8080, "payload": b"GET /index"}), [])

    def test_range_rule(self):
        rule = parse_rule_text("alert tcp any any -> any 1:1024 (msg:\"low ports\"; content:\"x\"; sid:3; rev:1;)")
        self._load([rule])
        base = {"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP", "src_port": 50000}
        self.assertEqual(self._sids({**base, "dst_port": 22, "payload": b"x"}), [3])
        self.assertEqual(self._sids({**base, "dst_port": 1024, "payload": b"x"}), [3])
        self.assertEqual(self._sids({**base, "dst_port": 1025, "payload": b"x"}), [])

    def test_source_selector_is_enforced(self):
        rule = parse_rule_text("alert tcp 192.168.68.110 any -> any 80 "
                               '(msg:"specific source"; content:"GET /"; sid:5; rev:1;)')
        self._load([rule])
        packet = {"src_ip": "10.0.0.9", "dst_ip": "198.51.100.9", "protocol": "TCP",
                  "src_port": 50000, "dst_port": 80, "payload": b"GET /admin"}
        self.assertEqual(self._sids(packet), [])

    def test_file_rules_compile_deterministically(self):
        with patch.dict("os.environ", {"DELTA_NIDS_PORT_VARIABLES": "{}"}, clear=False):
            from core.rule_management import load_port_variables
            load_port_variables()
            rule = {"sid": 77, "rev": 1, "protocol": "TCP", "dst_port": "$HTTP_PORTS",
                    "content": "x", "message": "file"}
            self._load([rule])
            self.assertEqual(self.engine._compiled_rules[0]["dst_port"], "80,8000,8008,8080,8888")


if __name__ == "__main__":
    unittest.main()