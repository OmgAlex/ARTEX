import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .adapters import samples
from .advisory import Provider, advise
from .common import Invalid, strict_json
from .demo import DEMO_TIME, demo
from .render import to_html
from .verify import decide, evaluate


def xml(state, host="127.0.0.1", exit_code="success", start=DEMO_TIME):
    return (f'<nmaprun scanner="nmap" start="{start}"><host><address addr="{host}"/>'
            f'<ports><port protocol="tcp" portid="5432"><state state="{state}"/></port></ports>'
            f'</host><runstats><finished exit="{exit_code}"/></runstats></nmaprun>').encode()


class Adapters(unittest.TestCase):
    def test_port_states(self):
        rule = {"kind":"tcp.exposure","port":5432}
        for state, expected in [("open","present"),("closed","absent"),("open|filtered","unknown")]:
            with self.subTest(state=state):
                self.assertEqual(samples(xml(state), "127.0.0.1", rule)[0]["outcome"], expected)
        self.assertEqual(samples(xml("open"), "127.0.0.2", rule), [])
        self.assertEqual(samples(xml("open", exit_code="error"), "127.0.0.1", rule), [])

    def test_entity_xml(self):
        with self.assertRaises(Invalid):
            samples(b"<!DOCTYPE nmaprun [<!ENTITY x 'test'>]><nmaprun/>", "127.0.0.1",
                    {"kind":"tcp.exposure","port":5432})

    def test_role_grants(self):
        rule = {"kind":"postgres.superuser","role":"app"}
        for flag, expected in [(True,"present"),(False,"absent")]:
            data = json.dumps({"database":"stage","role":"app","captured_at":DEMO_TIME,"rolsuper":flag}).encode()
            self.assertEqual(samples(data, "stage", rule)[0]["outcome"], expected)
            self.assertEqual(samples(data, "other", rule), [])

    def test_scanner_consensus_remains_hypothesis(self):
        cases = {"testssl":[{"id":"rule","severity":"MEDIUM"}],
                 "forge":{"suite":{"test_results":{"rule":{"status":"Failure"}}}},
                 "echidna":{"tests":[{"name":"rule","status":"solved"}]}, "semgrep":{"results":[{"check_id":"rule"}]}, "trivy":{"Results":[{"Vulnerabilities":[
                 {"VulnerabilityID":"rule"}]}]}, "zap":{"site":[{"alerts":[{"pluginid":"rule"}]}]},
                 "slither":{"success":True,"results":{"detectors":[{"check":"rule"}]}}}
        for tool, obj in cases.items():
            with self.subTest(tool=tool):
                rule = {"kind":tool,"detector":"rule"}
                items = samples(json.dumps(obj).encode(), "asset", rule)
                verdict, _ = decide(rule, [{"side":"target","items":items}])
                self.assertEqual(verdict, "hypothesis")
                rule["detector"] = "unreported"
                self.assertEqual(samples(json.dumps(obj).encode(), "asset", rule)[0]["outcome"], "unknown")

    def test_malformed_json(self):
        with self.assertRaises(Invalid):
            strict_json(b'{"x":1,"x":2}')


class Pipeline(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.manifest = demo(self.home/"demo")
        self.report = evaluate(self.manifest)

    def test_provider_config(self):
        with patch.dict(os.environ, {"WHITEHAT_STRONG_URL":"http://public.example","WHITEHAT_STRONG_MODEL":"x"}):
            with self.assertRaises(Invalid):
                Provider("strong")

    def test_planner_worker_and_review(self):
        case = self.report["cases"][0]
        case["status"] = "conflicting"
        calls = []
        def stub(instructions, payload):
            calls.append(json.dumps(payload))
            if "numeric case index" in instructions:
                return {"order":[0]}
            if "Choose one local" in instructions:
                return {"action":"inspect_control"}
            return {"reason":"conflicting_records","next":"review_scope"}
        advise(self.report, stub, stub, 4)
        self.assertEqual(self.report["model_review"]["calls"], 4)
        self.assertIn("reviewer", case["advisory"])
        self.assertEqual(case["status"], "conflicting")
        self.assertNotIn("fixture.test", "".join(calls))

    def test_budget_exhaustion(self):
        advise(self.report, lambda *_: {"order":[0]}, lambda *_: self.fail(), 1)
        self.assertEqual(self.report["model_review"]["status"], "budget_exhausted")

    def test_model_cannot_set_status_or_execute(self):
        advise(self.report, lambda *_:{"order":[0]}, lambda *_:{"action":"shell","status":"confirmed"}, 3)
        self.assertEqual(self.report["model_review"]["status"], "provider_or_schema_error")
        self.assertEqual(self.report["cases"][0]["status"], "confirmed")

    def test_html_output_escapes_operator_text(self):
        self.report["cases"][0]["target"] = "<script>alert(1)</script>"
        self.assertNotIn("<script>", to_html(self.report))

    def test_cli_writes_pair_and_preserves_previous(self):
        output = self.home/"report"
        cmd = [sys.executable,"-m","whitehat","report",str(self.manifest),"--out",str(output)]
        first = subprocess.run(cmd,capture_output=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue((output/"report.html").is_file())
        original = (output/"report.json").read_bytes()
        self.assertEqual(json.loads(original)["counts"]["confirmed"],1)
        self.assertEqual(subprocess.run(cmd,capture_output=True).returncode, 1)
        self.assertEqual((output/"report.json").read_bytes(),original)
