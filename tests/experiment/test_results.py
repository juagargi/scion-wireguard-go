import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

import results as R

LOG = """\
Hummingbird: buying the reservation for 1-ff00:0:111 from the marketplace at [1-ff00:0:110,10.0.0.1]:8080, set by HUMMINGBIRD_MARKETPLACE_ADDRESS
Hummingbird reservation for 1-ff00:0:111 in use, expires at 2026-01-01T00:00:00Z, flyovers at [a b]
Buying Hummingbird reservation for 1-ff00:0:111 failed (attempt 1/3): timeout
Buying Hummingbird reservation for 1-ff00:0:111 failed: boom
Hummingbird reservation for 1-ff00:0:111 in use, expires at 2026-01-01T00:01:00Z, flyovers at [c]
Hummingbird reservation for 1-ff00:0:111 in use, expires at 2026-01-01T00:02:00Z, flyovers at [d]
"""


def wl(state="passed", role="primary", id="w1"):
    return R.WorkloadOutcome(id=id, kind="file_copy", role=role, tunnel="t", from_="A", to="B", state=state,
                             details={"sha256_sender": "x"})


def run(workloads, interrupted=False):
    return R.RunResult("r1", "c.json", "abc", "docker", "n", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z",
                       interrupted, workloads, [R.SenderStats("A", 2, 1, 1, ["m"])], {"window_s": 60, "priority_drops": 0.0},
                       "http://g")


class Fake(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "priority" in self.path:
            body = {"status": "success", "data": {"result": []}}
        elif "freshness" in self.path:
            body = {"status": "success", "data": {"result": [{"value": [1, "7"]}]}}
        else:
            body = {"status": "error", "error": "bad"}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class Tests(unittest.TestCase):
    def test_log(self):
        s = R.parse_sender_log(LOG, "A")
        self.assertEqual((s.reservations_bought, s.reservations_failed, s.handovers), (3, 2, 2))
        self.assertEqual(s.marketplace_addresses, ["[1-ff00:0:110,10.0.0.1]:8080"])
        self.assertEqual(R.parse_sender_log("").handovers, 0)

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sub" / "results.json"
            r = run([wl()])
            R.write_results(p, r)
            self.assertEqual(json.loads(p.read_text())["workloads"][0]["from"], "A")
            self.assertEqual(R.read_results(p), r)
            self.assertFalse(list(p.parent.glob("*.tmp")))

    def test_passed(self):
        self.assertTrue(run([wl(), wl("stopped", "background", "bg")]).passed)
        for state in ("failed", "timeout", "stopped"):
            r = run([wl(state)])
            self.assertFalse(r.passed)
            self.assertEqual(R.exit_code(r), 1)
        self.assertFalse(run([wl()], interrupted=True).passed)
        self.assertFalse(run([]).passed)
        self.assertEqual(R.exit_code(run([wl()])), 0)

    def test_prometheus(self):
        srv = http.server.HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        out = R.query_prometheus(f"http://127.0.0.1:{srv.server_port}", 100, 160)
        srv.shutdown()
        self.assertEqual(out["demoted_freshness"], 7.0)
        self.assertIsNone(out["priority_drops"])
        self.assertIsNone(out["priority_drops_egress_down"])
        self.assertIn("drops_egress_down", out)
        self.assertTrue(out["demoted_expired"].startswith("error"))
        dead = R.query_prometheus("http://127.0.0.1:1", 100, 160, timeout=0.5)
        self.assertTrue(all(str(v).startswith("error") for k, v in dead.items() if k != "window_s"))

    def test_url(self):
        self.assertEqual(R.grafana_url(3000, 1.5, 2),
                         "http://127.0.0.1:3000/d/wgexp-overview/?orgId=1&from=1500&to=2000&refresh=")
        self.assertIn("&var-tunnel=t1", R.grafana_url(3000, 1, 2, tunnel="t1"))

    def test_summary(self):
        s = R.render_summary(run([wl(), wl("failed", id="w2")]))
        self.assertIn("w2", s)
        self.assertIn("Grafana: http://g", s)
        self.assertTrue(s.endswith("FAIL"))
        self.assertTrue(R.render_summary(run([wl()])).endswith("PASS"))
        self.assertIn("INTERRUPTED", R.render_summary(run([wl()], True)))


if __name__ == "__main__":
    unittest.main()
