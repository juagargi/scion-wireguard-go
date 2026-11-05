import sys
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner_metrics import MetricsServer, Registry, WorkloadLabels, make_runner_registry  # noqa: E402


class RegistryTest(unittest.TestCase):
    def test_golden(self):
        r = Registry()
        c = r.counter("x_total", "A counter.\nline", ("a", "from"))
        g = r.gauge("y", "A gauge.", ("a",))
        h = r.histogram("z_seconds", "Hist.", ("a",), (0.1, 1.0))
        c.labels(**{"a": 'q"\\\n', "from": "A"}).inc(2)
        g.labels(a="1").set(1.5)
        h.labels(a="1").observe(0.05)
        h.labels(a="1").observe(0.5)
        h.labels(a="1").observe(7)
        self.assertEqual(r.render(), "\n".join([
            "# HELP x_total A counter.\\nline",
            "# TYPE x_total counter",
            'x_total{a="q\\"\\\\\\n",from="A"} 2',
            "# HELP y A gauge.",
            "# TYPE y gauge",
            'y{a="1"} 1.5',
            "# HELP z_seconds Hist.",
            "# TYPE z_seconds histogram",
            'z_seconds_bucket{a="1",le="0.1"} 1',
            'z_seconds_bucket{a="1",le="1"} 2',
            'z_seconds_bucket{a="1",le="+Inf"} 3',
            'z_seconds_sum{a="1"} 7.55',
            'z_seconds_count{a="1"} 3',
            ""]))

    def test_label_mismatch_and_negative_counter(self):
        r = Registry()
        c = r.counter("c_total", "c", ("a",))
        with self.assertRaises(ValueError):
            c.labels(b="1")
        with self.assertRaises(ValueError):
            c.labels(a="1").inc(-1)
        with self.assertRaises(ValueError):
            r.gauge("c_total", "dup")

    def test_unlabelled(self):
        r = Registry()
        c = r.counter("n_total", "n")
        c.inc()
        c.inc(2)
        self.assertIn("n_total 3\n", r.render())


class RunnerRegistryTest(unittest.TestCase):
    def test_declared(self):
        m = make_runner_registry("run1", "abc", "exp")
        text = m.registry.render()
        for name, typ in [("wgexp_workload_state", "gauge"), ("wgexp_workload_bytes_total", "counter"),
                          ("wgexp_workload_iterations_total", "counter"),
                          ("wgexp_workload_restarts_total", "counter"), ("wgexp_verify_total", "counter"),
                          ("wgexp_iperf3_datagrams_total", "counter"),
                          ("wgexp_iperf3_lost_datagrams_total", "counter"),
                          ("wgexp_ping_rtt_seconds", "histogram"), ("wgexp_ping_sent_total", "counter"),
                          ("wgexp_ping_received_total", "counter"), ("wgexp_ping_jitter_seconds", "gauge"),
                          ("wgexp_reservations_total", "counter"), ("wgexp_run_info", "gauge")]:
            self.assertIn(f"# TYPE {name} {typ}\n", text)
        self.assertIn('wgexp_run_info{run_id="run1",config_sha256="abc"} 1\n', text)

    def test_workload_labels(self):
        class T: id = "t1"
        class W: id, kind, role, from_, to, tunnel = "w", "ping", "background", "A", "B", T()
        m = make_runner_registry("r", "s", "e")
        labels = WorkloadLabels(W())
        self.assertEqual(list(labels), ["workload", "kind", "role", "tunnel", "from", "to"])
        m.workload_bytes.labels(**labels).inc(5)
        m.verify.labels(**labels, result="ok").inc()
        text = m.registry.render()
        self.assertIn('wgexp_workload_bytes_total{workload="w",kind="ping",role="background",'
                      'tunnel="t1",from="A",to="B"} 5\n', text)
        self.assertIn('to="B",result="ok"} 1\n', text)


class ServerTest(unittest.TestCase):
    def test_http(self):
        r = Registry()
        r.counter("a_total", "a").inc()
        s = MetricsServer(r, 0)
        s.start()
        try:
            self.assertNotEqual(s.port, 0)
            with urllib.request.urlopen(f"http://127.0.0.1:{s.port}/metrics") as resp:
                self.assertIn("version=0.0.4", resp.headers["Content-Type"])
                self.assertIn("a_total 1\n", resp.read().decode())
            with self.assertRaises(Exception):
                urllib.request.urlopen(f"http://127.0.0.1:{s.port}/other")
        finally:
            s.stop()
        s.stop()


if __name__ == "__main__":
    unittest.main()
