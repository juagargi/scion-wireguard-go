"""CLI and run wiring of experiment.py with fakes: no Docker, no SSH, no wireguard-go."""

import contextlib
import dataclasses
import io
import json
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config  # noqa: E402
import experiment  # noqa: E402
import wireguard  # noqa: E402
import workloads  # noqa: E402

HERE = Path(__file__).resolve().parent
DOCKER_JSON = HERE / "experiment-docker.json"


def run_main(argv, **kwargs):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = experiment.main(argv, **kwargs)
    return rc, out.getvalue()


class FakeHost:
    def __init__(self, name):
        self.name = name
        self.commands = []
        self.stopped = []
        self.files = {}

    def run(self, argv, check=True, **kw):
        self.commands.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    def path_exists(self, remote):
        return True

    def stop_daemon(self, pid_path, **kw):
        self.stopped.append(pid_path)
        return False

    def get_file(self, remote, local):
        Path(local).write_text(f"log of {remote}\n")


class FakeInfra:
    def __init__(self, experiment_, fail_setup=None, teardown_errors=()):
        self.experiment = experiment_
        self.calls = []
        self.fail_setup = fail_setup
        self.teardown_errors = list(teardown_errors)
        self._hosts = {k: FakeHost(k) for k in sorted({e.host_key for e in experiment_.endpoints})}
        self.prometheus_url = "http://127.0.0.1:1"

    def step(self, name):
        self.calls.append(name)
        if self.fail_setup == name:
            return [f"{name} broke"]
        return []

    def check_clocks(self):
        return self.step("clocks")

    def setup_infrastructure(self):
        return self.step("infrastructure")

    def preflight(self):
        return self.step("preflight")

    def install_binary(self, path):
        self.calls.append(("binary", path))
        return {}

    def install_jwt(self):
        self.calls.append("jwt")

    def setup_monitoring(self):
        return self.step("monitoring")

    def teardown_infrastructure(self):
        self.calls.append("teardown")
        return list(self.teardown_errors)

    def hosts(self):
        return self._hosts

    def binary_paths(self):
        return {k: "/share/bin/wireguard-go" for k in self._hosts}

    def jwt_paths(self):
        return {"1-ff00:0:111": "/tmp/jwt"}

    def run_dir(self, key):
        return "/tmp/wgexp"

    def sciond_address(self, endpoint):
        return "[::1]:30255"

    def write_targets(self):
        self.calls.append("targets")

    def wait_metrics_delivered(self, end):
        self.calls.append("delivered")

    def grafana_url(self, start, end=None):
        return "http://grafana/d/x"


class FakeInstance:
    created = []

    def __init__(self, experiment_, endpoint, host, binary, run_dir, run_id, jwt_path, sciond):
        self.endpoint, self.host, self.run_id = endpoint, host, run_id
        self.log_path = f"{run_dir}/runs/{run_id}/wg-{endpoint.name}.log"
        self.started = self.stopped = False
        self.jwt_path = jwt_path
        FakeInstance.created.append(self)

    def start(self):
        self.started = True
        return 42

    def alive(self):
        return not self.stopped

    def stop(self):
        self.stopped = True

    def log_tail(self):
        return ""

    def reservation_log_stats(self):
        return wireguard.ReservationStats(purchased=2, failed=1, handovers=1, marketplaces=())


class FakeServer:
    def __init__(self, registry, port, bind):
        self.port, self.bind, self.started, self.stopped = port, bind, False, False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


class FakeRunner:
    """behaviour: 'pass' finishes at once, 'fail' fails at once, 'hang' never finishes."""
    behaviour = {}

    def __init__(self, workload, sender, receiver, metrics, d1, d2, run_id, reservation, logs_dir,
                 index=0):
        self.w = workload
        self.index, self.reservation = index, reservation
        self.state = workloads.PENDING
        self.prepared = self.stopped = self.cleaned = False
        self.error = None

    def prepare(self):
        self.prepared = True

    def start(self):
        assert self.prepared, "start before prepare"
        how = self.behaviour.get(self.w.id, "pass" if self.w.role == "primary" else "hang")
        self.state = {"pass": workloads.PASSED, "fail": workloads.FAILED,
                      "hang": workloads.RUNNING}[how]
        if how == "fail":
            self.error = "sha256 mismatch"

    def poll(self):
        return self.state

    def stop(self):
        self.stopped = True
        if self.state == workloads.RUNNING:
            self.state = workloads.PASSED if self.w.role == "background" else workloads.FAILED
            if self.state == workloads.FAILED:
                self.error = "stopped before completion"

    def cleanup(self):
        self.cleaned = True

    def result(self):
        return workloads.WorkloadResult(
            id=self.w.id, kind=self.w.kind, role=self.w.role, state=self.state, iterations=1,
            restarts=0, bytes=100, started_at=1.0, ended_at=3.0, duration=2.0,
            mean_goodput_bps=400.0, details={}, error=self.error)


def quick_experiment(**run):
    exp = config.load_config(DOCKER_JSON)
    settings = dataclasses.replace(exp.run, warmup=0.0, cooldown=0.0, **run)
    return dataclasses.replace(exp, run=settings)


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        FakeInstance.created = []
        FakeRunner.behaviour = {}
        self.servers = []
        patcher = mock.patch.object(wireguard, "bring_up_tunnel", return_value={"QoS1": "in use"})
        self.bring_up = patcher.start()
        self.addCleanup(patcher.stop)

    def server_factory(self, *args):
        server = FakeServer(*args)
        self.servers.append(server)
        return server

    def run_(self, exp=None, infra=None, **kwargs):
        exp = exp or quick_experiment()
        infra = infra or FakeInfra(exp)
        run = experiment.Run(exp, infra, run_id="rid", logs_root=Path(self.tmp.name),
                             instance_factory=FakeInstance, runner_factory=FakeRunner,
                             server_factory=self.server_factory, poll_interval=0.01,
                             sleep=lambda s: time.sleep(min(s, 0.01)), **kwargs)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = run.execute()
        self.output = out.getvalue()
        results = json.loads((Path(self.tmp.name) / "rid" / "results.json").read_text())
        return rc, results, run, infra

    def test_passing_run(self):
        rc, results, run, infra = self.run_()
        self.assertEqual(rc, 0)
        self.assertTrue(results["passed"])
        self.assertFalse(results["interrupted"])
        self.assertEqual([w["id"] for w in results["workloads"]],
                         ["copy-1g", "be-load", "ping-ab", "ping-cd"])
        self.assertEqual(results["workloads"][0]["state"], "passed")
        self.assertEqual(results["senders"][0]["reservations_bought"], 2)
        self.assertEqual(results["grafana_url"], "http://grafana/d/x")
        self.assertIn("targets", infra.calls)
        # everything created was cleaned up
        self.assertTrue(all(i.started and i.stopped for i in FakeInstance.created))
        self.assertTrue(all(r.stopped and r.cleaned for r in run.runners.values()))
        self.assertTrue(self.servers[0].started and self.servers[0].stopped)
        self.assertEqual(self.servers[0].bind, "127.0.0.1")
        self.assertEqual(self.servers[0].port, 9189)
        self.assertTrue((Path(self.tmp.name) / "rid" / "wg-QoS1.log").is_file())
        # the receivers were prepared before anything started; only the sender has a JWT
        self.assertEqual({i.endpoint.name: i.jwt_path for i in FakeInstance.created},
                         {"QoS1": "/tmp/jwt", "QoS2": None, "BE1": None, "BE2": None})
        # bwlimit source: the sender's reservation
        self.assertEqual(run.runners["copy-1g"].reservation, 20_000_000)
        self.assertEqual(sorted(r.index for r in run.runners.values() if r.w.kind == "file_copy"), [0])
        self.assertIn("PASS", self.output)

    def test_run_dir_is_made_by_the_user_before_the_instances(self):
        # wireguard-go's root launcher would otherwise create it, owned by root, and the workloads
        # (not root) could not write into it.
        order = []
        start = FakeInstance.start
        with mock.patch.object(FakeInstance, "start", lambda self: order.append("start") or start(self)):
            _, _, _, infra = self.run_()
        for host in infra.hosts().values():
            self.assertIn(["mkdir", "-p", "--", "/tmp/wgexp/runs/rid/work"], host.commands)

    def test_leftovers_removed_first_only_ours(self):
        _, _, _, infra = self.run_()
        host = infra.hosts()["1-ff00:0:112"]
        removed = [c for c in host.commands if c[:2] == ["rm", "-rf"]]
        self.assertIn(["rm", "-rf", "--", "/tmp/wgexp/runs"], removed)
        deleted = [c for c in host.commands if c[:3] == ["ip", "link", "del"]]
        self.assertEqual(sorted(c[4] for c in deleted if c[4].startswith("wgx-")), ["wgx-ab", "wgx-cd"])

    def test_failing_primary_fails_the_run(self):
        FakeRunner.behaviour = {"copy-1g": "fail"}
        rc, results, run, _ = self.run_()
        self.assertEqual(rc, 1)
        self.assertFalse(results["passed"])
        copy = results["workloads"][0]
        self.assertEqual((copy["state"], copy["error"]), ("failed", "sha256 mismatch"))
        self.assertTrue(all(r.cleaned for r in run.runners.values()))
        self.assertIn("FAIL", self.output)

    def test_max_duration_marks_timeout(self):
        FakeRunner.behaviour = {"copy-1g": "hang"}
        rc, results, run, _ = self.run_(quick_experiment(max_duration=0.2))
        self.assertEqual(rc, 1)
        copy = results["workloads"][0]
        self.assertEqual(copy["state"], "timeout")
        self.assertTrue(all(r.cleaned for r in run.runners.values()))

    def test_runner_timeout_error_is_a_timeout(self):
        res = workloads.WorkloadResult("c", "file_copy", "primary", workloads.FAILED, 0, 0, 0, 1.0, 2.0,
                                       1.0, 0.0, {}, "timed out after 5s")
        wl = quick_experiment().workloads[0]
        outcome = experiment.to_outcome(res, wl, interrupted=False, timed_out=False)
        self.assertEqual(outcome.state, "timeout")
        self.assertEqual(outcome.tunnel, "ab")
        self.assertEqual((outcome.from_, outcome.to), ("QoS1", "QoS2"))

    def test_interrupt_cleans_up_and_marks_interrupted(self):
        FakeRunner.behaviour = {"copy-1g": "hang"}
        calls = []

        def sleep(seconds):
            calls.append(seconds)
            if len(calls) == 4:
                raise KeyboardInterrupt
            time.sleep(0.01)

        exp, handler = quick_experiment(), signal.getsignal(signal.SIGINT)
        infra = FakeInfra(exp)
        run = experiment.Run(exp, infra, run_id="rid", logs_root=Path(self.tmp.name),
                             instance_factory=FakeInstance, runner_factory=FakeRunner,
                             server_factory=self.server_factory, poll_interval=0.01, sleep=sleep)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = run.execute()
        results = json.loads((Path(self.tmp.name) / "rid" / "results.json").read_text())
        self.assertEqual(rc, 1)
        self.assertTrue(results["interrupted"])
        self.assertFalse(results["passed"])
        self.assertEqual(results["workloads"][0]["state"], "stopped")
        self.assertTrue(all(i.stopped for i in FakeInstance.created))
        self.assertTrue(self.servers[0].stopped)
        self.assertIs(signal.getsignal(signal.SIGINT), handler)  # restored after the cleanup

    def test_tunnel_failure_still_writes_results_and_cleans_up(self):
        self.bring_up.side_effect = wireguard.WireguardError("no traffic passed")
        rc, results, run, _ = self.run_()
        self.assertEqual(rc, 1)
        self.assertFalse(results["passed"])
        self.assertTrue(all(w["state"] == "failed" and "no traffic passed" in w["error"]
                            for w in results["workloads"]))
        self.assertTrue(all(i.stopped for i in FakeInstance.created))
        self.assertIn("no traffic passed", self.output)

    def test_instance_dying_during_the_run_fails_it(self):
        FakeRunner.behaviour = {"copy-1g": "hang"}
        original = FakeInstance.alive
        with mock.patch.object(FakeInstance, "alive",
                               lambda self: False if self.endpoint.name == "QoS2" and self.started
                               and sum(i.endpoint.name == "QoS2" for i in FakeInstance.created) else True):
            rc, results, _, _ = self.run_()
        self.assertEqual(rc, 1)
        self.assertIn("died during the run", self.output)
        self.assertIs(FakeInstance.alive, original)

    def test_reservation_metrics_are_counted(self):
        _, _, run, _ = self.run_()
        text = run.metrics.registry.render()
        self.assertIn('wgexp_reservations_total{endpoint="QoS1",result="ok"} 2', text)
        self.assertIn('wgexp_reservations_total{endpoint="QoS1",result="failed"} 1', text)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.exp = config.load_config(DOCKER_JSON)
        self.infra = FakeInfra(self.exp)
        self.factory = lambda exp, scion, dry: self.infra
        self.builds = []

        def builder(dry):
            self.builds.append(dry)
            return Path("/bin/wireguard-go")
        self.builder = builder
        self.args = ["--config", str(DOCKER_JSON), "--scion-dir", str(HERE)]

    def test_setup_prints_informative_first_and_ends_with_done(self):
        rc, out = run_main(["setup", *self.args], infra_factory=self.factory, builder=self.builder)
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        self.assertEqual(lines[0], self.exp.informative[0])
        self.assertEqual(lines[-1], "setup: done.")
        self.assertEqual(self.infra.calls[:3], ["clocks", "infrastructure", "preflight"])
        self.assertEqual(self.infra.calls[-2:], ["jwt", "monitoring"])
        self.assertEqual(self.builds, [False])

    def test_setup_failure_ends_with_failed(self):
        self.infra.fail_setup = "preflight"
        rc, out = run_main(["setup", *self.args], infra_factory=self.factory, builder=self.builder)
        self.assertEqual(rc, 1)
        self.assertEqual(out.splitlines()[-1], "setup: FAILED.")
        self.assertIn("preflight broke", out)

    def test_setup_exception_ends_with_failed(self):
        def broken(*a):
            raise RuntimeError("docker is down")
        rc, out = run_main(["setup", *self.args], infra_factory=broken, builder=self.builder)
        self.assertEqual(rc, 1)
        self.assertIn("docker is down", out)
        self.assertEqual(out.splitlines()[-1], "setup: FAILED.")

    def test_setup_dry_run_is_passed_on(self):
        seen = []
        def factory(exp, scion, dry):
            seen.append(dry)
            return self.infra
        rc, out = run_main(["setup", "--dry-run", *self.args], infra_factory=factory,
                           builder=self.builder)
        self.assertEqual((rc, seen, self.builds), (0, [True], [True]))
        self.assertEqual(out.splitlines()[-1], "setup: done.")

    def test_dry_run_only_for_setup(self):
        rc, out = run_main(["run", "--dry-run", *self.args], infra_factory=self.factory)
        self.assertEqual(rc, 2)

    def test_invalid_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{}")
            rc, out = run_main(["setup", "--config", str(bad), "--scion-dir", tmp],
                               infra_factory=self.factory, builder=self.builder)
        self.assertEqual(rc, 2)
        self.assertEqual(out.splitlines()[-1], "setup: FAILED.")

    def test_missing_scion_dir(self):
        with mock.patch.dict("os.environ", {}, clear=False) as env:
            env.pop("SCION_DIR", None)
            rc, out = run_main(["teardown", "--config", str(DOCKER_JSON)], infra_factory=self.factory)
        self.assertEqual(rc, 2)
        self.assertIn("--scion-dir", out)

    def test_scion_dir_from_environment(self):
        with mock.patch.dict("os.environ", {"SCION_DIR": str(HERE)}):
            rc, out = run_main(["teardown", "--config", str(DOCKER_JSON)], infra_factory=self.factory)
        self.assertEqual(rc, 0)

    def test_teardown_continues_and_reports(self):
        self.infra.teardown_errors = ["remove qdiscs: boom"]
        rc, out = run_main(["teardown", *self.args], infra_factory=self.factory)
        self.assertEqual(rc, 1)
        self.assertIn("remove qdiscs: boom", out)
        self.assertEqual(out.splitlines()[-1], "teardown: FAILED.")
        self.assertIn("teardown", self.infra.calls)
        # the leftovers of the hosts were removed and the docker run dir deleted
        host = self.infra.hosts()["1-ff00:0:112"]
        self.assertIn(["rm", "-rf", "--", "/tmp/wgexp"], host.commands)

    def test_teardown_ok(self):
        rc, out = run_main(["teardown", *self.args], infra_factory=self.factory)
        self.assertEqual((rc, out.splitlines()[-1]), (0, "teardown: done."))

    def test_teardown_survives_a_failing_host(self):
        self.infra.hosts()["1-ff00:0:111"].run = mock.Mock(side_effect=RuntimeError("container gone"))
        rc, out = run_main(["teardown", *self.args], infra_factory=self.factory)
        self.assertEqual(rc, 1)
        self.assertIn("container gone", out)
        self.assertIn("teardown", self.infra.calls)  # infrastructure still torn down

    def test_run_id_format(self):
        import datetime
        rid = experiment.make_run_id(self.exp, datetime.datetime(2026, 11, 4, 16, 5, 18))
        self.assertEqual(rid, "20261104-160518-docker-tiny-1g")


class DashboardContractTest(unittest.TestCase):
    """Every panel query that filters on `tunnel` must select a metric that carries that label
    (wgexp_reservations_total has none: its panel showed nothing in the first live run)."""

    def test_tunnel_selectors_match_metric_labels(self):
        import re
        import runner_metrics
        dashboard = json.loads(
            (HERE / "monitoring" / "grafana" / "dashboards" / "wgexp-overview.json").read_text())
        metrics = runner_metrics.make_runner_registry("r", "s", "n")
        labels = {f.name: set(f.labelnames) for f in metrics.registry._families} \
            if hasattr(metrics.registry, "_families") else {}

        def panels(items):
            for panel in items:
                yield from panels(panel.get("panels", []))
                yield panel

        checked = 0
        for panel in panels(dashboard["panels"]):
            for target in panel.get("targets", []):
                expr = target.get("expr", "")
                for name, selector in re.findall(r"(wgexp_\w+?)(?:_bucket|_count|_sum)?\{([^}]*)\}", expr):
                    if "tunnel" in selector and labels:
                        checked += 1
                        self.assertIn("tunnel", labels.get(name, {"tunnel"}), f"{name} in {expr}")
        if labels:
            self.assertGreater(checked, 5)

    def test_router_queries_leave_out_hidden_routers(self):
        """A router with display false is labeled display="false"; no panel or results.json
        figure may count it (the same rule as hummbwtester's dashboard)."""
        import re
        dashboard = json.loads(
            (HERE / "monitoring" / "grafana" / "dashboards" / "wgexp-overview.json").read_text())
        import results
        exprs: list[str] = list(results.PROMETHEUS_QUERIES.values())

        def collect(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "expr" and isinstance(item, str):
                        exprs.append(item)
                    else:
                        collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect(dashboard)
        selectors = [(expr, m.group(0)) for expr in exprs
                     for m in re.finditer(r'\b(?:router_\w+|up(?=\{+job="scion-border-routers"))'
                                          r'(?:\{+[^}]*\}+)?', expr)]
        self.assertGreater(len(selectors), 20)
        for expr, selector in selectors:
            with self.subTest(expr=expr):
                self.assertIn('display!="false"', selector)


if __name__ == "__main__":
    unittest.main()
