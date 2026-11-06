"""Tests for infra.py.

The pure helpers run anywhere. The tests that load hummbwtester need $SCION_DIR (a SCION checkout)
and PyYAML, and are skipped without them. Nothing here touches Docker or an SSH host: subprocess,
hummbwtester's step functions and the hosts are mocked.
"""

import dataclasses
import datetime
import inspect
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import config  # noqa: E402
import infra  # noqa: E402

DOCKER = HERE / "experiment-docker.json"
SCIERA = HERE / "experiment-sciera.json"

SCION_DIR = os.environ.get("SCION_DIR")
try:
    import yaml  # noqa: F401
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

REAL = bool(SCION_DIR) and HAVE_YAML and (Path(SCION_DIR or "/nonexistent") / "tools" / "hummbwtester").is_dir()
needs_scion = unittest.skipUnless(REAL, "needs $SCION_DIR and PyYAML")

_HB = None


def real_hb():
    global _HB
    if _HB is None:
        _HB = infra.load_hummbwtester(Path(SCION_DIR))
    return _HB


def docker_experiment():
    return config.load_config(DOCKER)


def sciera_experiment():
    return config.load_config(SCIERA)


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FakeHost:
    """A Host whose commands are answered by a function argv -> (returncode, stdout)."""

    def __init__(self, name, answer=None, address="10.0.0.1"):
        self.name = name
        self.answer = answer or (lambda argv, root: (0, ""))
        self.commands = []
        self._address = address
        self.files = {}

    def run(self, argv, *, check=True, root=False, **kwargs):
        self.commands.append((list(argv), root))
        code, out = self.answer(list(argv), root)
        return completed(out, code)

    def address(self):
        return self._address

    def read_text(self, remote):
        return self.files[remote]


class FakeOrchestration:
    """Just enough of hummbwtester's orchestration for the tests that must run without PyYAML."""

    GEN = Path("/nonexistent-gen")
    ROOT = Path("/nonexistent-root")

    @staticmethod
    def tester_service(ia):
        return "tester_" + ia.replace(":", "_")

    @staticmethod
    def join_host_port(host, port):
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    @staticmethod
    def border_router_targets():
        return [{"targets": ["172.20.0.9:30442"], "labels": {"as": "ff00_0_110", "br": "br1-ff00_0_110-1"}}]

    @staticmethod
    def dc_args(*args):
        return ["docker", "compose", "-f", "/x/scion-dc.yml", *args]


class Pure(unittest.TestCase):
    def test_labels_cover_the_plan_table(self):
        exp = docker_experiment()
        a, b, c, d = (exp.endpoint(n) for n in "ABCD")
        self.assertEqual(infra.wireguard_labels(exp, a, "tester_x"), {
            "experiment": "docker-tiny-1g", "tunnel": "ab", "endpoint": "A", "peer": "B",
            "class": "hummingbird", "tunnel_class": "hummingbird", "isd_as": "1-ff00:0:111",
            "node": "tester_x"})
        lb = infra.wireguard_labels(exp, b, "n")
        self.assertEqual((lb["class"], lb["tunnel_class"], lb["peer"]),
                         ("best_effort", "hummingbird", "A"))
        lc = infra.wireguard_labels(exp, c, "n")
        self.assertEqual((lc["class"], lc["tunnel_class"], lc["tunnel"]),
                         ("best_effort", "best_effort", "cd"))
        self.assertEqual(infra.wireguard_labels(exp, d, "n")["peer"], "C")

    def test_grafana_url_window(self):
        exp = docker_experiment()
        i = infra.DockerInfra(exp, Path("/x"), hb=SimpleNamespace(orchestration=FakeOrchestration))
        self.assertEqual(i.grafana_url(100, 160.5),
                         "http://127.0.0.1:3001/d/wgexp-overview/wgexp-overview?orgId=1"
                         "&from=100000&to=160500")
        start = datetime.datetime.fromtimestamp(5)
        self.assertTrue(i.grafana_url(start).endswith("from=5000&to=now"))
        self.assertEqual(i.prometheus_url, "http://127.0.0.1:8091")

    def test_dispatched_ports(self):
        self.assertEqual(infra.parse_dispatched_ports("31000-32767"), (31000, 32767))
        for none in ("all", None, "", "weird"):
            self.assertIsNone(infra.parse_dispatched_ports(none))

    def test_route_clashes_ignore_default_and_own_devices(self):
        out = ("default via 10.0.0.1 dev eth0\n"
               "10.78.0.0/24 dev wgx-ab proto kernel scope link src 10.78.0.1\n"
               "10.78.0.0/25 dev eth1 scope link\n"
               "unreachable 10.78.0.128/25\n")
        self.assertEqual(infra.route_clashes(out, {"wgx-ab"}),
                         ["10.78.0.0/25 dev eth1 scope link", "unreachable 10.78.0.128/25"])
        self.assertEqual(infra.route_clashes("", {"wgx-ab"}), [])

    def test_host_payload(self):
        exp = docker_experiment()
        self.assertEqual(infra.host_payload_bytes(exp),
                         {"1-ff00:0:111": 1 << 30, "1-ff00:0:112": 1 << 30})

    def test_wgexp_stack_fields_match_the_plan(self):
        f = infra.WGEXP_STACK_FIELDS
        self.assertEqual((f["remote_dir"], f["prometheus_container"], f["prometheus_project"],
                          f["remote_prometheus_port"], f["config_hash_label"],
                          f["grafana_container"], f["grafana_project"], f["tunnel_state_dir"]),
                         ("/tmp/wgexp/prometheus", "wgexp-prometheus", "wgexp-ssh", 8091,
                          "org.scion.wgexp.config-sha256", "wgexp-grafana", "wgexp-monitoring",
                          Path("/tmp/wgexp/ssh-tunnels")))
        self.assertEqual(f["prometheus_config"], HERE / "monitoring" / "prometheus.yml")
        self.assertEqual(f["grafana_compose"], HERE / "monitoring" / "docker-compose.yml")
        self.assertTrue(f["prometheus_config"].is_file() and f["grafana_compose"].is_file())

    def test_missing_pyyaml_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / "tools" / "hummbwtester" / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "orchestration.py").write_text("")
            with mock.patch("importlib.util.find_spec", return_value=None):
                with self.assertRaises(infra.InfraError) as cm:
                    infra.load_hummbwtester(Path(tmp))
            self.assertIn("'yaml'", str(cm.exception))
            with self.assertRaises(infra.InfraError) as cm:
                infra.load_hummbwtester(Path(tmp) / "nope")
            self.assertIn("orchestration.py", str(cm.exception))


class DockerTargets(unittest.TestCase):
    """(b) The target documents of the docker example, with a fake hummbwtester."""

    def make(self, tmp):
        i = infra.DockerInfra(docker_experiment(), Path("/x"), gen_dir=Path(tmp),
                              hb=SimpleNamespace(orchestration=FakeOrchestration))
        addresses = {"1-ff00:0:110": "172.20.0.2", "1-ff00:0:111": "172.20.0.3",
                     "1-ff00:0:112": "172.20.0.4"}
        i._address_of_tester = addresses.__getitem__
        return i

    def test_documents(self):
        with tempfile.TemporaryDirectory() as tmp:
            docs = self.make(tmp).target_documents()
        self.assertEqual(set(docs), set(infra.TARGET_FILES))
        wg = json.loads(docs["targets/wireguard.json"])
        self.assertEqual([t["targets"][0] for t in wg],
                         ["172.20.0.3:28015", "172.20.0.4:28015",
                          "172.20.0.2:28016", "172.20.0.4:28016"])
        self.assertEqual([t["labels"]["endpoint"] for t in wg], list("ABCD"))
        self.assertEqual(wg[1]["labels"]["node"], "tester_1-ff00_0_112")
        self.assertEqual(wg[0]["labels"]["class"], "hummingbird")
        self.assertEqual(json.loads(docs["targets/runner.json"]),
                         [{"targets": ["127.0.0.1:9189"], "labels": {"experiment": "docker-tiny-1g"}}])
        self.assertEqual(json.loads(docs["targets/border_routers.json"]),
                         FakeOrchestration.border_router_targets())

    def test_write_targets_creates_the_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            i = self.make(Path(tmp) / "gen")
            i.write_targets()
            names = sorted(p.name for p in (Path(tmp) / "gen" / "prometheus").iterdir())
            self.assertEqual(names, ["border_routers.json", "runner.json", "wireguard.json"])
            self.assertEqual(os.stat(Path(tmp) / "gen" / "prometheus").st_uid, os.getuid())

    def test_ipv6_target_is_bracketed(self):
        with tempfile.TemporaryDirectory() as tmp:
            i = self.make(tmp)
            i._address_of_tester = lambda ia: "fd00::15"
            wg = json.loads(i.target_documents()["targets/wireguard.json"])
        self.assertEqual(wg[0]["targets"], ["[fd00::15]:28015"])

    def test_paths_and_sciond(self):
        i = infra.DockerInfra(docker_experiment(), Path("/x"), host_factory=lambda k: FakeHost(
            k, lambda argv, root: (0, "[fd00::1]:30255\n")),
            hb=SimpleNamespace(orchestration=FakeOrchestration))
        self.assertEqual(i.binary_paths(), {k: "/share/bin/wireguard-go" for k in
                                            ("1-ff00:0:110", "1-ff00:0:111", "1-ff00:0:112")})
        self.assertEqual(i.jwt_paths(), {"1-ff00:0:111": infra.DOCKER_JWT})
        self.assertEqual(i.sciond_address(i.experiment.endpoint("A")), "[fd00::1]:30255")
        self.assertEqual(i.hosts()["1-ff00:0:111"].commands[-1][0], ["printenv", "SCION_DAEMON"])


class DockerPreflight(unittest.TestCase):
    def infra_with(self, answer):
        hosts = {}

        def factory(key):
            hosts[key] = FakeHost(key, answer)
            return hosts[key]

        i = infra.DockerInfra(docker_experiment(), Path("/x"), host_factory=factory,
                              hb=SimpleNamespace(orchestration=FakeOrchestration))
        i._disk_problems = lambda: []
        return i, hosts

    def test_ok(self):
        def answer(argv, root):
            if argv[:2] == ["bash", "-c"]:
                return 0, ""
            if argv == ["ping", "-V"]:
                return 0, "ping from iputils 20211215\n"
            return 0, "10.0.0.0/8 dev eth9\n" if "route" in argv and False else ""
        i, hosts = self.infra_with(answer)
        self.assertEqual(i.preflight(), [])
        cmds = [c[0] for c in hosts["1-ff00:0:112"].commands]
        self.assertIn(["test", "-c", "/dev/net/tun"], cmds)
        # B and D share the container: one route check per tunnel prefix and selector
        routes = [c for c in cmds if c[:2] == ["ip", "-o"]]
        self.assertEqual(len(routes), 4)
        self.assertIn(["ip", "-o", "route", "show", "to", "root", "10.78.0.0/24"], routes)
        self.assertFalse(any(root for c, root in hosts["1-ff00:0:112"].commands))

    def test_ping_sender_needs_iputils(self):
        def answer(argv, root):
            if argv == ["ping", "-V"]:
                return 0, "ping (GNU inetutils) 2.5\n"
            return 0, ""
        i, _ = self.infra_with(answer)
        i.dry_run = True
        problems = i.preflight()
        # ping-ab is sent from A (111) and ping-cd from C (110); 112 sends no ping
        self.assertEqual(sorted(p.split(":")[0] for p in problems if "iputils" in p),
                         ["1-ff00", "1-ff00"])
        self.assertFalse(any(p.startswith("1-ff00:0:112") and "iputils" in p for p in problems))

    def test_problems_are_collected(self):
        def answer(argv, root):
            if argv[:2] == ["bash", "-c"]:
                return 0, "iperf3\n"
            if argv == ["test", "-c", "/dev/net/tun"]:
                return 1, ""
            if argv[:2] == ["ip", "-o"] and "10.78.0.0/24" in argv:
                return 0, "10.78.0.0/24 dev eth5 scope link\n"
            return 0, ""
        i, _ = self.infra_with(answer)
        with self.assertRaises(infra.InfraError) as cm:
            i.preflight()
        text = str(cm.exception)
        self.assertIn("missing tools: iperf3", text)
        self.assertIn("/dev/net/tun", text)
        self.assertIn("tunnel ab prefix 10.78.0.0/24 overlaps", text)
        # dry-run returns them instead
        i.dry_run = True
        self.assertGreaterEqual(len(i.preflight()), 3)

    def test_listen_port_must_be_dispatched(self):
        i, _ = self.infra_with(lambda argv, root: (0, ""))
        i._dispatched_ports = lambda key: (33000, 34000)
        with self.assertRaises(infra.InfraError) as cm:
            i.preflight()
        self.assertIn("listen_port 32000 is outside the dispatched_ports range 33000-34000",
                      str(cm.exception))


@needs_scion
class ReuseAPI(unittest.TestCase):
    """(a) The names, parameters and fields of hummbwtester that infra.py calls."""

    def test_function_signatures(self):
        hb = real_hb()
        o, remote, ss = hb.orchestration, hb.remote, hb.ssh_setup
        functions = [
            (o, "patch_router_configs", ["router"]),
            (o, "compose_data", []),
            (o, "inter_as_router_peers", ["compose"]),
            (o, "patch_compose", ["compose", "peers", "tc"]),
            (o, "monitoring_compose", ["args", "quiet", "compose", "project"]),
            (o, "ensure_docker_qdiscs", ["compose", "tc", "peers"]),
            (o, "remove_docker_qdiscs", []),
            (o, "border_router_targets", []),
            (o, "wait_for_scion", ["source_ia", "destination", "timeout"]),
            (o, "parse_marketplace_config", ["marketplace", "kind"]),
            (o, "local_container_owner", ["container"]),
            (o, "marketplace_registration_website", []),
            (o, "obtain_marketplace_jwt", ["marketplace", "url"]),
            (o, "write_private_jwt", ["token"]),
            (o, "install_docker_jwt", ["token", "services"]),
            (o, "remove_docker_jwt", ["services", "remote"]),
            (o, "tester_service", ["ia"]),
            (o, "join_host_port", ["host", "port"]),
            (o, "dc_args", ["args"]),
            (o, "run", ["command", "check", "kwargs"]),
            (remote, "load_deployment", ["root", "participants", "relay_ports"]),
            (remote, "preflight", ["host", "dry_run", "required_tools"]),
            (remote, "ssh_command", ["host", "command", "check", "kwargs"]),
            (remote, "scp_to", ["host", "local", "remote"]),
            (remote, "setup_dir", ["host"]),
            (remote, "jwt_path", ["host"]),
            (ss, "ensure_marketplace", ["inventory", "dry_run"]),
            (ss, "obtain_marketplace_jwt", ["inventory"]),
            (ss, "ensure_marketplace_notes", ["inventory", "dry_run"]),
            (ss, "stop_marketplace", ["inventory"]),
            (ss, "ensure_selective_qdiscs", ["inventory", "tc", "dry_run"]),
            (ss, "remove_selective_qdiscs", ["inventory", "tc"]),
            (ss, "copy_if_changed", ["host", "local", "target", "mode", "dry_run"]),
            (ss, "print_manual_steps", ["action", "steps", "dry_run"]),
            (ss, "setup_hosts", ["inventory"]),
            (ss, "ensure_prometheus", ["inventory", "targets", "dry_run", "stack"]),
            (ss, "stop_prometheus", ["host", "stack"]),
            (ss, "ensure_tunnels", ["specs", "forward", "dry_run", "stack"]),
            (ss, "stop_tunnels", ["stack"]),
            (ss, "ensure_grafana", ["forward", "dry_run", "stack"]),
            (ss, "router_metric_sources", ["inventory", "first_port"]),
            (ss, "target_documents_for", ["inventory", "sources", "target_files"]),
            (ss, "tunnel_specs_for", ["inventory", "sources"]),
            (ss, "prometheus_forward", ["inventory"]),
        ]
        for module, name, parameters in functions:
            with self.subTest(function=f"{module.__name__}.{name}"):
                self.assertEqual(list(inspect.signature(getattr(module, name)).parameters),
                                 parameters)

    def test_dataclass_fields(self):
        hb = real_hb()
        classes = [
            (hb.remote, "SSHHost", ["name", "alias", "sciond", "run_dir", "readiness_command",
                                    "static_info", "control_service"]),
            (hb.remote, "Inventory", ["hosts", "server_host", "client_hosts", "prometheus_host",
                                      "local_port_base", "routers", "shaping", "marketplace",
                                      "local_prometheus_port", "participant_hosts"]),
            (hb.ssh_setup, "MonitoringStack", [
                "prometheus_config", "remote_dir", "prometheus_container", "prometheus_project",
                "remote_prometheus_port", "config_hash_label", "grafana_container",
                "grafana_compose", "grafana_project", "tunnel_state_dir", "tunnel_manifest"]),
            (hb.ssh_setup, "MetricSource", ["host", "address", "port", "labels", "target_file"]),
            (hb.ssh_setup, "TunnelSpec", ["source_alias", "prometheus_alias", "port",
                                          "source_address"]),
            (hb.ssh_setup, "PrometheusForward", ["alias", "port", "binds"]),
            (hb.orchestration, "MarketplaceConfig", [
                "username", "password_env", "sub_account", "host", "scion_address", "interfaces",
                "location_override"]),
        ]
        for module, name, fields in classes:
            with self.subTest(dataclass=f"{module.__name__}.{name}"):
                self.assertEqual([f.name for f in dataclasses.fields(getattr(module, name))],
                                 fields)

    def test_constants(self):
        hb = real_hb()
        self.assertEqual(hb.ssh_setup.SCION_CONFIG_DIR, "/etc/scion")
        self.assertEqual(hb.remote.DEFAULT_REQUIRED_TOOLS, ("sha256sum", "nc"))
        self.assertEqual(Path(hb.orchestration.ROOT).resolve(), Path(SCION_DIR).resolve())
        self.assertEqual(hb.orchestration.COMPOSE, Path(hb.orchestration.ROOT) / "gen" / "scion-dc.yml")
        self.assertTrue(callable(hb.ssh_setup.MetricSource) and callable(hb.ssh_setup.MonitoringStack))

    def test_our_stack_builds(self):
        stack = infra.wgexp_stack(real_hb().ssh_setup, 8091)
        self.assertEqual(stack.manifest, Path("/tmp/wgexp/ssh-tunnels/manifest.json"))
        self.assertEqual(stack.grafana_container, "wgexp-grafana")

    def test_jwt_path_of_install_docker_jwt(self):
        """infra.DOCKER_JWT is where hummbwtester's install_docker_jwt puts the token."""
        o = real_hb().orchestration
        with mock.patch.object(o, "run") as run, mock.patch.object(o, "COMPOSE", Path("/x/c.yml")):
            local, remote = o.install_docker_jwt("secret", {"tester_a"})
        local.unlink()
        self.assertEqual(remote, infra.DOCKER_JWT)
        for call in run.call_args_list:
            self.assertNotIn("secret", " ".join(call.args[0]))


@needs_scion
class DockerFlow(unittest.TestCase):
    """The Docker setup, monitoring and teardown calls, with hummbwtester's functions mocked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.o = real_hb().orchestration
        self.calls = []

    def make(self, dry_run=False, experiment=None, **kwargs):
        return infra.DockerInfra(experiment or docker_experiment(), Path(SCION_DIR), dry_run,
                                 hb=real_hb(), gen_dir=Path(self.tmp.name), **kwargs)

    def patch_topology(self):
        o, calls = self.o, self.calls
        compose = {"services": {"tester_1-ff00_0_110": {}, "tester_1-ff00_0_111": {},
                                "tester_1-ff00_0_112": {}}}
        peers = {"br1": ["10.0.0.2"]}
        patches = [
            mock.patch.object(o, "compose_data", lambda: compose),
            mock.patch.object(o, "inter_as_router_peers", lambda c: peers),
            mock.patch.object(o, "patch_router_configs",
                              lambda r: calls.append(("patch_router_configs", r))),
            mock.patch.object(o, "patch_compose",
                              lambda c, p, tc: calls.append(("patch_compose", p, tc))),
            mock.patch.object(o, "run", lambda cmd, **kw: calls.append(("run", cmd, kw))),
            mock.patch.object(o, "wait_for_scion",
                              lambda s, d, t=60: calls.append(("wait_for_scion", s, d))),
            mock.patch.object(o, "ensure_docker_qdiscs",
                              lambda c, tc, p=None: calls.append(("qdiscs", tc, p))),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return compose, peers

    def hosts_fake(self):
        return lambda key: FakeHost(key, address={"1-ff00:0:110": "172.20.0.21",
                                                  "1-ff00:0:111": "172.20.0.28",
                                                  "1-ff00:0:112": "fd00::14"}[key])

    def test_setup_order(self):
        compose, peers = self.patch_topology()
        i = self.make(host_factory=self.hosts_fake())
        with mock.patch("builtins.print"):
            self.assertEqual(i.setup_infrastructure(), [])
        names = [c[0] for c in self.calls]
        self.assertEqual(names, ["patch_router_configs", "patch_compose", "run"]
                         + ["wait_for_scion"] * 4 + ["qdiscs"])
        self.assertEqual(self.calls[0][1], i.experiment.deployment.router)
        self.assertEqual(self.calls[1][2], {"rate": "50mbit", "burst": "50kb", "limit": "256kb"})
        self.assertEqual(self.calls[2][1], [str(self.o.ROOT / "scion.sh"), "start"])
        self.assertEqual(self.calls[2][2], {"cwd": self.o.ROOT})
        self.assertEqual([c[1:] for c in self.calls[3:7]], [
            ("1-ff00:0:111", "1-ff00:0:112,fd00::14"), ("1-ff00:0:112", "1-ff00:0:111,172.20.0.28"),
            ("1-ff00:0:110", "1-ff00:0:112,fd00::14"), ("1-ff00:0:112", "1-ff00:0:110,172.20.0.21")])

    def test_dry_run_changes_nothing(self):
        self.patch_topology()
        i = self.make(dry_run=True, host_factory=self.hosts_fake())
        out = []
        with mock.patch("builtins.print", lambda *a, **k: out.append(" ".join(map(str, a)))):
            self.assertEqual(i.setup_infrastructure(), [])
        self.assertEqual(self.calls, [])
        text = "\n".join(out)
        for step in ("patch the border-router configs", "run ./scion.sh start",
                     "apply the TBF qdiscs", "wait until 1-ff00:0:111 reaches"):
            self.assertIn(f"dry-run: would {step}", text)

    def test_dry_run_collects_failures(self):
        self.patch_topology()
        with mock.patch.object(self.o, "compose_data", side_effect=ValueError("no compose")):
            i = self.make(dry_run=True, host_factory=self.hosts_fake())
            with mock.patch("builtins.print"):
                failures = i.setup_infrastructure()
        self.assertTrue(failures and "no compose" in failures[0])
        self.assertEqual(self.calls, [])

    def test_real_failure_raises_and_stops(self):
        self.patch_topology()
        with mock.patch.object(self.o, "patch_router_configs", side_effect=ValueError("bad toml")):
            i = self.make(host_factory=self.hosts_fake())
            with mock.patch("builtins.print"), self.assertRaises(infra.InfraError) as cm:
                i.setup_infrastructure()
        self.assertIn("bad toml", str(cm.exception))
        self.assertEqual([c[0] for c in self.calls], [])

    def test_no_tc_means_no_shaping(self):
        self.patch_topology()
        raw = json.loads(DOCKER.read_text())
        del raw["tc"]
        exp = config.parse_config(raw, DOCKER)
        i = self.make(experiment=exp, host_factory=self.hosts_fake())
        with mock.patch("builtins.print"):
            i.setup_infrastructure()
        self.assertNotIn("patch_compose", [c[0] for c in self.calls])
        self.assertNotIn("qdiscs", [c[0] for c in self.calls])

    # (d) and (e)

    def fake_subprocess(self, owners=None, record=None):
        owners = owners or {}
        record = record if record is not None else []

        def run(argv, **kwargs):
            record.append((list(argv), kwargs))
            if argv[:3] == ["docker", "inspect", "--format"] and argv[3].startswith("{{index"):
                owner = owners.get(argv[-1])
                return completed(owner, 0) if owner is not None else completed("", 1)
            return completed("", 0)

        return run, record

    def test_monitoring_command_lines(self):
        run, record = self.fake_subprocess()
        i = self.make()
        i.target_documents = lambda: {n: "[]\n" for n in infra.TARGET_FILES}
        waited = []
        with mock.patch("subprocess.run", run), mock.patch("builtins.print"), \
                mock.patch.object(infra, "wait_service", lambda c, u, *a, **k: waited.append((c, u))):
            self.assertEqual(i.setup_monitoring(), [])
        compose = str(infra.MONITORING_COMPOSE)
        commands = [argv for argv, _ in record if argv[:2] == ["docker", "compose"]]
        self.assertEqual(commands, [[
            "docker", "compose", "--progress", "quiet", "--project-name", "wgexp-monitoring",
            "-f", compose, "up", "-d", "prometheus", "grafana"]])
        env = next(kw["env"] for argv, kw in record if argv[:2] == ["docker", "compose"])
        self.assertEqual((env["PROMETHEUS_PORT"], env["GRAFANA_PORT"]), ("8091", "3001"))
        self.assertEqual(waited, [("wgexp-prometheus", "http://127.0.0.1:8091/-/ready"),
                                  ("wgexp-grafana", "http://127.0.0.1:3001/api/health")])

    def test_monitoring_keeps_ours_and_refuses_foreign(self):
        i = self.make()
        i.target_documents = lambda: {n: "[]\n" for n in infra.TARGET_FILES}
        for owners in ({infra.PROMETHEUS_CONTAINER: "monitoring/prometheus"},
                       {infra.GRAFANA_CONTAINER: "hummbwtester/grafana"},
                       {infra.PROMETHEUS_CONTAINER: "wgexp-monitoring/grafana"}):
            run, record = self.fake_subprocess(owners)
            with mock.patch("subprocess.run", run), mock.patch("builtins.print"):
                with self.assertRaises(infra.InfraError) as cm:
                    i.setup_monitoring()
            self.assertIn("refusing to replace", str(cm.exception))
            self.assertFalse([a for a, _ in record if a[:2] == ["docker", "compose"]])
        # our own containers are fine
        run, record = self.fake_subprocess({infra.PROMETHEUS_CONTAINER: "wgexp-monitoring/prometheus",
                                            infra.GRAFANA_CONTAINER: "wgexp-monitoring/grafana"})
        with mock.patch("subprocess.run", run), mock.patch("builtins.print"), \
                mock.patch.object(infra, "wait_service"):
            self.assertEqual(i.setup_monitoring(), [])

    def test_monitoring_dry_run_starts_nothing(self):
        run, record = self.fake_subprocess()
        i = self.make(dry_run=True)
        with mock.patch("subprocess.run", run), mock.patch("builtins.print"):
            self.assertEqual(i.setup_monitoring(), [])
        self.assertFalse([a for a, _ in record if a[:2] == ["docker", "compose"]])
        self.assertFalse((Path(self.tmp.name) / "prometheus").exists())

    def test_teardown_continues_past_failures(self):
        o = self.o
        run, record = self.fake_subprocess({infra.PROMETHEUS_CONTAINER: "wgexp-monitoring/prometheus",
                                            infra.GRAFANA_CONTAINER: "wgexp-monitoring/grafana"})
        removed = []
        i = self.make()
        with mock.patch("subprocess.run", run), mock.patch("builtins.print"), \
                mock.patch.object(o, "remove_docker_qdiscs", side_effect=RuntimeError("tc failed")), \
                mock.patch.object(o, "remove_docker_jwt",
                                  lambda services, remote: removed.append((services, remote))):
            errors = i.teardown_infrastructure()
        self.assertEqual(len(errors), 1)
        self.assertIn("tc failed", errors[0])
        commands = [a for a, _ in record if a[:2] == ["docker", "compose"]]
        self.assertEqual(commands, [[
            "docker", "compose", "--progress", "quiet", "--project-name", "wgexp-monitoring",
            "-f", str(infra.MONITORING_COMPOSE), "rm", "--stop", "--force", "prometheus", "grafana"]])
        self.assertNotIn("-v", commands[0])  # the volumes stay
        self.assertEqual(removed, [({"tester_1-ff00_0_111"}, infra.DOCKER_JWT)])

    def test_install_binary_copies_only_when_different(self):
        binary = Path(self.tmp.name) / "wireguard-go"
        binary.write_bytes(b"binary")
        digest = infra.Infra.sha256(binary)
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            if "sha256sum" in cmd:
                same = "tester_1-ff00_0_112" in cmd
                return completed(f"{digest if same else '0' * 64}  /share/bin/wireguard-go\n", 0)
            return completed("", 0)

        i = self.make()
        with mock.patch.object(self.o, "run", run), mock.patch("builtins.print"):
            paths = i.install_binary(binary)
        self.assertEqual(set(paths.values()), {"/share/bin/wireguard-go"})
        copies = [c for c in calls if "cp" in c]
        self.assertEqual({c[-1].split(":")[0] for c in copies},
                         {"tester_1-ff00_0_110", "tester_1-ff00_0_111"})
        self.assertTrue(all(c[-1].endswith(":/share/bin/wireguard-go.new") for c in copies))
        # dry run copies nothing
        calls.clear()
        i = self.make(dry_run=True)
        with mock.patch.object(self.o, "run", run), mock.patch("builtins.print"):
            i.install_binary(binary)
        self.assertFalse([c for c in calls if "cp" in c])

    def test_install_jwt_never_puts_the_password_or_token_in_argv(self):
        o = self.o
        seen = {}
        i = self.make()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WGEXP_MARKETPLACE_PASSWORD", None)
            with mock.patch.object(o, "marketplace_registration_website", lambda: "https://m:1"), \
                    mock.patch.object(o, "obtain_marketplace_jwt",
                                      lambda cfg, url: seen.update(cfg=cfg, url=url) or "TOKEN"), \
                    mock.patch.object(o, "install_docker_jwt",
                                      lambda token, services: (seen.update(token=token,
                                                                           services=services)
                                                               or (Path(self.tmp.name) / "j",
                                                                   infra.DOCKER_JWT))), \
                    mock.patch("builtins.print"):
                paths = i.install_jwt()
                self.assertEqual(os.environ["WGEXP_MARKETPLACE_PASSWORD"], "1234")
            os.environ.pop("WGEXP_MARKETPLACE_PASSWORD", None)
        self.assertEqual(paths, {"1-ff00:0:111": infra.DOCKER_JWT})
        self.assertEqual(seen["url"], "https://m:1")
        self.assertEqual(seen["services"], {"tester_1-ff00_0_111"})
        self.assertEqual((seen["cfg"].username, seen["cfg"].location_override), ("alice", False))


class RequiredTools(unittest.TestCase):
    """Each host is asked only for the tools of the workloads it is an end of."""

    def test_sciera_hosts(self):
        exp = sciera_experiment()
        self.assertEqual(infra.required_tools(exp, "rnp"), ("ip", "ping", "sha256sum", "rsync", "dd"))
        self.assertEqual(infra.required_tools(exp, "ufes"), ("ip", "ping", "sha256sum", "iperf3"))
        self.assertEqual(infra.required_tools(exp, "ufms"),
                         ("ip", "ping", "sha256sum", "rsync", "dd", "iperf3"))


@needs_scion
class SSHFlow(unittest.TestCase):
    """(c) The SSH inventory, sources, documents and relay specs for experiment-sciera.json.

    Nothing connects to a host: hummbwtester's step functions and ssh_command are mocked.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.hb = real_hb()
        patcher = mock.patch.object(infra, "SSH_REQUIRED_MODULES", ())
        patcher.start()
        self.addCleanup(patcher.stop)

    def make(self, dry_run=False, **kwargs):
        return infra.SSHInfra(sciera_experiment(), Path(SCION_DIR), dry_run, hb=self.hb,
                              gen_dir=Path(self.tmp.name), **kwargs)

    def test_inventory(self):
        i = self.make()
        inv = i.inventory
        self.assertEqual(inv.participant_hosts, frozenset({"rnp", "ufes", "ufms"}))
        self.assertEqual((inv.server_host, inv.client_hosts), ("", {}))
        self.assertEqual((inv.prometheus_host, inv.local_port_base), ("ufms", 19190))
        self.assertEqual(inv.local_prometheus_port, 8091)  # monitoring.prometheus_port
        self.assertEqual(inv.hosts["rnp"].alias, "sciera-rnp")
        self.assertEqual(inv.marketplace.host, "ufms")
        self.assertTrue(inv.marketplace.location_override)
        self.assertEqual(len(inv.routers), 3)
        self.assertEqual(len(inv.shaping), 4)
        self.assertEqual(i.stack.remote_prometheus_port, 8091)
        # the experiment's own config is not modified to build it
        self.assertNotIn("local_prometheus_port", i.experiment.raw["deployment"]["metrics"])

    def test_sources_ports(self):
        sources = self.make().metric_sources()
        self.assertEqual([(s.host, s.address, s.port, s.target_file) for s in sources], [
            ("rnp", "127.0.0.1:28015", 19190, "targets/wireguard.json"),
            ("ufms", "127.0.0.1:28015", 19191, "targets/wireguard.json"),
            ("ufes", "127.0.0.1:28016", 19192, "targets/wireguard.json"),
            ("ufms", "127.0.0.1:28016", 19193, "targets/wireguard.json"),
            (None, "127.0.0.1:9189", 19194, "targets/runner.json"),
            ("rnp", "127.0.0.1:38401", 19195, "targets/border_routers.json"),
            ("ufes", "127.0.0.1:38401", 19196, "targets/border_routers.json"),
            ("ufms", "127.0.0.1:38401", 19197, "targets/border_routers.json"),
        ])
        self.assertEqual(sources[0].labels["node"], "rnp")
        self.assertEqual(sources[3].labels, {
            "experiment": sciera_experiment().name, "tunnel": "cd", "endpoint": "D", "peer": "C",
            "class": "best_effort", "tunnel_class": "best_effort", "isd_as": "71-2:0:5c",
            "node": "ufms"})
        self.assertEqual(sources[5].labels, {"as": "71_1916", "br": "br-2"})

    def test_target_documents(self):
        docs = {k: json.loads(v) for k, v in self.make().target_documents().items()}
        self.assertEqual(set(docs), set(infra.TARGET_FILES))
        # Prometheus runs on ufms: B and D are scraped directly, A and C through their relays
        self.assertEqual([t["targets"] for t in docs["targets/wireguard.json"]],
                         [["127.0.0.1:19190"], ["127.0.0.1:28015"], ["127.0.0.1:19192"],
                          ["127.0.0.1:28016"]])
        self.assertEqual(docs["targets/runner.json"],
                         [{"targets": ["127.0.0.1:19194"], "labels": {"experiment": sciera_experiment().name}}])
        self.assertEqual([t["targets"] for t in docs["targets/border_routers.json"]],
                         [["127.0.0.1:19195"], ["127.0.0.1:19196"], ["127.0.0.1:38401"]])

    def test_relay_specs(self):
        i = self.make()
        specs = self.hb.ssh_setup.tunnel_specs_for(i.inventory, i.metric_sources())
        self.assertEqual([(s.source_alias, s.prometheus_alias, s.port, s.source_address)
                          for s in specs], [
            ("sciera-rnp", "sciera-ufms", 19190, "127.0.0.1:28015"),
            ("sciera-ufes", "sciera-ufms", 19192, "127.0.0.1:28016"),
            (None, "sciera-ufms", 19194, "127.0.0.1:9189"),
            ("sciera-rnp", "sciera-ufms", 19195, "127.0.0.1:38401"),
            ("sciera-ufes", "sciera-ufms", 19196, "127.0.0.1:38401"),
        ])

    def test_paths_and_sciond(self):
        i = self.make()
        self.assertEqual(i.binary_paths(), {k: "/var/tmp/wgexp/setup/wireguard-go"
                                            for k in ("rnp", "ufes", "ufms")})
        self.assertEqual(i.jwt_paths(), {"rnp": "/var/tmp/wgexp/setup/marketplace.jwt"})
        self.assertEqual(i.sciond_address(i.experiment.endpoint("C")), "127.0.0.1:30255")
        self.assertEqual(i.run_dir("ufes"), "/var/tmp/wgexp")

    def test_monitoring_steps_use_our_stack(self):
        ss, calls = self.hb.ssh_setup, []
        i = self.make()
        forward = SimpleNamespace(port=8091, binds=("127.0.0.1",))
        patches = [
            mock.patch.object(ss, "ensure_prometheus",
                              lambda inv, t, dry, stack=None: calls.append(("prometheus", t, dry, stack))),
            mock.patch.object(ss, "ensure_tunnels",
                              lambda specs, fwd, dry, stack=None: calls.append(("tunnels", specs, fwd, dry, stack))),
            mock.patch.object(ss, "ensure_grafana",
                              lambda fwd, dry, stack=None: calls.append(
                                  ("grafana", dry, stack, os.environ.get("GRAFANA_PORT")))),
            mock.patch.object(ss, "prometheus_forward", lambda inv: forward),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        saved = os.environ.get("GRAFANA_PORT")
        self.addCleanup(lambda: os.environ.__setitem__("GRAFANA_PORT", saved) if saved is not None
                        else os.environ.pop("GRAFANA_PORT", None))
        with mock.patch("builtins.print"):
            self.assertEqual(i.setup_monitoring(), [])
        self.assertEqual([c[0] for c in calls], ["prometheus", "tunnels", "grafana"])
        self.assertEqual(set(calls[0][1]), set(infra.TARGET_FILES))
        self.assertIs(calls[0][3], calls[1][4])
        self.assertEqual(calls[0][3].prometheus_container, "wgexp-prometheus")
        self.assertEqual(len(calls[1][1]), 5)
        self.assertIs(calls[1][2], forward)
        self.assertEqual(calls[2][3], "3001")
        self.assertEqual((calls[0][2], calls[1][3], calls[2][1]), (False, False, False))
        # the targets are also written locally
        self.assertEqual(sorted(p.name for p in (Path(self.tmp.name) / "prometheus").iterdir()),
                         ["border_routers.json", "runner.json", "wireguard.json"])

    def test_dry_run_writes_no_targets_and_passes_dry_run(self):
        ss, flags = self.hb.ssh_setup, []
        i = self.make(dry_run=True)
        forward = SimpleNamespace(port=8091, binds=("127.0.0.1",))
        with mock.patch.object(ss, "ensure_prometheus", lambda inv, t, dry, stack=None: flags.append(dry)), \
                mock.patch.object(ss, "ensure_tunnels", lambda s, f, dry, stack=None: flags.append(dry)), \
                mock.patch.object(ss, "ensure_grafana", lambda f, dry, stack=None: flags.append(dry)), \
                mock.patch.object(ss, "prometheus_forward", lambda inv: forward), \
                mock.patch("builtins.print"):
            self.assertEqual(i.setup_monitoring(), [])
        self.assertEqual(flags, [True, True, True])
        self.assertFalse((Path(self.tmp.name) / "prometheus").exists())

    def test_setup_infrastructure_order_and_manual_steps(self):
        ss, calls = self.hb.ssh_setup, []
        i = self.make(dry_run=True)
        with mock.patch.object(ss, "ensure_marketplace", lambda inv, dry: calls.append(("mp", dry))), \
                mock.patch.object(ss, "ensure_selective_qdiscs",
                                  lambda inv, tc, dry: calls.append(("qdisc", tc, dry))), \
                mock.patch.object(ss, "ensure_marketplace_notes",
                                  lambda inv, dry: calls.append(("notes", dry)) or ["restart X"]), \
                mock.patch.object(ss, "print_manual_steps",
                                  lambda action, steps, dry: calls.append(("manual", action, steps, dry))), \
                mock.patch("builtins.print"):
            self.assertEqual(i.setup_infrastructure(), [])
        self.assertEqual(calls, [("mp", True), ("qdisc", {"rate": "10mbit", "burst": "50kb",
                                                           "limit": "256kb"}, True),
                                 ("notes", True), ("manual", "setup", ["restart X"], True)])

    def test_dry_run_collects_a_failing_step_and_goes_on(self):
        ss, calls = self.hb.ssh_setup, []
        i = self.make(dry_run=True)
        with mock.patch.object(ss, "ensure_marketplace", side_effect=RuntimeError("host down")), \
                mock.patch.object(ss, "ensure_selective_qdiscs", lambda *a: calls.append("qdisc")), \
                mock.patch.object(ss, "ensure_marketplace_notes", lambda *a: calls.append("notes") or []), \
                mock.patch.object(ss, "print_manual_steps"), mock.patch("builtins.print"):
            failures = i.setup_infrastructure()
        self.assertEqual(calls, ["qdisc", "notes"])
        self.assertEqual(len(failures), 1)
        self.assertIn("host down", failures[0])

    def test_real_setup_stops_at_the_first_failure(self):
        ss, calls = self.hb.ssh_setup, []
        i = self.make()
        with mock.patch.object(ss, "ensure_marketplace", side_effect=RuntimeError("boom")), \
                mock.patch.object(ss, "ensure_selective_qdiscs", lambda *a: calls.append("qdisc")), \
                mock.patch.object(ss, "print_manual_steps"), mock.patch("builtins.print"):
            with self.assertRaises(infra.InfraError):
                i.setup_infrastructure()
        self.assertEqual(calls, [])

    def test_missing_bcrypt_is_named(self):
        i = self.make()
        with mock.patch.object(infra, "SSH_REQUIRED_MODULES", ("not_a_module_xyz",)), \
                mock.patch.object(self.hb.ssh_setup, "print_manual_steps"), mock.patch("builtins.print"):
            with self.assertRaises(infra.InfraError) as cm:
                i.setup_infrastructure()
        self.assertIn("not_a_module_xyz", str(cm.exception))

    def test_install_binary_and_jwt(self):
        ss, copies = self.hb.ssh_setup, []
        binary = Path(self.tmp.name) / "wg"
        binary.write_bytes(b"x")
        i = self.make()

        def copy(host, local, target, mode, dry):
            copies.append((host.name, Path(local).name if "jwt" in target else str(local), target, mode,
                           dry, Path(local).stat().st_mode & 0o777 if Path(local).exists() else None))
            return host.name != "ufes"

        with mock.patch.object(ss, "copy_if_changed", copy), \
                mock.patch.object(ss, "obtain_marketplace_jwt", lambda inv: "TOKEN"), \
                mock.patch("builtins.print"):
            self.assertEqual(i.install_binary(binary), i.binary_paths())
            paths = i.install_jwt()
        self.assertEqual([c[:5] for c in copies if "jwt" not in c[2]], [
            (n, str(binary), "/var/tmp/wgexp/setup/wireguard-go", "700", False)
            for n in ("rnp", "ufes", "ufms")])
        jwt = [c for c in copies if "jwt" in c[2]]
        self.assertEqual(len(jwt), 1)
        self.assertEqual((jwt[0][0], jwt[0][2], jwt[0][3]), ("rnp", "/var/tmp/wgexp/setup/marketplace.jwt", "600"))
        self.assertEqual(jwt[0][5], 0o600)  # the controller's copy is private
        self.assertEqual(paths, {"rnp": "/var/tmp/wgexp/setup/marketplace.jwt"})

    def test_preflight_uses_remote_preflight_and_checks(self):
        remote, ss = self.hb.remote, self.hb.ssh_setup
        topo = json.dumps({"isd_as": "71-1916", "dispatched_ports": "31000-32767"})

        def answer(argv, root):
            if argv[:2] == ["bash", "-c"] and "df -Pk" in argv[2]:
                return 0, "Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/x 100 1 99999999 1% /\n"
            if argv == ["ping", "-V"]:
                return 0, "ping from iputils 20240117\n"
            return 0, ""

        hosts = {}

        def factory(key):
            hosts[key] = FakeHost(key, answer)
            hosts[key].files[ss.SCION_CONFIG_DIR + "/topology.json"] = topo
            return hosts[key]

        i = self.make(host_factory=factory)
        pre = []
        with mock.patch.object(remote, "preflight",
                               lambda host, dry=False, required_tools=(): pre.append((host.name, dry, tuple(required_tools)))), \
                mock.patch("builtins.print"):
            self.assertEqual(i.preflight(), [])
        self.assertEqual(sorted(p[0] for p in pre), ["rnp", "ufes", "ufms"])
        self.assertEqual(pre[0][2], ("ip", "ping", "sha256sum", "rsync", "dd", "nc"))  # rnp: A sends the copy
        for key, host in hosts.items():
            cmds = host.commands
            self.assertIn((["true"], True), cmds)  # sudo -n true
            self.assertIn((["test", "-c", "/dev/net/tun"], False), cmds)

    def test_preflight_reports_sudo_ports_and_disk(self):
        remote, ss = self.hb.remote, self.hb.ssh_setup
        topo = json.dumps({"dispatched_ports": "33000-34000"})

        def answer(argv, root):
            if root:
                return 1, ""
            if argv[:2] == ["bash", "-c"] and "df -Pk" in argv[2]:
                return 0, "h\n/dev/x 100 1 1000 1% /\n"
            return 0, ""

        def factory(key):
            h = FakeHost(key, answer)
            h.files[ss.SCION_CONFIG_DIR + "/topology.json"] = topo
            return h

        i = self.make(dry_run=True, host_factory=factory)
        with mock.patch.object(remote, "preflight", lambda *a, **k: None), mock.patch("builtins.print"):
            problems = i.preflight()
        text = "\n".join(problems)
        self.assertIn("sudo -n true", text)
        self.assertIn("outside the dispatched_ports range 33000-34000", text)
        self.assertIn("GB free but the payload needs", text)

    def test_teardown_continues_past_failures(self):
        ss, remote, calls = self.hb.ssh_setup, self.hb.remote, []
        i = self.make()

        def rec(name, fail=None):
            def f(*args, **kwargs):
                calls.append((name, kwargs.get("stack")))
                if fail:
                    raise fail
            return f

        with mock.patch.object(ss, "remove_selective_qdiscs", rec("qdiscs", RuntimeError("tc down"))), \
                mock.patch.object(ss, "stop_prometheus", rec("prometheus")), \
                mock.patch.object(ss, "stop_tunnels", rec("tunnels")), \
                mock.patch.object(ss, "stop_marketplace", rec("marketplace", RuntimeError("still up"))), \
                mock.patch.object(self.hb.orchestration, "local_container_owner", lambda c: None), \
                mock.patch.object(remote, "ssh_command",
                                  lambda host, cmd, **kw: calls.append(("rm", host.name, cmd))), \
                mock.patch("builtins.print"):
            errors = i.teardown_infrastructure()
        names = [c[0] for c in calls]
        self.assertEqual(names[:4], ["qdiscs", "prometheus", "tunnels", "marketplace"])
        self.assertEqual(len(errors), 2)
        self.assertIn("tc down", errors[0])
        self.assertIn("still up", errors[1])
        stacks = [c[1] for c in calls if c[0] in ("prometheus", "tunnels")]
        self.assertTrue(all(s is i.stack for s in stacks))
        rms = [c for c in calls if c[0] == "rm"]
        self.assertIn(("rm", "ufms", "rm -rf /tmp/wgexp/prometheus"), rms)
        self.assertEqual(sorted(c[1] for c in rms if "setup" in c[2]), ["rnp", "ufes", "ufms"])


if __name__ == "__main__":
    unittest.main()
